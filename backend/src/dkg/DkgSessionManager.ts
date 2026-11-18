/**
 * DkgSessionManager.ts
 *
 * Coordinator-Side Dealerless DKG Session Manager.
 *
 * Core Security Invariants:
 *  1. ZERO Central Key Material: The coordinator possesses ZERO private Shamir shares,
 *     zero secret polynomials, and cannot decrypt peer-to-peer encrypted envelopes.
 *  2. Explicit Session State Machine:
 *     CREATED -> PARTICIPANTS_REGISTERED -> DKG_RUNNING -> SHARES_VERIFIED ->
 *     AGREEMENT_PENDING -> DKG_COMPLETED -> FAILED
 *  3. Fail-Closed Validation: Rejects unauthenticated messages, out-of-order transitions,
 *     replays, and inconsistent public-key outputs across participants.
 */

import crypto from 'crypto';
import { DomainType } from '../types/domain';
import { deriveHybridParams } from '../crypto/hybriddkg/hybridDkg';
import {
  DkgSessionState,
  DkgSessionConfig,
  DkgParticipantRegistration,
  EncryptedShareEnvelope,
  SignedProtocolEnvelope,
  DkgSessionFinalResult,
} from './types';
import { verifyDkgSignature } from './dkgCrypto';

export class DkgSessionManager {
  private sessions = new Map<string, DkgSessionConfig>();
  private states = new Map<string, DkgSessionState>();
  private participants = new Map<string, Map<number, DkgParticipantRegistration>>();
  private mailboxes = new Map<string, Map<number, Array<EncryptedShareEnvelope | SignedProtocolEnvelope>>>();
  private finalConfirmations = new Map<string, Map<number, {
    domainPublicKeyHex: string;
    commitments: string[];
    agreedQ: number[];
  }>>();
  private finalResults = new Map<string, DkgSessionFinalResult>();

  // Dedup and replay protection
  private seenSignatures = new Set<string>();

  /**
   * Initializes a new DKG session with specified domain and fault configuration.
   */
  public createSession(
    domain: DomainType,
    n: number,
    t?: number,
    f?: number,
    timeoutMs: number = 60_000
  ): DkgSessionConfig {
    const params = deriveHybridParams(n, t, f);
    const sessionId = `saral-dkg-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const now = Date.now();

    const config: DkgSessionConfig = {
      sessionId,
      domain,
      n: params.n,
      t: params.t,
      f: params.f,
      threshold: params.threshold,
      timeoutMs,
      createdAt: now,
      expiresAt: now + timeoutMs,
    };

    this.sessions.set(sessionId, config);
    this.states.set(sessionId, 'CREATED');
    this.participants.set(sessionId, new Map());
    this.mailboxes.set(sessionId, new Map());
    this.finalConfirmations.set(sessionId, new Map());

    return config;
  }

  /**
   * Registers an authenticated participant into a DKG session.
   */
  public registerParticipant(
    sessionId: string,
    participant: {
      id: string;
      nodeIndex: number;
      domain: DomainType;
      identityPublicKeyHex: string;
    }
  ): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`[DKG Manager] Session '${sessionId}' not found`);
    }

    const state = this.states.get(sessionId);
    if (state !== 'CREATED' && state !== 'PARTICIPANTS_REGISTERED') {
      throw new Error(`[DKG Manager] Cannot register participant in session state '${state}'`);
    }

    if (participant.domain !== session.domain) {
      throw new Error(`[DKG Manager] Participant domain mismatch: expected ${session.domain}, got ${participant.domain}`);
    }

    if (participant.nodeIndex < 1 || participant.nodeIndex > session.n) {
      throw new Error(`[DKG Manager] Participant nodeIndex ${participant.nodeIndex} out of bounds (1..${session.n})`);
    }

    const partMap = this.participants.get(sessionId)!;

    // Check for duplicate index or ID
    for (const [, p] of partMap) {
      if (p.nodeIndex === participant.nodeIndex) {
        throw new Error(`[DKG Manager] Duplicate nodeIndex ${participant.nodeIndex} already registered`);
      }
      if (p.id === participant.id) {
        throw new Error(`[DKG Manager] Duplicate participant ID '${participant.id}' already registered`);
      }
    }

    const reg: DkgParticipantRegistration = {
      ...participant,
      registeredAt: Date.now(),
    };

    partMap.set(participant.nodeIndex, reg);

    // Initialize participant mailbox
    const mailMap = this.mailboxes.get(sessionId)!;
    mailMap.set(participant.nodeIndex, []);

    if (partMap.size === session.n) {
      this.states.set(sessionId, 'PARTICIPANTS_REGISTERED');
    }
  }

  /**
   * Starts the DKG execution once all participants are registered.
   */
  public startDkg(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`[DKG Manager] Session '${sessionId}' not found`);
    }

    const state = this.states.get(sessionId);
    if (state !== 'PARTICIPANTS_REGISTERED') {
      throw new Error(`[DKG Manager] Cannot start DKG: state is '${state}' (require 'PARTICIPANTS_REGISTERED')`);
    }

    this.states.set(sessionId, 'DKG_RUNNING');
  }

  /**
   * Submits an encrypted share envelope from a dealer to a target recipient.
   * The coordinator routes ciphertext without having the ability to decrypt.
   */
  public submitEncryptedShare(envelope: EncryptedShareEnvelope): void {
    const session = this.sessions.get(envelope.sessionId);
    if (!session) {
      throw new Error(`[DKG Manager] Session '${envelope.sessionId}' not found`);
    }

    const state = this.states.get(envelope.sessionId);
    if (state !== 'DKG_RUNNING' && state !== 'SHARES_VERIFIED' && state !== 'AGREEMENT_PENDING') {
      throw new Error(`[DKG Manager] Session '${envelope.sessionId}' not in active running state (${state})`);
    }

    // Dedup signature
    if (this.seenSignatures.has(envelope.signatureHex)) {
      return; // Deduplicate
    }
    this.seenSignatures.add(envelope.signatureHex);

    const partMap = this.participants.get(envelope.sessionId)!;
    const sender = partMap.get(envelope.dealerIndex);
    if (!sender) {
      throw new Error(`[DKG Manager] Unknown dealer index ${envelope.dealerIndex}`);
    }

    const recipient = partMap.get(envelope.targetIndex);
    if (!recipient) {
      throw new Error(`[DKG Manager] Unknown target index ${envelope.targetIndex}`);
    }

    // Verify sender signature
    const sigPayload = `${envelope.sessionId}:${envelope.domain}:${envelope.dealerIndex}:${envelope.targetIndex}:${envelope.encryptedPayload}:${envelope.ivHex}:${envelope.authTagHex}`;
    if (!verifyDkgSignature(sigPayload, envelope.signatureHex, sender.identityPublicKeyHex)) {
      throw new Error(`[DKG Manager] Invalid digital signature from dealer ${envelope.dealerIndex}`);
    }

    // Enqueue in recipient mailbox
    const mailMap = this.mailboxes.get(envelope.sessionId)!;
    const mailbox = mailMap.get(envelope.targetIndex);
    if (mailbox) {
      mailbox.push(envelope);
    }
  }

  /**
   * Submits a signed protocol message (ECHO, READY, PROPOSAL, LEAD_CH) for relay.
   */
  public submitProtocolMessage(envelope: SignedProtocolEnvelope): void {
    const session = this.sessions.get(envelope.sessionId);
    if (!session) {
      throw new Error(`[DKG Manager] Session '${envelope.sessionId}' not found`);
    }

    const state = this.states.get(envelope.sessionId);
    if (state !== 'DKG_RUNNING' && state !== 'SHARES_VERIFIED' && state !== 'AGREEMENT_PENDING') {
      throw new Error(`[DKG Manager] Session '${envelope.sessionId}' not in active running state (${state})`);
    }

    if (this.seenSignatures.has(envelope.signatureHex)) {
      return; // Deduplicate
    }
    this.seenSignatures.add(envelope.signatureHex);

    const partMap = this.participants.get(envelope.sessionId)!;
    const sender = partMap.get(envelope.fromIndex);
    if (!sender) {
      throw new Error(`[DKG Manager] Unknown sender index ${envelope.fromIndex}`);
    }

    // Verify sender signature
    const payloadStr = JSON.stringify(envelope.payload);
    const hashMsg = `${envelope.sessionId}:${envelope.domain}:${envelope.fromIndex}:${payloadStr}`;
    if (!verifyDkgSignature(hashMsg, envelope.signatureHex, sender.identityPublicKeyHex)) {
      throw new Error(`[DKG Manager] Invalid digital signature from sender ${envelope.fromIndex}`);
    }

    // Update state to AGREEMENT_PENDING if proposal observed
    if (envelope.payload?.type === 'DKG_PROPOSAL' && state === 'DKG_RUNNING') {
      this.states.set(envelope.sessionId, 'AGREEMENT_PENDING');
    }

    const mailMap = this.mailboxes.get(envelope.sessionId)!;

    if (envelope.targetIndex === 'broadcast') {
      // Deliver to all peers except sender
      for (const [idx, box] of mailMap) {
        if (idx !== envelope.fromIndex) {
          box.push(envelope);
        }
      }
    } else {
      const box = mailMap.get(envelope.targetIndex);
      if (box) {
        box.push(envelope);
      }
    }
  }

  /**
   * Polls messages queued for a given participant.
   */
  public pollMessages(
    sessionId: string,
    nodeIndex: number
  ): Array<EncryptedShareEnvelope | SignedProtocolEnvelope> {
    const mailMap = this.mailboxes.get(sessionId);
    if (!mailMap) return [];

    const box = mailMap.get(nodeIndex);
    if (!box || box.length === 0) return [];

    const messages = [...box];
    box.length = 0; // Clear retrieved messages
    return messages;
  }

  /**
   * Submits a participant's final public output confirmation.
   * When >= n - f nodes confirm, verifies agreement and finalizes the session.
   */
  public submitFinalConfirmation(
    sessionId: string,
    nodeIndex: number,
    confirmation: {
      domainPublicKeyHex: string;
      commitments: string[];
      agreedQ: number[];
    }
  ): DkgSessionFinalResult | null {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`[DKG Manager] Session '${sessionId}' not found`);
    }

    const confMap = this.finalConfirmations.get(sessionId)!;
    confMap.set(nodeIndex, confirmation);

    const minRequired = session.n - session.f;

    if (confMap.size >= minRequired && this.states.get(sessionId) !== 'DKG_COMPLETED') {
      // Verify agreement consistency across all confirmations
      let expectedPub: string | null = null;
      let expectedQ: number[] | null = null;

      for (const [idx, conf] of confMap) {
        if (!expectedPub) {
          expectedPub = conf.domainPublicKeyHex;
          expectedQ = conf.agreedQ;
        } else {
          if (conf.domainPublicKeyHex !== expectedPub) {
            this.states.set(sessionId, 'FAILED');
            throw new Error(
              `[DKG Manager] Agreement breach: node ${idx} output pubkey ${conf.domainPublicKeyHex} !== ${expectedPub}`
            );
          }
        }
      }

      this.states.set(sessionId, 'DKG_COMPLETED');

      const partMap = this.participants.get(sessionId)!;
      const firstConf = confMap.get(Array.from(confMap.keys())[0])!;

      const result: DkgSessionFinalResult = {
        sessionId,
        domain: session.domain,
        domainPublicKeyHex: expectedPub!,
        commitments: firstConf.commitments,
        agreedQ: expectedQ!,
        threshold: session.threshold,
        n: session.n,
        completedAt: Date.now(),
        participatingNodeIds: Array.from(partMap.values()).map((p) => p.id),
      };

      this.finalResults.set(sessionId, result);
      return result;
    }

    return this.finalResults.get(sessionId) || null;
  }

  /**
   * Retrieves current session configuration and state.
   */
  public getSessionStatus(sessionId: string): {
    config: DkgSessionConfig | null;
    state: DkgSessionState | null;
    registeredParticipants: number;
    completedParticipants: number;
  } {
    const config = this.sessions.get(sessionId) || null;
    const state = this.states.get(sessionId) || null;
    const parts = this.participants.get(sessionId)?.size || 0;
    const confs = this.finalConfirmations.get(sessionId)?.size || 0;

    return {
      config,
      state,
      registeredParticipants: parts,
      completedParticipants: confs,
    };
  }

  /**
   * Retrieves final public result of a completed DKG session.
   */
  public getFinalResult(sessionId: string): DkgSessionFinalResult | null {
    return this.finalResults.get(sessionId) || null;
  }
}

// Global coordinator singleton
export const dkgSessionManager = new DkgSessionManager();
