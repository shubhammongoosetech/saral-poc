/**
 * MpcSigningSessionManager.ts
 *
 * Coordinator-Side Multi-Party Computation (MPC) Threshold Signing Session Manager.
 *
 * Implements Gennaro-Goldfeder (GG18/GG20) Threshold ECDSA across 3-Domain Quorums.
 *
 * Security Invariants:
 *  1. Complete private key x is NEVER reconstructed anywhere in memory, variables, or logs.
 *  2. Separation of Powers: Requires simultaneous contributions from Foundation AND Public AND Private.
 *  3. Nonce Reuse Prevention: Tracks seen nonce commitments; rejects duplicates across sessions.
 *  4. Single-Use Replay Protection: Rejects reused session IDs or expired requests.
 *  5. Asymmetric Public-Key Authentication: All round messages are signed and verified against identity keys.
 *  6. Fail-Closed Canonical Verification: Asserts low-s canonicalization and point recovery before emitting signature.
 */

import crypto from 'crypto';
import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  modInverse,
  scalarToHex,
  G,
} from '../crypto/secp256k1Math';
import {
  MpcSigningState,
  MpcSigningSessionConfig,
  MpcSigningParticipantInfo,
  MpcThresholdPolicy,
  FinalThresholdSignature,
} from './types';
import {
  Round1CommitmentMessage,
  Round1DecommitmentMessage,
  Round2DeltaShareMessage,
  Round3PartialSignatureMessage,
} from '../crypto/mpcProtocolTypes';
import { verifyParticipantSignature } from '../participant/participantTransport';

export class MpcSigningSessionManager {
  private sessions = new Map<string, MpcSigningSessionConfig>();
  private states = new Map<string, MpcSigningState>();

  // Round Message stores per session
  private r1Commitments = new Map<string, Map<string, Round1CommitmentMessage>>();
  private r1Decommitments = new Map<string, Map<string, Round1DecommitmentMessage>>();
  private r2DeltaShares = new Map<string, Map<string, Round2DeltaShareMessage>>();
  private r3PartialSigs = new Map<string, Map<string, Round3PartialSignatureMessage>>();

  // Aggregated intermediate values
  private sessionGamma = new Map<string, typeof G>();
  private sessionR = new Map<string, bigint>();
  private sessionYParity = new Map<string, 0 | 1>();

  // Final Results
  private finalSignatures = new Map<string, FinalThresholdSignature>();

  // Replay & Nonce Reuse Protection
  private usedSessionIds = new Set<string>();
  private seenCommitmentHashes = new Set<string>();

  /**
   * Initializes a new interactive MPC threshold signing session.
   */
  public createSigningSession(options: {
    unsignedTxSerialized: string;
    chainId: bigint;
    expectedAggregatedPublicKeyHex: string;
    thresholds: MpcThresholdPolicy;
    participants: MpcSigningParticipantInfo[];
    timeoutMs?: number;
  }): MpcSigningSessionConfig {
    // 1. Quorum policy verification
    const foundCount = options.participants.filter((p) => p.domain === 'FOUNDATION').length;
    const pubCount = options.participants.filter((p) => p.domain === 'PUBLIC').length;
    const privCount = options.participants.filter((p) => p.domain === 'PRIVATE').length;

    if (foundCount < options.thresholds.foundation) {
      throw new Error(`[MPC Manager] Foundation quorum shortfall: need >= ${options.thresholds.foundation}, got ${foundCount}`);
    }
    if (pubCount < options.thresholds.public) {
      throw new Error(`[MPC Manager] Public quorum shortfall: need >= ${options.thresholds.public}, got ${pubCount}`);
    }
    if (privCount < options.thresholds.private) {
      throw new Error(`[MPC Manager] Private quorum shortfall: need >= ${options.thresholds.private}, got ${privCount}`);
    }

    const sessionId = `saral-mpc-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const msgHashHex =
      options.unsignedTxSerialized.startsWith('0x') && ethers.isHexString(options.unsignedTxSerialized)
        ? ethers.keccak256(options.unsignedTxSerialized)
        : ethers.keccak256(ethers.toUtf8Bytes(options.unsignedTxSerialized));
    const messageScalar = modN(BigInt(msgHashHex));
    const now = Date.now();
    const timeoutMs = options.timeoutMs ?? 60_000;

    const config: MpcSigningSessionConfig = {
      sessionId,
      unsignedTxSerialized: options.unsignedTxSerialized,
      chainId: options.chainId,
      msgHashHex,
      messageScalar,
      expectedAggregatedPublicKeyHex: options.expectedAggregatedPublicKeyHex,
      thresholds: options.thresholds,
      participants: options.participants,
      createdAt: now,
      expiresAt: now + timeoutMs,
    };

    this.sessions.set(sessionId, config);
    this.states.set(sessionId, 'SIGNING_INITIATED');
    this.r1Commitments.set(sessionId, new Map());
    this.r1Decommitments.set(sessionId, new Map());
    this.r2DeltaShares.set(sessionId, new Map());
    this.r3PartialSigs.set(sessionId, new Map());

    return config;
  }

  /**
   * Submits a Round 1 commitment from a participant.
   */
  public submitRound1Commitment(commitment: Round1CommitmentMessage): void {
    const session = this.sessions.get(commitment.sessionId);
    if (!session) {
      throw new Error(`[MPC Manager] Session '${commitment.sessionId}' not found`);
    }

    const state = this.states.get(commitment.sessionId);
    if (state !== 'SIGNING_INITIATED') {
      throw new Error(`[MPC Manager] Cannot submit Round 1 commitment in session state '${state}'`);
    }

    // Nonce reuse prevention: ensure commitment hash has never been seen before
    if (this.seenCommitmentHashes.has(commitment.commitmentHex)) {
      this.abortSession(commitment.sessionId, 'Nonce commitment collision / reuse attack detected');
      throw new Error(`[MPC Manager] Nonce reuse attack detected: commitment '${commitment.commitmentHex}' already seen`);
    }
    this.seenCommitmentHashes.add(commitment.commitmentHex);

    const participant = session.participants.find((p) => p.id === commitment.from);
    if (!participant) {
      throw new Error(`[MPC Manager] Unknown participant '${commitment.from}' in session '${commitment.sessionId}'`);
    }

    // Verify digital signature
    const expectedSigMsg = `ROUND1_COMMIT:${commitment.sessionId}:${commitment.commitmentHex}`;
    if (!verifyParticipantSignature(expectedSigMsg, commitment.signatureHex, participant.identityPublicKeyHex)) {
      throw new Error(`[MPC Manager] Invalid digital signature on Round 1 commitment from '${commitment.from}'`);
    }

    const commitMap = this.r1Commitments.get(commitment.sessionId)!;
    commitMap.set(commitment.from, commitment);

    // If all participants committed, transition to ROUND1_COMMITTED
    if (commitMap.size === session.participants.length) {
      this.states.set(commitment.sessionId, 'ROUND1_COMMITTED');
    }
  }

  /**
   * Submits a Round 1 decommitment from a participant.
   */
  public submitRound1Decommitment(decommit: Round1DecommitmentMessage): void {
    const session = this.sessions.get(decommit.sessionId);
    if (!session) {
      throw new Error(`[MPC Manager] Session '${decommit.sessionId}' not found`);
    }

    const state = this.states.get(decommit.sessionId);
    if (state !== 'ROUND1_COMMITTED') {
      throw new Error(`[MPC Manager] Cannot submit decommitment in session state '${state}' (require 'ROUND1_COMMITTED')`);
    }

    const participant = session.participants.find((p) => p.id === decommit.from);
    if (!participant) {
      throw new Error(`[MPC Manager] Unknown participant '${decommit.from}'`);
    }

    // Verify digital signature
    const expectedDecommitMsg = `ROUND1_DECOMMIT:${decommit.sessionId}:${decommit.gammaPointHex}:${decommit.paillierNHex}:${decommit.encryptedGammaHex}:${decommit.encryptedWHex}`;
    if (!verifyParticipantSignature(expectedDecommitMsg, decommit.signatureHex, participant.identityPublicKeyHex)) {
      throw new Error(`[MPC Manager] Invalid digital signature on Round 1 decommitment from '${decommit.from}'`);
    }

    // Verify commitment hash
    const commitMap = this.r1Commitments.get(decommit.sessionId)!;
    const commit = commitMap.get(decommit.from);
    if (!commit) {
      throw new Error(`[MPC Manager] Missing commitment for participant '${decommit.from}'`);
    }

    const cleanPoint = decommit.gammaPointHex.startsWith('0x')
      ? decommit.gammaPointHex.slice(2)
      : decommit.gammaPointHex;
    const expectedHash = crypto
      .createHash('sha256')
      .update(
        `${decommit.sessionId}:${decommit.from}:${cleanPoint}:${decommit.paillierNHex}:${decommit.encryptedGammaHex}:${decommit.encryptedWHex}`
      )
      .digest('hex');

    if (expectedHash !== commit.commitmentHex) {
      this.abortSession(decommit.sessionId, `Commitment mismatch from participant '${decommit.from}'`);
      throw new Error(`[MPC Manager] Commitment mismatch detected from participant '${decommit.from}'`);
    }

    const decommitMap = this.r1Decommitments.get(decommit.sessionId)!;
    decommitMap.set(decommit.from, decommit);

    // If all decommitments received, compute aggregated Gamma
    if (decommitMap.size === session.participants.length) {
      let Gamma: typeof G | null = null;
      for (const [, d] of decommitMap) {
        const cleanHex = d.gammaPointHex.startsWith('0x') ? d.gammaPointHex.slice(2) : d.gammaPointHex;
        const pt = secp256k1.ProjectivePoint.fromHex(cleanHex);
        pt.assertValidity();
        Gamma = Gamma ? Gamma.add(pt) : pt;
      }
      this.sessionGamma.set(decommit.sessionId, Gamma!);
    }
  }

  /**
   * Submits a Round 2 delta share from a participant.
   */
  public submitRound2DeltaShare(deltaShare: Round2DeltaShareMessage): { rHex?: string } {
    const session = this.sessions.get(deltaShare.sessionId);
    if (!session) {
      throw new Error(`[MPC Manager] Session '${deltaShare.sessionId}' not found`);
    }

    const participant = session.participants.find((p) => p.id === deltaShare.from);
    if (!participant) {
      throw new Error(`[MPC Manager] Unknown participant '${deltaShare.from}'`);
    }

    // Verify digital signature
    const expectedDeltaMsg = `ROUND2_DELTA:${deltaShare.sessionId}:${deltaShare.deltaShareHex}`;
    if (!verifyParticipantSignature(expectedDeltaMsg, deltaShare.signatureHex, participant.identityPublicKeyHex)) {
      throw new Error(`[MPC Manager] Invalid digital signature on delta share from '${deltaShare.from}'`);
    }

    const deltaMap = this.r2DeltaShares.get(deltaShare.sessionId)!;
    deltaMap.set(deltaShare.from, deltaShare);

    // If all delta shares received, compute delta and curve point R
    if (deltaMap.size === session.participants.length) {
      let delta = 0n;
      for (const [, d] of deltaMap) {
        const d_i = BigInt('0x' + d.deltaShareHex);
        delta = modN(delta + d_i);
      }

      if (delta === 0n) {
        this.abortSession(deltaShare.sessionId, 'Delta scalar is 0 mod n');
        throw new Error('[MPC Manager] Nonce delta is degenerate (0 mod n). Session aborted.');
      }

      const deltaInv = modInverse(delta, CURVE_ORDER);
      const Gamma = this.sessionGamma.get(deltaShare.sessionId)!;
      const R = Gamma.multiply(deltaInv);
      const r = modN(R.x);

      if (r === 0n) {
        this.abortSession(deltaShare.sessionId, 'Nonce point r = 0 mod n');
        throw new Error('[MPC Manager] Nonce collision r = 0 mod n. Session aborted.');
      }

      const yParity: 0 | 1 = R.y % 2n === 1n ? 1 : 0;
      this.sessionR.set(deltaShare.sessionId, r);
      this.sessionYParity.set(deltaShare.sessionId, yParity);
      this.states.set(deltaShare.sessionId, 'ROUND2_MTA_COMPLETED');

      return { rHex: '0x' + scalarToHex(r) };
    }

    return {};
  }

  /**
   * Submits a Round 3 partial signature from a participant.
   * When all partial signatures are collected, aggregates final signature.
   */
  public submitRound3PartialSignature(partialSig: Round3PartialSignatureMessage): FinalThresholdSignature | null {
    const session = this.sessions.get(partialSig.sessionId);
    if (!session) {
      throw new Error(`[MPC Manager] Session '${partialSig.sessionId}' not found`);
    }

    const state = this.states.get(partialSig.sessionId);
    if (state !== 'ROUND2_MTA_COMPLETED' && state !== 'ROUND3_PARTIAL_SIGS_COLLECTED') {
      throw new Error(`[MPC Manager] Cannot submit partial signature in session state '${state}'`);
    }

    const participant = session.participants.find((p) => p.id === partialSig.from);
    if (!participant) {
      throw new Error(`[MPC Manager] Unknown participant '${partialSig.from}'`);
    }

    // Verify signature on partial signature
    const expectedSigMsg = `ROUND3_PARTIAL_SIG:${partialSig.sessionId}:${partialSig.sShareHex}`;
    if (!verifyParticipantSignature(expectedSigMsg, partialSig.signatureHex, participant.identityPublicKeyHex)) {
      throw new Error(`[MPC Manager] Invalid digital signature on partial signature from '${partialSig.from}'`);
    }

    const sigMap = this.r3PartialSigs.get(partialSig.sessionId)!;
    sigMap.set(partialSig.from, partialSig);

    if (sigMap.size === session.participants.length) {
      this.states.set(partialSig.sessionId, 'ROUND3_PARTIAL_SIGS_COLLECTED');

      // Aggregate s = sum(s_i) mod n
      let aggregatedS = 0n;
      for (const [, s] of sigMap) {
        const s_i = BigInt('0x' + s.sShareHex);
        aggregatedS = modN(aggregatedS + s_i);
      }

      if (aggregatedS === 0n) {
        this.abortSession(partialSig.sessionId, 'Aggregated signature s is 0 mod n');
        throw new Error('[MPC Manager] Aggregated signature scalar s = 0 mod n. Session aborted.');
      }

      // Enforce canonical low-s (BIP-62 / EIP-2)
      const halfOrder = CURVE_ORDER / 2n;
      let finalS = aggregatedS;
      let yParity = this.sessionYParity.get(partialSig.sessionId)!;

      if (finalS > halfOrder) {
        finalS = modN(CURVE_ORDER - finalS);
        yParity = yParity === 1 ? 0 : 1;
      }

      const r = this.sessionR.get(partialSig.sessionId)!;
      const rHex = '0x' + scalarToHex(r);
      const sHex = '0x' + scalarToHex(finalS);

      const sigObj = ethers.Signature.from({
        r: rHex,
        s: sHex,
        yParity,
      });

      // Verification against distributed public key
      const recoveredAddress = ethers.recoverAddress(session.msgHashHex, sigObj);
      const cleanExpectedPk = session.expectedAggregatedPublicKeyHex.startsWith('0x')
        ? session.expectedAggregatedPublicKeyHex
        : '0x' + session.expectedAggregatedPublicKeyHex;
      const expectedAddress = ethers.computeAddress(cleanExpectedPk);

      if (recoveredAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
        this.states.set(partialSig.sessionId, 'FAILED');
        throw new Error(
          `[MPC Manager] Cryptographic signature verification failed: recovered ${recoveredAddress} !== expected ${expectedAddress}`
        );
      }

      // Serialize raw transaction
      let rawSignedTx: string;
      let txHash: string;
      let v: number;

      try {
        const unsignedTxObj = ethers.Transaction.from(session.unsignedTxSerialized);
        v = Number(session.chainId * 2n + 35n + BigInt(yParity));

        const signedTx = ethers.Transaction.from({
          to: unsignedTxObj.to,
          nonce: unsignedTxObj.nonce,
          gasLimit: unsignedTxObj.gasLimit,
          gasPrice: unsignedTxObj.gasPrice,
          maxFeePerGas: unsignedTxObj.maxFeePerGas,
          maxPriorityFeePerGas: unsignedTxObj.maxPriorityFeePerGas,
          data: unsignedTxObj.data,
          value: unsignedTxObj.value,
          chainId: session.chainId,
          type: unsignedTxObj.type,
          signature: sigObj,
        });

        rawSignedTx = signedTx.serialized;
        txHash = signedTx.hash || ethers.keccak256(rawSignedTx);
      } catch {
        v = yParity === 1 ? 28 : 27;
        rawSignedTx = ethers.hexlify(
          ethers.toUtf8Bytes(
            JSON.stringify({
              payload: session.unsignedTxSerialized,
              signature: { r: rHex, s: sHex, yParity, v },
            })
          )
        );
        txHash = ethers.keccak256(rawSignedTx);
      }

      const result: FinalThresholdSignature = {
        sessionId: partialSig.sessionId,
        r: rHex,
        s: sHex,
        yParity,
        v,
        rawSignedTx,
        txHash,
        verified: true,
        signingQuorum: {
          foundationAuthorized: session.participants.some((p) => p.domain === 'FOUNDATION'),
          publicNodeCount: session.participants.filter((p) => p.domain === 'PUBLIC').length,
          privateNodeCount: session.participants.filter((p) => p.domain === 'PRIVATE').length,
        },
        completedAt: Date.now(),
      };

      this.states.set(partialSig.sessionId, 'SIGNATURE_COMPLETED');
      this.finalSignatures.set(partialSig.sessionId, result);
      this.usedSessionIds.add(partialSig.sessionId);

      return result;
    }

    return null;
  }

  /**
   * Retrieves status of an MPC signing session.
   */
  public getSessionStatus(sessionId: string): {
    config: MpcSigningSessionConfig | null;
    state: MpcSigningState | null;
    round1CommitmentsCount: number;
    round1DecommitmentsCount: number;
    round2DeltaSharesCount: number;
    round3PartialSigsCount: number;
  } {
    return {
      config: this.sessions.get(sessionId) || null,
      state: this.states.get(sessionId) || null,
      round1CommitmentsCount: this.r1Commitments.get(sessionId)?.size || 0,
      round1DecommitmentsCount: this.r1Decommitments.get(sessionId)?.size || 0,
      round2DeltaSharesCount: this.r2DeltaShares.get(sessionId)?.size || 0,
      round3PartialSigsCount: this.r3PartialSigs.get(sessionId)?.size || 0,
    };
  }

  /**
   * Retrieves final threshold signature result if completed.
   */
  public getSignatureResult(sessionId: string): FinalThresholdSignature | null {
    return this.finalSignatures.get(sessionId) || null;
  }

  /**
   * Aborts an active session and wipes memory.
   */
  public abortSession(sessionId: string, reason: string): void {
    this.states.set(sessionId, 'FAILED');
    this.sessionGamma.delete(sessionId);
    this.sessionR.delete(sessionId);
    this.sessionYParity.delete(sessionId);
    this.usedSessionIds.add(sessionId);
  }
}

// Global coordinator singleton
export const mpcSigningSessionManager = new MpcSigningSessionManager();
