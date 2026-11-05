/**
 * participantService.ts
 *
 * Independent MPC Participant Service Process
 *
 * Architectural Invariants:
 *   1. Local Share Loading: Each participant loads ONLY its own encrypted share from its dedicated storage vault.
 *   2. Local Share Decryption: Decryption occurs strictly inside this service's isolated memory space.
 *   3. Zero Leakage: Plaintext shares (s_i, w_i) and private keys are NEVER exposed over network responses, logs, or metrics.
 *   4. Local Ephemeral Nonces: (k_i, gamma_i) are sampled and zeroized locally.
 *   5. Feldman VSS Self-Validation: Validates local share against commitments before entering Round 1.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  randomScalar,
  scalarMultiplyG,
  scalarToHex,
  G,
} from '../crypto/secp256k1Math';
import {
  computeLagrangeCoefficient,
  verifyShareWithCommitments,
} from '../crypto/shamirField';
import { DomainType } from '../crypto/thresholdEcdsa';
import { decryptShareGcm } from '../crypto/secureEncryption';
import {
  ParticipantId,
  MpcSessionConfig,
  Round1CommitmentMessage,
  Round1DecommitmentMessage,
  Round2PairwiseMtaPacket,
  Round2DeltaShareMessage,
  Round3PartialSignatureMessage,
} from '../crypto/mpcProtocolTypes';
import {
  PaillierKeyPair,
  PaillierPublicKey,
  generatePaillierKeyPair,
  paillierEncrypt,
  paillierDecrypt,
  paillierHomomorphicMultiplyAndBlind,
  validatePaillierPublicKey,
  validatePaillierCiphertext,
  decodeSignedPlaintext,
} from '../crypto/paillierCrypto';
import { verifyParticipantSignature } from './participantTransport';
import { trustedParticipantRegistry } from './participantRegistry';
import { loadOrCreateNodeIdentity } from './nodeIdentityManager';

interface ParticipantSessionMemory {
  config: MpcSessionConfig;
  state: 'COMMITTED' | 'DECOMMITTED' | 'MTA_EXCHANGED' | 'COMPLETED' | 'ABORTED';
  w_i: bigint;
  k_i: bigint;
  gamma_i: bigint;
  Gamma_i: typeof G;
  encGamma: bigint;
  encW: bigint;
  commitmentHex: string;
  peerDecommitments: Map<ParticipantId, Round1DecommitmentMessage>;
  mu: Map<ParticipantId, bigint>;
  nu: Map<ParticipantId, bigint>;
  alpha: Map<ParticipantId, bigint>;
  beta: Map<ParticipantId, bigint>;
  delta_i?: bigint;
  sigma_i?: bigint;
  createdAt: number;
}

export class IndependentParticipantService {
  public readonly id: ParticipantId;
  public readonly domain: DomainType;
  public readonly nodeIndex: number;
  public readonly shareIndex: number;
  public readonly endpoint: string;

  // Private cryptographic identity keypair (secp256k1)
  private identityPrivateKeyHex: string;
  public readonly identityPublicKeyHex: string;

  // Private Paillier keypair for homomorphic MtA operations
  private paillierKey: PaillierKeyPair;

  // Private isolated Shamir share (strictly isolated in process memory)
  private privateShareValue: bigint | null = null;
  private tenantShares = new Map<string, bigint>();
  private isShareLoaded = false;

  // Replay prevention
  private usedSessionIds = new Set<string>();
  private activeSessions = new Map<string, ParticipantSessionMemory>();

  constructor(options: {
    nodeId?: string;
    domain: DomainType;
    nodeIndex: number;
    shareIndex: number;
    endpoint?: string;
    paillierBits?: number;
    customIdentityPrivKeyHex?: string;
    customKeyDir?: string;
  }) {
    this.domain = options.domain;
    this.nodeIndex = options.nodeIndex;
    this.shareIndex = options.shareIndex;
    this.id = options.nodeId || `saral-${options.domain.toLowerCase()}-${options.nodeIndex}`;
    this.endpoint = options.endpoint || `ipc:///tmp/${this.id}.sock`;

    // 1. Generate or load secp256k1 identity keypair using protected local storage
    if (options.customIdentityPrivKeyHex) {
      this.identityPrivateKeyHex = options.customIdentityPrivKeyHex;
      const pubPoint = scalarMultiplyG(BigInt('0x' + this.identityPrivateKeyHex));
      this.identityPublicKeyHex = pubPoint.toHex(true);
    } else {
      const identity = loadOrCreateNodeIdentity(this.id, options.customKeyDir);
      this.identityPrivateKeyHex = identity.identityPrivateKeyHex;
      this.identityPublicKeyHex = identity.identityPublicKeyHex;
    }

    // 2. Initialize Paillier keypair
    const bits = options.paillierBits || (process.env.PAILLIER_BITS ? parseInt(process.env.PAILLIER_BITS, 10) : 2048);
    this.paillierKey = generatePaillierKeyPair(bits);
    // Note: Automatic registry enrollment removed. Node identity enrollment is governed
    // by independent ceremony via performEnrollmentCeremony.
  }

  /**
   * Loads and decrypts the node's share locally inside its own process memory.
   * Supports tenant-scoped shares for multi-user isolation on shared infrastructure nodes.
   * The coordinator NEVER sees or handles this encrypted or decrypted payload.
   */
  public async loadShareLocally(encryptedShareSerialized: string, userId?: string): Promise<void> {
    try {
      // Decrypt locally using domain-isolated HKDF key
      const decrypted = decryptShareGcm(encryptedShareSerialized, this.domain);
      let shareScalar: bigint;
      try {
        const parsed = JSON.parse(decrypted);
        shareScalar = BigInt('0x' + parsed.value);
      } catch {
        const cleanHex = decrypted.startsWith('0x') ? decrypted.slice(2) : decrypted;
        shareScalar = BigInt('0x' + cleanHex);
      }

      this.privateShareValue = modN(shareScalar);
      if (userId) {
        this.tenantShares.set(userId, this.privateShareValue);
      }
      this.isShareLoaded = true;
    } catch (err: any) {
      throw new Error(`[Participant ${this.id}] Failed to load and decrypt share locally: ${err.message}`);
    }
  }

  /**
   * Retrieves isolated tenant share for local inspection / test verification.
   */
  public getTenantShare(userId: string): bigint | undefined {
    return this.tenantShares.get(userId);
  }

  /**
   * Helper to set share directly for memory-isolated unit tests where vault files are not present.
   */
  public setShareForTesting(shareValue: bigint): void {
    this.privateShareValue = modN(shareValue);
    this.isShareLoaded = true;
  }

  /**
   * Signs payload using daemon's asymmetric secp256k1 identity private key.
   */
  private signPayload(payload: string): string {
    const hash = crypto.createHash('sha256').update(payload).digest();
    const sig = secp256k1.sign(hash, this.identityPrivateKeyHex);
    return sig.toCompactHex();
  }

  /**
   * Round 1: Session Initiation & Nonce Commitment
   */
  public async onSessionInit(
    config: MpcSessionConfig,
    commitmentsHex?: string[]
  ): Promise<Round1CommitmentMessage> {
    if (!this.isShareLoaded || this.privateShareValue === null) {
      throw new Error(`[Participant ${this.id}] Cannot participate in session: Local share not loaded in vault`);
    }

    const now = Date.now();

    // 1. Replay & Expired Session Protection
    if (this.usedSessionIds.has(config.sessionId) || this.activeSessions.has(config.sessionId)) {
      throw new Error(`[Participant ${this.id}] Replay attack detected: sessionId '${config.sessionId}' has already been processed`);
    }
    if (now > config.expiresAt) {
      throw new Error(`[Participant ${this.id}] Session '${config.sessionId}' has expired`);
    }

    // 2. Validate Membership & Enrolled Identity
    const me = config.participants.find((p) => p.id === this.id);
    if (!me) {
      throw new Error(`[Participant ${this.id}] Node is not an active participant in session '${config.sessionId}'`);
    }

    // Verify own enrolled identity matches
    trustedParticipantRegistry.loadFromDisk();
    const ownCheck = trustedParticipantRegistry.verifyEnrolledIdentity(
      this.id,
      this.identityPublicKeyHex,
      this.domain
    );
    if (!ownCheck.valid) {
      throw new Error(`[Participant ${this.id}] Enrolled identity verification failed: ${ownCheck.reason}`);
    }

    // 3. Feldman VSS Self-Verification
    if (commitmentsHex && commitmentsHex.length > 0) {
      const isShareValid = verifyShareWithCommitments(
        { index: this.shareIndex, value: this.privateShareValue },
        commitmentsHex
      );
      if (!isShareValid) {
        throw new Error(`[Participant ${this.id}] Feldman VSS verification failed: local share corrupted`);
      }
    }

    // 4. Calculate local effective additive share w_i = lambda_i * s_i mod n
    const domainParticipants = config.participants.filter((p) => p.domain === this.domain);
    const domainIndices = domainParticipants.map((p) => p.shareIndex);

    let lambda = 1n;
    if (domainIndices.length === 1) {
      lambda = 1n;
    } else {
      lambda = computeLagrangeCoefficient(this.shareIndex, domainIndices);
    }
    const w_i = modN(lambda * this.privateShareValue);

    // 5. Ephemeral Nonce Generation
    const k_i = randomScalar();
    const gamma_i = randomScalar();
    const Gamma_i = scalarMultiplyG(gamma_i);

    // Encrypt under participant's own Paillier key with fresh randomness
    const encGamma = paillierEncrypt(gamma_i, this.paillierKey.publicKey);
    const encW = paillierEncrypt(w_i, this.paillierKey.publicKey);

    // Commitment C_i = SHA256(sessionId || id || Gamma_i || N || encGamma || encW)
    const commitInput = `${config.sessionId}:${this.id}:${Gamma_i.toHex(true)}:${this.paillierKey.publicKey.N.toString(16)}:${encGamma.toString(16)}:${encW.toString(16)}`;
    const commitmentHex = crypto.createHash('sha256').update(commitInput).digest('hex');

    this.activeSessions.set(config.sessionId, {
      config,
      state: 'COMMITTED',
      w_i,
      k_i,
      gamma_i,
      Gamma_i,
      encGamma,
      encW,
      commitmentHex,
      peerDecommitments: new Map(),
      mu: new Map(),
      nu: new Map(),
      alpha: new Map(),
      beta: new Map(),
      createdAt: now,
    });

    const sig = this.signPayload(`ROUND1_COMMIT:${config.sessionId}:${commitmentHex}`);

    return {
      type: 'ROUND1_COMMIT',
      sessionId: config.sessionId,
      from: this.id,
      commitmentHex,
      timestamp: now,
      signatureHex: sig,
    };
  }

  /**
   * Round 1: Decommitment
   */
  public async onDecommitRequest(sessionId: string): Promise<Round1DecommitmentMessage> {
    const session = this.activeSessions.get(sessionId);
    if (!session || session.state !== 'COMMITTED') {
      throw new Error(`[Participant ${this.id}] Invalid state for decommit in session '${sessionId}'`);
    }

    session.state = 'DECOMMITTED';
    const gammaPointHex = session.Gamma_i.toHex(true);
    const paillierNHex = this.paillierKey.publicKey.N.toString(16);
    const encryptedGammaHex = session.encGamma.toString(16);
    const encryptedWHex = session.encW.toString(16);

    const sig = this.signPayload(
      `ROUND1_DECOMMIT:${sessionId}:${gammaPointHex}:${paillierNHex}:${encryptedGammaHex}:${encryptedWHex}`
    );

    return {
      type: 'ROUND1_DECOMMIT',
      sessionId,
      from: this.id,
      gammaPointHex,
      paillierNHex,
      encryptedGammaHex,
      encryptedWHex,
      timestamp: Date.now(),
      signatureHex: sig,
    };
  }

  /**
   * Round 2: Pairwise MtA Packet Generation
   */
  public async generatePairwiseMtaPackets(
    sessionId: string,
    allDecommitments: Round1DecommitmentMessage[]
  ): Promise<{ packets: Round2PairwiseMtaPacket[] }> {
    const session = this.activeSessions.get(sessionId);
    if (!session || session.state !== 'DECOMMITTED') {
      throw new Error(`[Participant ${this.id}] Invalid state for MtA packet generation`);
    }

    for (const d of allDecommitments) {
      if (d.from === this.id) continue;
      session.peerDecommitments.set(d.from, d);
    }

    const packets: Round2PairwiseMtaPacket[] = [];
    const peers = session.config.participants.filter((p) => p.id !== this.id);

    for (const peer of peers) {
      const peerDecommit = session.peerDecommitments.get(peer.id);
      if (!peerDecommit) {
        throw new Error(`[Participant ${this.id}] Missing decommitment for peer '${peer.id}'`);
      }

      // Check peer against trusted participant registry
      const peerEnrolled = trustedParticipantRegistry.verifyEnrolledIdentity(
        peer.id,
        peer.identityPublicKeyHex || peer.publicKeyHex,
        peer.domain
      );
      if (!peerEnrolled.valid) {
        throw new Error(`[Participant ${this.id}] Peer '${peer.id}' identity verification failed: ${peerEnrolled.reason}`);
      }

      // Verify peer decommitment signature
      const peerPk = peer.identityPublicKeyHex || peer.publicKeyHex;
      const expectedDecommitMsg = `ROUND1_DECOMMIT:${sessionId}:${peerDecommit.gammaPointHex}:${peerDecommit.paillierNHex}:${peerDecommit.encryptedGammaHex}:${peerDecommit.encryptedWHex}`;
      if (!verifyParticipantSignature(expectedDecommitMsg, peerDecommit.signatureHex, peerPk)) {
        throw new Error(`[Participant ${this.id}] Invalid digital signature on peer '${peer.id}' decommitment`);
      }

      const peerN = BigInt('0x' + peerDecommit.paillierNHex);
      const peerPub: PaillierPublicKey = {
        N: peerN,
        N2: peerN * peerN,
        bits: peerN.toString(2).length,
      };

      if (!validatePaillierPublicKey(peerPub)) {
        throw new Error(`[Participant ${this.id}] Peer '${peer.id}' announced invalid Paillier key`);
      }

      const peerEncGamma = BigInt('0x' + peerDecommit.encryptedGammaHex);
      const peerEncW = BigInt('0x' + peerDecommit.encryptedWHex);

      if (!validatePaillierCiphertext(peerEncGamma, peerPub) || !validatePaillierCiphertext(peerEncW, peerPub)) {
        throw new Error(`[Participant ${this.id}] Peer '${peer.id}' announced invalid Paillier ciphertext`);
      }

      const mu_ij = randomScalar();
      const alpha_ij = randomScalar();
      session.mu.set(peer.id, mu_ij);
      session.alpha.set(peer.id, alpha_ij);

      const cDelta = paillierHomomorphicMultiplyAndBlind(peerEncGamma, session.k_i, mu_ij, peerPub);
      const cSigma = paillierHomomorphicMultiplyAndBlind(peerEncW, session.k_i, alpha_ij, peerPub);

      const cDeltaHex = cDelta.toString(16);
      const cSigmaHex = cSigma.toString(16);
      const sig = this.signPayload(`ROUND2_MTA:${sessionId}:${peer.id}:${cDeltaHex}:${cSigmaHex}`);

      packets.push({
        type: 'ROUND2_PAIRWISE_MTA',
        sessionId,
        from: this.id,
        to: peer.id,
        cDeltaHex,
        cSigmaHex,
        timestamp: Date.now(),
        signatureHex: sig,
      });
    }

    return { packets };
  }

  /**
   * Round 2: Process Incoming Pairwise MtA Packets
   */
  public async onPeerMtaPacketsReceived(
    sessionId: string,
    incomingPackets: Round2PairwiseMtaPacket[]
  ): Promise<Round2DeltaShareMessage> {
    const session = this.activeSessions.get(sessionId);
    if (!session || session.state !== 'DECOMMITTED') {
      throw new Error(`[Participant ${this.id}] Invalid state for processing incoming MtA`);
    }

    const peers = session.config.participants.filter((p) => p.id !== this.id);

    for (const packet of incomingPackets) {
      if (packet.to !== this.id) continue;

      const sender = session.config.participants.find((p) => p.id === packet.from);
      if (!sender) throw new Error(`[Participant ${this.id}] Unknown sender '${packet.from}'`);

      const senderPk = sender.identityPublicKeyHex || sender.publicKeyHex;
      const expectedMsg = `ROUND2_MTA:${sessionId}:${this.id}:${packet.cDeltaHex}:${packet.cSigmaHex}`;
      if (!verifyParticipantSignature(expectedMsg, packet.signatureHex, senderPk)) {
        throw new Error(`[Participant ${this.id}] Invalid signature on incoming MtA packet from '${packet.from}'`);
      }

      const cDelta = BigInt('0x' + packet.cDeltaHex);
      const cSigma = BigInt('0x' + packet.cSigmaHex);

      if (!validatePaillierCiphertext(cDelta, this.paillierKey.publicKey) || !validatePaillierCiphertext(cSigma, this.paillierKey.publicKey)) {
        throw new Error(`[Participant ${this.id}] Corrupted ciphertext from peer '${packet.from}'`);
      }

      const rawNu = paillierDecrypt(cDelta, this.paillierKey.privateKey);
      const rawBeta = paillierDecrypt(cSigma, this.paillierKey.privateKey);

      const nu_ji = decodeSignedPlaintext(rawNu, this.paillierKey.publicKey.N, CURVE_ORDER);
      const beta_ji = decodeSignedPlaintext(rawBeta, this.paillierKey.publicKey.N, CURVE_ORDER);

      session.nu.set(packet.from, nu_ji);
      session.beta.set(packet.from, beta_ji);
    }

    for (const peer of peers) {
      if (!session.nu.has(peer.id) || !session.beta.has(peer.id)) {
        throw new Error(`[Participant ${this.id}] Missing MtA share from peer '${peer.id}'`);
      }
    }

    let delta_i = modN(session.k_i * session.gamma_i);
    for (const peer of peers) {
      delta_i = modN(delta_i + (session.mu.get(peer.id) || 0n) + (session.nu.get(peer.id) || 0n));
    }
    session.delta_i = delta_i;

    let sigma_i = modN(session.k_i * session.w_i);
    for (const peer of peers) {
      sigma_i = modN(sigma_i + (session.alpha.get(peer.id) || 0n) + (session.beta.get(peer.id) || 0n));
    }
    session.sigma_i = sigma_i;

    session.state = 'MTA_EXCHANGED';
    const deltaHex = scalarToHex(delta_i);
    const sig = this.signPayload(`ROUND2_DELTA:${sessionId}:${deltaHex}`);

    return {
      type: 'ROUND2_DELTA_SHARE',
      sessionId,
      from: this.id,
      deltaShareHex: deltaHex,
      timestamp: Date.now(),
      signatureHex: sig,
    };
  }

  /**
   * Round 3: Compute Partial Signature & Wipe Ephemeral Memory
   */
  public async computePartialSignature(
    sessionId: string,
    r: bigint
  ): Promise<Round3PartialSignatureMessage> {
    const session = this.activeSessions.get(sessionId);
    if (!session || session.state !== 'MTA_EXCHANGED') {
      throw new Error(`[Participant ${this.id}] Invalid state for Round 3 signing`);
    }

    if (r <= 0n || r >= CURVE_ORDER) {
      throw new Error(`[Participant ${this.id}] Invalid scalar r: out of bounds`);
    }

    const m = session.config.messageScalar;
    const k_i = session.k_i;
    const sigma_i = session.sigma_i!;

    const s_i = modN(modN(m * k_i) + modN(r * sigma_i));

    // Zeroize Ephemeral Memory
    session.k_i = 0n;
    session.gamma_i = 0n;
    session.w_i = 0n;
    session.sigma_i = 0n;
    session.mu.clear();
    session.nu.clear();
    session.alpha.clear();
    session.beta.clear();

    session.state = 'COMPLETED';
    this.usedSessionIds.add(sessionId);

    const sShareHex = scalarToHex(s_i);
    const sig = this.signPayload(`ROUND3_PARTIAL_SIG:${sessionId}:${sShareHex}`);

    return {
      type: 'ROUND3_PARTIAL_SIG',
      sessionId,
      from: this.id,
      sShareHex,
      timestamp: Date.now(),
      signatureHex: sig,
    };
  }

  /**
   * Aborts active session and wipes memory.
   */
  public abortSession(sessionId: string, reason: string): void {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.k_i = 0n;
      session.gamma_i = 0n;
      session.w_i = 0n;
      session.mu.clear();
      session.nu.clear();
      session.alpha.clear();
      session.beta.clear();
      session.state = 'ABORTED';
      this.activeSessions.delete(sessionId);
      this.usedSessionIds.add(sessionId);
      console.warn(`[Participant ${this.id}] Session '${sessionId}' aborted: ${reason}`);
    }
  }
}

