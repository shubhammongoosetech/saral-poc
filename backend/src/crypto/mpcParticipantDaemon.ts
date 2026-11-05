/**
 * mpcParticipantDaemon.ts
 *
 * Independent MPC Participant Daemon for SARAL Decentralized Threshold ECDSA.
 *
 * Security Architecture:
 *   - Autonomous Node Process: Each participant daemon isolates its private Shamir share s_i.
 *   - Zero Export: s_i, w_i, k_i, gamma_i are never transmitted across network or exported via getters.
 *   - Asymmetric Public-Key Authentication: All round messages are signed with the daemon's
 *     independent secp256k1 identity key and verified with its public key (no shared HMAC).
 *   - Audited Paillier Homomorphic Encryption: Fresh cryptographically secure randomness for every MtA
 *     packet. Pairwise cross-terms evaluated homomorphically with strict range and signed plaintext decoding.
 *   - Replay & Expiry Protection: Unique single-use session UUIDs and strict validity windows.
 *   - Memory Zeroization & Limitations: Session nonces (k_i, gamma_i, w_i, sigma_i) are unlinked and
 *     overwritten with 0n upon partial signature emission or abort.
 *     [Limitation Note: In JavaScript V8, BigInt primitives are immutable heap allocations; while
 *      object references are zeroized and maps cleared, complete RAM overwrite depends on V8 GC cycles.]
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  randomScalar,
  scalarMultiplyG,
  scalarToHex,
  G,
} from './secp256k1Math';
import {
  computeLagrangeCoefficient,
  verifyShareWithCommitments,
} from './shamirField';
import {
  ParticipantId,
  MpcSessionConfig,
  Round1CommitmentMessage,
  Round1DecommitmentMessage,
  Round2PairwiseMtaPacket,
  Round2DeltaShareMessage,
  Round3PartialSignatureMessage,
} from './mpcProtocolTypes';
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
} from './paillierCrypto';
import { loadOrCreateNodeIdentity } from '../participant/nodeIdentityManager';
import { DomainType } from './thresholdEcdsa';

export type DaemonSessionState =
  | 'INITIALIZED'
  | 'ROUND1_COMMITTED'
  | 'ROUND1_DECOMMITTED'
  | 'ROUND2_MTA_EXCHANGED'
  | 'COMPLETED'
  | 'ABORTED';

interface ActiveSessionMemory {
  config: MpcSessionConfig;
  state: DaemonSessionState;
  w_i: bigint;            // Effective additive Shamir share for this session
  k_i: bigint;            // Ephemeral nonce share
  gamma_i: bigint;        // Ephemeral masking scalar
  Gamma_i: typeof G;      // Ephemeral curve commitment Gamma_i = gamma_i * G
  encGamma: bigint;       // Enc(gamma_i) under daemon's Paillier key
  encW: bigint;           // Enc(w_i) under daemon's Paillier key
  commitmentHex: string;  // SHA256 commitment announced in Round 1
  peerDecommitments: Map<ParticipantId, Round1DecommitmentMessage>;
  mu: Map<ParticipantId, bigint>;    // Outgoing MtA blinding pads for gamma
  nu: Map<ParticipantId, bigint>;    // Incoming MtA decrypted shares for gamma
  alpha: Map<ParticipantId, bigint>; // Outgoing MtA blinding pads for w
  beta: Map<ParticipantId, bigint>;  // Incoming MtA decrypted shares for w
  delta_i?: bigint;       // Announced delta share
  sigma_i?: bigint;       // Local product share sigma_i = k * w (aggregated locally)
  createdAt: number;
}

/**
 * Asymmetrically verifies a daemon's signature using its secp256k1 identity public key.
 */
export function verifyDaemonSignature(
  payload: string,
  signatureHex: string,
  identityPublicKeyHex: string
): boolean {
  try {
    const hash = crypto.createHash('sha256').update(payload).digest();
    const cleanPub = identityPublicKeyHex.startsWith('0x')
      ? identityPublicKeyHex.slice(2)
      : identityPublicKeyHex;
    return secp256k1.verify(signatureHex, hash, cleanPub);
  } catch {
    return false;
  }
}

export class MpcParticipantDaemon {
  public readonly id: ParticipantId;
  public readonly domain: DomainType;
  public readonly nodeIndex: number;
  public readonly shareIndex: number;

  // Private isolated share strictly in daemon memory (NEVER EXPORTED)
  private privateShareValue: bigint;

  // Node cryptographic identity for pairwise signing (secp256k1 asymmetric keypair)
  private identityPrivateKeyHex: string;
  public readonly identityPublicKeyHex: string;

  // Node Paillier keypair for pairwise MtA operations
  private paillierKey: PaillierKeyPair;

  // Replay prevention: Set of observed/used session IDs
  private usedSessionIds = new Set<string>();

  // Active sessions in memory
  private sessions = new Map<string, ActiveSessionMemory>();

  constructor(
    domain: DomainType,
    nodeIndex: number,
    shareIndex: number,
    privateShareValue: bigint,
    paillierBits: number = process.env.PAILLIER_BITS
      ? parseInt(process.env.PAILLIER_BITS, 10)
      : process.env.NODE_ENV === 'production'
      ? 2048
      : 1024
  ) {
    this.domain = domain;
    this.nodeIndex = nodeIndex;
    this.shareIndex = shareIndex;
    this.id = `saral-daemon-${domain.toLowerCase()}-${nodeIndex}`;
    this.privateShareValue = modN(privateShareValue);

    // Persistent secp256k1 node identity keypair loaded from protected local vault (0o600)
    const identity = loadOrCreateNodeIdentity(this.id);
    this.identityPrivateKeyHex = identity.identityPrivateKeyHex;
    this.identityPublicKeyHex = identity.identityPublicKeyHex;

    // Initialize Paillier keypair for homomorphic MtA (2048-bit standard)
    this.paillierKey = generatePaillierKeyPair(paillierBits);
  }

  /**
   * Updates the node's private share during proactive secret sharing (PSS) refresh.
   */
  public updateRefreshedShare(newShareValue: bigint): void {
    this.privateShareValue = modN(newShareValue);
  }

  /**
   * Checks whether the participant daemon has a valid Shamir share loaded.
   */
  public isLoaded(): boolean {
    return this.privateShareValue !== undefined && this.privateShareValue > 0n;
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
    const now = Date.now();

    // 1. Replay Protection: Check if session ID was already used or active
    if (this.usedSessionIds.has(config.sessionId) || this.sessions.has(config.sessionId)) {
      throw new Error(`[Daemon ${this.id}] Replay attack detected: sessionId '${config.sessionId}' has already been processed`);
    }
    if (now > config.expiresAt) {
      throw new Error(`[Daemon ${this.id}] Session '${config.sessionId}' has expired (replay window closed)`);
    }

    // 2. Participation Validation: Ensure this daemon is part of the session
    const me = config.participants.find((p) => p.id === this.id);
    if (!me) {
      throw new Error(`[Daemon ${this.id}] Daemon is not an active participant in session '${config.sessionId}'`);
    }

    // 3. Feldman VSS Self-Verification: Detect if local share was corrupted before signing
    if (commitmentsHex && commitmentsHex.length > 0) {
      const isShareValid = verifyShareWithCommitments(
        { index: this.shareIndex, value: this.privateShareValue },
        commitmentsHex
      );
      if (!isShareValid) {
        throw new Error(`[Daemon ${this.id}] Feldman VSS verification failed: local share corrupted`);
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

    // 5. Generate ephemeral nonce shares (k_i, gamma_i) locally with fresh randomness
    const k_i = randomScalar();
    const gamma_i = randomScalar();
    const Gamma_i = scalarMultiplyG(gamma_i);

    // Encrypt gamma_i and w_i under daemon's OWN Paillier public key with fresh randomness
    const encGamma = paillierEncrypt(gamma_i, this.paillierKey.publicKey);
    const encW = paillierEncrypt(w_i, this.paillierKey.publicKey);

    // Commitment C_i = SHA256(sessionId || id || Gamma_i || N || encGamma || encW)
    const commitInput = `${config.sessionId}:${this.id}:${Gamma_i.toHex(true)}:${this.paillierKey.publicKey.N.toString(16)}:${encGamma.toString(16)}:${encW.toString(16)}`;
    const commitmentHex = crypto.createHash('sha256').update(commitInput).digest('hex');

    // Register active session memory
    this.sessions.set(config.sessionId, {
      config,
      state: 'ROUND1_COMMITTED',
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
   * Round 1 Decommit: Reveals Gamma_i, Paillier public key, and encrypted inputs.
   */
  public async onDecommitRequest(sessionId: string): Promise<Round1DecommitmentMessage> {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'ROUND1_COMMITTED') {
      throw new Error(`[Daemon ${this.id}] Invalid state for decommit in session '${sessionId}'`);
    }

    session.state = 'ROUND1_DECOMMITTED';
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
   * Round 2: Pairwise MtA Packet Generation using Paillier Homomorphic Encryption
   */
  public async generatePairwiseMtaPackets(
    sessionId: string,
    allDecommitments: Round1DecommitmentMessage[]
  ): Promise<{
    packets: Round2PairwiseMtaPacket[];
  }> {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'ROUND1_DECOMMITTED') {
      throw new Error(`[Daemon ${this.id}] Invalid state for Round 2 MtA generation in session '${sessionId}'`);
    }

    // Verify and store peer decommitments
    for (const decommit of allDecommitments) {
      if (decommit.from === this.id) continue;
      session.peerDecommitments.set(decommit.from, decommit);
    }

    const packets: Round2PairwiseMtaPacket[] = [];
    const peers = session.config.participants.filter((p) => p.id !== this.id);

    for (const peer of peers) {
      const peerDecommit = session.peerDecommitments.get(peer.id);
      if (!peerDecommit) {
        throw new Error(`[Daemon ${this.id}] Missing decommitment for peer '${peer.id}'`);
      }

      // Verify peer decommitment digital signature
      const peerPk = peer.identityPublicKeyHex || peer.publicKeyHex;
      const expectedMsg = `ROUND1_DECOMMIT:${sessionId}:${peerDecommit.gammaPointHex}:${peerDecommit.paillierNHex}:${peerDecommit.encryptedGammaHex}:${peerDecommit.encryptedWHex}`;
      if (!verifyDaemonSignature(expectedMsg, peerDecommit.signatureHex, peerPk)) {
        throw new Error(`[Daemon ${this.id}] Asymmetric signature verification failed for peer '${peer.id}' decommitment`);
      }

      const peerN = BigInt('0x' + peerDecommit.paillierNHex);
      const peerPub: PaillierPublicKey = {
        N: peerN,
        N2: peerN * peerN,
        bits: peerN.toString(2).length,
      };

      if (!validatePaillierPublicKey(peerPub)) {
        throw new Error(`[Daemon ${this.id}] Peer '${peer.id}' announced invalid Paillier public key`);
      }

      const peerEncGamma = BigInt('0x' + peerDecommit.encryptedGammaHex);
      const peerEncW = BigInt('0x' + peerDecommit.encryptedWHex);

      if (!validatePaillierCiphertext(peerEncGamma, peerPub) || !validatePaillierCiphertext(peerEncW, peerPub)) {
        throw new Error(`[Daemon ${this.id}] Peer '${peer.id}' announced invalid Paillier ciphertext in decommitment`);
      }

      // Choose uniform random blinding pads
      const mu_ij = randomScalar();
      const alpha_ij = randomScalar();
      session.mu.set(peer.id, mu_ij);
      session.alpha.set(peer.id, alpha_ij);

      // Homomorphically evaluate scalar products with fresh randomness under peer's Paillier key
      const cDelta = paillierHomomorphicMultiplyAndBlind(
        peerEncGamma,
        session.k_i,
        mu_ij,
        peerPub
      );
      const cSigma = paillierHomomorphicMultiplyAndBlind(
        peerEncW,
        session.k_i,
        alpha_ij,
        peerPub
      );

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
   * Round 2: Process Incoming Pairwise MtA Packets & Compute Delta Share
   */
  public async onPeerMtaPacketsReceived(
    sessionId: string,
    incomingPackets: Round2PairwiseMtaPacket[]
  ): Promise<Round2DeltaShareMessage> {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'ROUND1_DECOMMITTED') {
      throw new Error(`[Daemon ${this.id}] Invalid state for processing incoming MtA in session '${sessionId}'`);
    }

    const peers = session.config.participants.filter((p) => p.id !== this.id);

    // Decrypt incoming packets using daemon's OWN Paillier private key
    for (const packet of incomingPackets) {
      if (packet.to !== this.id) continue;

      // Verify asymmetric signature of incoming MtA packet
      const sender = session.config.participants.find((p) => p.id === packet.from);
      if (!sender) {
        throw new Error(`[Daemon ${this.id}] Unknown sender '${packet.from}' for MtA packet`);
      }

      const senderPk = sender.identityPublicKeyHex || sender.publicKeyHex;
      const expectedMsg = `ROUND2_MTA:${sessionId}:${this.id}:${packet.cDeltaHex}:${packet.cSigmaHex}`;
      if (!verifyDaemonSignature(expectedMsg, packet.signatureHex, senderPk)) {
        throw new Error(`[Daemon ${this.id}] Invalid digital signature on MtA packet from '${packet.from}'`);
      }

      try {
        const cDelta = BigInt('0x' + packet.cDeltaHex);
        const cSigma = BigInt('0x' + packet.cSigmaHex);

        if (
          !validatePaillierCiphertext(cDelta, this.paillierKey.publicKey) ||
          !validatePaillierCiphertext(cSigma, this.paillierKey.publicKey)
        ) {
          throw new Error(`[Daemon ${this.id}] Invalid Paillier ciphertext received from ${packet.from}`);
        }

        const rawNu = paillierDecrypt(cDelta, this.paillierKey.privateKey);
        const rawBeta = paillierDecrypt(cSigma, this.paillierKey.privateKey);

        // Safe signed decoding: convert Z_N to signed integer and reduce mod CURVE_ORDER
        const nu_ji = decodeSignedPlaintext(rawNu, this.paillierKey.publicKey.N, CURVE_ORDER);
        const beta_ji = decodeSignedPlaintext(rawBeta, this.paillierKey.publicKey.N, CURVE_ORDER);

        session.nu.set(packet.from, nu_ji);
        session.beta.set(packet.from, beta_ji);
      } catch (err: any) {
        this.abortSession(sessionId, `Paillier decryption failure from peer ${packet.from}`);
        throw new Error(`[Daemon ${this.id}] Malicious MtA packet detected from ${packet.from}: Decryption failure`);
      }
    }

    // Verify all peer shares arrived
    for (const peer of peers) {
      if (!session.nu.has(peer.id) || !session.beta.has(peer.id)) {
        throw new Error(`[Daemon ${this.id}] Missing MtA share from peer ${peer.id}`);
      }
    }

    // Compute local delta share: delta_i = k_i * gamma_i + sum_{j != i} (mu_{ij} + nu_{ij}) mod n
    let delta_i = modN(session.k_i * session.gamma_i);
    for (const peer of peers) {
      const mu_val = session.mu.get(peer.id) || 0n;
      const nu_val = session.nu.get(peer.id) || 0n;
      delta_i = modN(delta_i + mu_val + nu_val);
    }
    session.delta_i = delta_i;

    // Compute local sigma share: sigma_i = k_i * w_i + sum_{j != i} (alpha_{ij} + beta_{ij}) mod n
    let sigma_i = modN(session.k_i * session.w_i);
    for (const peer of peers) {
      const alpha_val = session.alpha.get(peer.id) || 0n;
      const beta_val = session.beta.get(peer.id) || 0n;
      sigma_i = modN(sigma_i + alpha_val + beta_val);
    }
    session.sigma_i = sigma_i;

    session.state = 'ROUND2_MTA_EXCHANGED';
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
   * Round 3: Compute Partial Signature & Wipe Ephemeral Nonces
   *
   * Partial signature: s_i = (m * k_i + r * sigma_i) mod n
   * CRITICAL SECURITY STEP: All ephemeral nonces are zeroized immediately after this call.
   */
  public async computePartialSignature(
    sessionId: string,
    r: bigint
  ): Promise<Round3PartialSignatureMessage> {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'ROUND2_MTA_EXCHANGED') {
      throw new Error(`[Daemon ${this.id}] Invalid state for Round 3 signing in session '${sessionId}'`);
    }

    if (r <= 0n || r >= CURVE_ORDER) {
      throw new Error(`[Daemon ${this.id}] Invalid curve scalar r received from coordinator: out of bounds`);
    }

    const m = session.config.messageScalar;
    const k_i = session.k_i;
    const sigma_i = session.sigma_i!;

    // s_i = (m * k_i + r * sigma_i) mod n
    const s_i = modN(modN(m * k_i) + modN(r * sigma_i));

    // Unlink and zeroize ephemeral nonces to prevent reuse or memory leaks
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
   * Safely aborts an active session and wipes memory.
   */
  public abortSession(sessionId: string, reason: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.k_i = 0n;
      session.gamma_i = 0n;
      session.w_i = 0n;
      session.mu.clear();
      session.nu.clear();
      session.alpha.clear();
      session.beta.clear();
      session.state = 'ABORTED';
      this.sessions.delete(sessionId);
      this.usedSessionIds.add(sessionId);
      console.warn(`[Daemon ${this.id}] Session '${sessionId}' aborted: ${reason}`);
    }
  }

  /**
   * Explicitly wipes and zeroizes active session state.
   */
  public wipeSession(sessionId: string): void {
    this.abortSession(sessionId, 'Zeroized and wiped');
  }
}
