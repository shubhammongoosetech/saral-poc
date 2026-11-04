/**
 * mpcProtocolTypes.ts
 *
 * Formal Protocol Definitions for SARAL True Decentralized Interactive MPC
 * (Compatible with CGGMP21 / GG20 Threshold ECDSA).
 *
 * Core Security Invariants:
 *  1. Coordinator is strictly a stateless relay and signature aggregator.
 *  2. Private Shamir shares s_i and effective shares w_i NEVER leave participant daemons.
 *  3. Nonce shares k_i and gamma_i are generated locally and wiped after use.
 *  4. Pairwise MtA messages are encrypted and authenticated directly between participant pairs.
 *  5. Replayed, modified, or out-of-order session messages are strictly rejected.
 */

import { DomainType } from './thresholdEcdsa';

export type ParticipantId = string;

export interface MpcParticipantIdentity {
  id: ParticipantId;
  domain: DomainType;
  shareIndex: number;
  nodeIndex: number;
  publicKeyHex: string; // Ephemeral or long-term ECDH/signing public key
  identityPublicKeyHex?: string; // secp256k1 identity verification public key
}

export interface MpcSessionConfig {
  sessionId: string; // Unique cryptographic session UUID
  unsignedTxSerialized: string; // EVM unsigned transaction
  chainId: bigint;
  msgHashHex: string; // keccak256(unsignedTxSerialized)
  messageScalar: bigint; // m in F_n
  participants: MpcParticipantIdentity[];
  thresholds: {
    foundation: number; // 1
    public: number; // e.g. 5
    private: number; // e.g. 5
  };
  expectedAggregatedPublicKeyHex: string;
  createdAt: number;
  expiresAt: number; // Replay window expiration (e.g. 60s)
}

/**
 * Round 1: Nonce Commitment Phase
 * Each participant i commits to its ephemeral point Gamma_i = gamma_i * G:
 *   C_i = H(sessionId || participantId || Gamma_i)
 */
export interface Round1CommitmentMessage {
  type: 'ROUND1_COMMIT';
  sessionId: string;
  from: ParticipantId;
  commitmentHex: string; // 32-byte hex hash commitment
  timestamp: number;
  signatureHex: string; // Authenticated participant signature
}

/**
 * Round 1: Nonce Decommitment Phase
 * Each participant i reveals its ephemeral public curve point Gamma_i:
 */
export interface Round1DecommitmentMessage {
  type: 'ROUND1_DECOMMIT';
  sessionId: string;
  from: ParticipantId;
  gammaPointHex: string; // Compressed point Gamma_i
  paillierNHex: string; // Paillier public modulus N_i
  encryptedGammaHex: string; // PaillierEnc_{N_i}(gamma_i)
  encryptedWHex: string; // PaillierEnc_{N_i}(w_i)
  timestamp: number;
  signatureHex: string;
}

/**
 * Round 2: Pairwise MtA Packet
 * Directly targeted from participant A to participant B.
 * Transports homomorphic ciphertexts evaluated under recipient's Paillier key:
 *   cDelta: (Enc(gamma_j)^k_i) * Enc(-mu_{ij}) mod N_j^2
 *   cSigma: (Enc(w_j)^k_i) * Enc(-alpha_{ij}) mod N_j^2
 */
export interface Round2PairwiseMtaPacket {
  type: 'ROUND2_PAIRWISE_MTA';
  sessionId: string;
  from: ParticipantId;
  to: ParticipantId;
  cDeltaHex: string;
  cSigmaHex: string;
  timestamp: number;
  signatureHex: string;
}

/**
 * Round 2: Participant Delta Share Broadcast
 * Each participant announces its local delta share:
 *   delta_i = k_i * gamma_i + sum_{j != i} (mu_{ij} + nu_{ij}) mod n
 */
export interface Round2DeltaShareMessage {
  type: 'ROUND2_DELTA_SHARE';
  sessionId: string;
  from: ParticipantId;
  deltaShareHex: string; // delta_i mod n
  timestamp: number;
  signatureHex: string;
}

/**
 * Round 3: Partial Signature Contribution
 * Each participant calculates its partial signature scalar:
 *   s_i = (m * k_i + r * sigma_i) mod n
 */
export interface Round3PartialSignatureMessage {
  type: 'ROUND3_PARTIAL_SIG';
  sessionId: string;
  from: ParticipantId;
  sShareHex: string; // s_i mod n
  timestamp: number;
  signatureHex: string;
}

export interface DistributedMpcSigningResult {
  sessionId: string;
  r: string; // 0x... (32-byte hex)
  s: string; // 0x... (32-byte hex, canonical low-s)
  yParity: 0 | 1;
  v: number;
  rawSignedTx: string;
  txHash: string;
  signingQuorum: {
    foundationAuthorized: boolean;
    publicNodeCount: number;
    privateNodeCount: number;
  };
  participatingNodes: {
    foundation: ParticipantId[];
    publicDomain: ParticipantId[];
    privateDomain: ParticipantId[];
  };
  metrics: {
    round1DurationMs: number;
    round2DurationMs: number;
    round3DurationMs: number;
    totalDurationMs: number;
  };
}
