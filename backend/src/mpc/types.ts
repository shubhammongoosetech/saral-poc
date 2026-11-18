/**
 * types.ts
 *
 * Multi-Party Computation (MPC) Threshold Signing Protocol Types.
 * Implements GG18/GG20-family Threshold ECDSA over secp256k1 with 3-Domain additive aggregation.
 */

import { DomainType } from '../types/domain';

export type MpcSigningState =
  | 'SIGNING_INITIATED'
  | 'ROUND1_COMMITTED'
  | 'ROUND2_MTA_COMPLETED'
  | 'ROUND3_PARTIAL_SIGS_COLLECTED'
  | 'SIGNATURE_COMPLETED'
  | 'FAILED';

export interface MpcThresholdPolicy {
  foundation: number; // e.g. 1
  public: number; // e.g. 5
  private: number; // e.g. 5
}

export interface MpcSigningParticipantInfo {
  id: string;
  domain: DomainType;
  nodeIndex: number;
  shareIndex: number;
  identityPublicKeyHex: string;
}

export interface MpcSigningSessionConfig {
  sessionId: string;
  unsignedTxSerialized: string;
  chainId: bigint;
  msgHashHex: string;
  messageScalar: bigint;
  expectedAggregatedPublicKeyHex: string;
  thresholds: MpcThresholdPolicy;
  participants: MpcSigningParticipantInfo[];
  createdAt: number;
  expiresAt: number;
}

export interface FinalThresholdSignature {
  sessionId: string;
  r: string; // 0x... 32-byte hex
  s: string; // 0x... 32-byte hex (canonical low-s)
  yParity: 0 | 1;
  v: number;
  rawSignedTx: string;
  txHash: string;
  verified: boolean;
  signingQuorum: {
    foundationAuthorized: boolean;
    publicNodeCount: number;
    privateNodeCount: number;
  };
  completedAt: number;
}
