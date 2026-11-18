/**
 * types.ts
 *
 * Distributed Key Generation (DKG) Protocol & Session Types
 * Based on "Distributed Key Generation in the Wild" (Kate, Huang, Goldberg 2012).
 */

import { DomainType } from '../types/domain';

export type DkgSessionState =
  | 'CREATED'
  | 'PARTICIPANTS_REGISTERED'
  | 'DKG_RUNNING'
  | 'SHARES_VERIFIED'
  | 'AGREEMENT_PENDING'
  | 'DKG_COMPLETED'
  | 'FAILED';

export interface DkgParticipantRegistration {
  id: string; // e.g. saral-public-1
  nodeIndex: number; // 1-based index (1..n)
  domain: DomainType;
  identityPublicKeyHex: string; // Compressed 33-byte secp256k1 hex
  registeredAt: number;
}

export interface DkgSessionConfig {
  sessionId: string;
  domain: DomainType;
  n: number;
  t: number;
  f: number;
  threshold: number; // k = t + 1
  timeoutMs: number;
  createdAt: number;
  expiresAt: number;
}

export interface EncryptedShareEnvelope {
  type: 'ENCRYPTED_SHARE';
  sessionId: string;
  domain: DomainType;
  dealerIndex: number;
  targetIndex: number;
  commitmentMatrix: string[][]; // (t+1) x (t+1) DLog commitments
  encryptedPayload: string; // AES-256-GCM ciphertext containing row polynomial coefficients
  ivHex: string;
  authTagHex: string;
  senderPublicKeyHex: string;
  signatureHex: string; // secp256k1 signature over payload
  timestamp: number;
}

export interface SignedProtocolEnvelope {
  type: 'DKG_PROTOCOL_MSG';
  sessionId: string;
  domain: DomainType;
  fromIndex: number;
  targetIndex: number | 'broadcast';
  payload: any;
  senderPublicKeyHex: string;
  signatureHex: string;
  timestamp: number;
}

export interface DkgSessionFinalResult {
  sessionId: string;
  domain: DomainType;
  domainPublicKeyHex: string; // Q_d = sum_{d in Q} C_{d,00}
  commitments: string[]; // Combined row-0 commitments C_k
  agreedQ: number[]; // Set of t+1 dealers
  threshold: number;
  n: number;
  completedAt: number;
  participatingNodeIds: string[];
}
