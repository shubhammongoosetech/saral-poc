/**
 * types.ts
 *
 * Types for P2P Node Networking and Authenticated Transport in SARAL.
 */

import { DomainName } from '../domain/types';

export type TssProtocol = 'HYBRID_DKG' | 'FROST_ED25519' | 'FROST_TAPROOT' | 'CGGMP21';

export interface P2PPeerInfo {
  nodeId: string;
  domain: DomainName;
  nodeIndex: number;
  shareIndex: number;
  endpoint: string; // e.g., "127.0.0.1:12001" or "node1.cluster.internal:12001"
  identityPublicKeyHex: string; // 33-byte compressed secp256k1 public key
}

export interface P2PMessageEnvelope {
  protocol: TssProtocol;
  sessionId: string;
  fromNodeId: string;
  toNodeId: string; // recipient nodeId or "BROADCAST"
  timestamp: number;
  nonce: string;
  encrypted: boolean;
  payload: string; // AES-GCM ciphertext hex or plaintext JSON string
  signatureHex: string; // Secp256k1 signature over canonical envelope string
}

export interface P2PNodeDaemonConfig {
  nodeId: string;
  domain: DomainName;
  nodeIndex: number;
  shareIndex: number;
  host: string;
  port: number;
  vaultDir: string;
  peerDirectory: P2PPeerInfo[];
}

export interface StoredKeyShare {
  sessionId: string;
  protocol: TssProtocol;
  domain: DomainName;
  shareIndex: number;
  secretScalarHex: string;
  publicKeyHex: string;
  groupPublicKeyHex: string;
  createdAt: number;
}
