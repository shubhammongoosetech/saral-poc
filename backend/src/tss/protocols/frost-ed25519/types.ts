/**
 * types.ts
 *
 * Types for RFC 9591 Flexible Round-Optimized Schnorr Threshold Signatures (FROST)
 * over Edwards25519 (Ed25519) curve for Solana native threshold signing.
 */

export interface FrostEd25519KeyShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  secretScalarHex: string; // 32-byte scalar mod L in hex
  publicKeyHex: string;    // 32-byte compressed point in hex
  groupPublicKeyHex: string; // 32-byte compressed group public key in hex
}

export interface FrostEd25519NoncePair {
  d: bigint; // Secret hiding nonce mod L
  e: bigint; // Secret binding nonce mod L
  D_hex: string; // 32-byte compressed point D = d * B
  E_hex: string; // 32-byte compressed point E = e * B
}

export interface FrostEd25519NonceCommitment {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  D_hex: string; // 32-byte compressed point D = d * B
  E_hex: string; // 32-byte compressed point E = e * B
}

export interface FrostEd25519SignatureShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  zShareHex: string; // 32-byte scalar mod L in hex
}

export interface FrostEd25519Signature {
  rawSignatureHex: string; // 64-byte signature: R_bytes (32) || z_bytes (32)
  R_hex: string;          // 32-byte compressed point R
  z_hex: string;          // 32-byte scalar z
  groupPublicKeyHex: string; // 32-byte compressed point Y
  solanaAddress: string;  // Base58 encoded group public key
}

export interface DomainParticipantConfig {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
}
