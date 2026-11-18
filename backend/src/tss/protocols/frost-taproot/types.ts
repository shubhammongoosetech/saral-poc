/**
 * types.ts
 *
 * Types for BIP-340 / BIP-341 Taproot-compatible FROST over secp256k1
 * for Bitcoin Schnorr and Taproot multi-party transaction signing.
 */

export interface FrostTaprootKeyShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  secretScalarHex: string; // 32-byte scalar mod n
  publicKeyHex: string;    // 33-byte compressed or 65-byte uncompressed point
  groupPublicKeyHex: string; // 32-byte x-only public key
}

export interface FrostTaprootNoncePair {
  d: bigint; // Hiding nonce mod n
  e: bigint; // Binding nonce mod n
  D_hex: string; // 33-byte compressed point D = d * G
  E_hex: string; // 33-byte compressed point E = e * G
}

export interface FrostTaprootNonceCommitment {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  D_hex: string; // 33-byte compressed point D = d * G
  E_hex: string; // 33-byte compressed point E = e * G
}

export interface FrostTaprootSignatureShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  zShareHex: string; // 32-byte scalar mod n
}

export interface FrostTaprootSignature {
  rawSignatureHex: string; // 64 bytes: R_x (32) || z (32)
  R_x_hex: string;         // 32-byte x-only nonce
  z_hex: string;           // 32-byte scalar z
  outputKeyHex: string;    // 32-byte x-only tweaked public key Q
  internalKeyHex: string;  // 32-byte x-only internal public key P
  taprootAddress: string;  // Bech32m P2TR address (bc1p... or tb1p...)
}
