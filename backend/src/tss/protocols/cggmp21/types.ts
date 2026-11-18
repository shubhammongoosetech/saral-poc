/**
 * types.ts
 *
 * Types for CGGMP21 (Canetti-Gennaro-Goldfeder-Makriyannis-Peled 2021)
 * Threshold ECDSA Protocol over secp256k1 for Ethereum and EVM-compatible chains.
 */

export interface Cggmp21KeyShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  secretScalarHex: string;   // 32-byte secret Shamir share scalar mod n
  publicKeyHex: string;      // 33-byte compressed participant public key
  groupPublicKeyHex: string; // 33-byte or 65-byte aggregated group public key
}

export interface Cggmp21LogStarProof {
  A_hex: string;  // A = alpha * G
  z_hex: string;  // z = alpha + e * x mod n
}

export interface Cggmp21AffGProof {
  A_hex: string;  // A = alpha * G
  B_hex: string;  // Commitment to Paillier intermediate
  z1_hex: string; // Response for scalar
  z2_hex: string; // Response for blinding
}

export interface Cggmp21Round1Commitment {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  commitmentHex: string; // Hash(sessionId || from || Gamma_pt || K_pt)
}

export interface Cggmp21Round2Decommitment {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  gammaPointHex: string; // 33-byte compressed Gamma_i = gamma_i * G
  kPointHex: string;     // 33-byte compressed K_i = k_i * G
  logStarProof: Cggmp21LogStarProof;
  affGProof: Cggmp21AffGProof;
  signatureHex: string;  // Asymmetric digital signature by participant
}

export interface Cggmp21Round3DeltaShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  deltaShareHex: string; // 32-byte delta_i = k_i * gamma mod n
  chiShareHex: string;   // 32-byte chi_i = k_i * w_i mod n
  signatureHex: string;
}

export interface Cggmp21Round4SignatureShare {
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  sigmaShareHex: string; // 32-byte sigma_i = k_i * m + r * chi_i mod n
  signatureHex: string;
}

export interface Cggmp21Signature {
  r: string;         // 32-byte hex
  s: string;         // 32-byte hex (canonical low-s <= n/2)
  yParity: 0 | 1;
  v: number;         // EIP-155 replay-protected v or yParity
  rawSignatureHex: string; // 65-byte hex: r (32) || s (32) || v (1)
  recoveredAddress: string; // Checksummed Ethereum address
}
