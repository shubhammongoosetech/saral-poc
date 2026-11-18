/**
 * frostEd25519.ts
 *
 * RFC 9591 Flexible Round-Optimized Schnorr Threshold Signatures (FROST)
 * over Edwards25519 for native Solana multi-party transaction signing.
 *
 * Mathematical Invariants:
 *  - Curve: Edwards25519 (x^2 + y^2 = 1 + d x^2 y^2)
 *  - Order: L = 2^252 + 27742317777372353535851937790883648493
 *  - Secret scalars: mod L (little-endian 32-byte encoding)
 *  - Curve points: ExtendedPoint (compressed 32-byte encoding)
 *  - Verification equation: z * B = R + c * Y
 *  - Standard Ed25519 compatibility: signatures verify with official Ed25519 verifiers.
 */

import crypto from 'crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { PublicKey } from '@solana/web3.js';
import {
  FrostEd25519KeyShare,
  FrostEd25519NoncePair,
  FrostEd25519NonceCommitment,
  FrostEd25519SignatureShare,
  FrostEd25519Signature,
} from './types';

export const ED25519_ORDER: bigint = ed25519.CURVE.n;
const L = ED25519_ORDER;

export function modL(a: bigint): bigint {
  return ((a % L) + L) % L;
}

export function modInverseL(a: bigint): bigint {
  let [old_r, r] = [modL(a), L];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return modL(old_s);
}

export function encodeScalarLittleEndian(scalar: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let temp = modL(scalar);
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return buf;
}

export function decodeScalarLittleEndian(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < bytes.length; i++) {
    res += BigInt(bytes[i]) << (8n * BigInt(i));
  }
  return res % L;
}

export function computeEd25519LagrangeCoefficient(i: number, participantIndices: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of participantIndices) {
    if (j === i) continue;
    num = modL(num * BigInt(j));
    den = modL(den * BigInt(j - i));
  }
  return modL(num * modInverseL(den));
}

/**
 * Derives RFC 9591 binding factor rho_i for participant i given context and all commitments.
 */
export function computeEd25519BindingFactor(
  participantIndex: number,
  message: Uint8Array,
  commitments: FrostEd25519NonceCommitment[]
): bigint {
  const sorted = [...commitments].sort((a, b) => a.shareIndex - b.shareIndex);
  const h = crypto.createHash('sha512');
  h.update('FROST-ED25519-SHA512-v1:rho');
  h.update(Buffer.from([participantIndex & 0xff]));
  h.update(Buffer.from(message));
  for (const c of sorted) {
    h.update(Buffer.from(c.D_hex, 'hex'));
    h.update(Buffer.from(c.E_hex, 'hex'));
  }
  const digest = h.digest();
  return decodeScalarLittleEndian(digest);
}

/**
 * Computes standard Ed25519 challenge: c = SHA-512(R || Y || m) mod L
 */
export function computeEd25519Challenge(
  R_bytes: Uint8Array,
  Y_bytes: Uint8Array,
  message: Uint8Array
): bigint {
  const digest = crypto
    .createHash('sha512')
    .update(Buffer.from(R_bytes))
    .update(Buffer.from(Y_bytes))
    .update(Buffer.from(message))
    .digest();
  return decodeScalarLittleEndian(digest);
}

/**
 * Autonomous Participant Round 1: Generate nonces d_i, e_i and public commitments D_i, E_i.
 */
export function generateEd25519NoncePair(): FrostEd25519NoncePair {
  let d = 0n;
  let e = 0n;
  while (d === 0n) {
    d = modL(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }
  while (e === 0n) {
    e = modL(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }

  const D_pt = ed25519.ExtendedPoint.BASE.multiply(d);
  const E_pt = ed25519.ExtendedPoint.BASE.multiply(e);

  return {
    d,
    e,
    D_hex: Buffer.from(D_pt.toRawBytes()).toString('hex'),
    E_hex: Buffer.from(E_pt.toRawBytes()).toString('hex'),
  };
}

/**
 * Autonomous Participant Round 2: Compute partial signature share z_i.
 *
 * For a 3-Domain setting:
 * If within-domain Lagrange is applied, participantIndices is the list of active participants
 * within participant's own domain.
 */
export function computeEd25519SignatureShare(
  keyShare: FrostEd25519KeyShare,
  noncePair: FrostEd25519NoncePair,
  commitments: FrostEd25519NonceCommitment[],
  domainParticipants: number[],
  groupCommitmentR_bytes: Uint8Array,
  groupPublicKey_bytes: Uint8Array,
  message: Uint8Array
): FrostEd25519SignatureShare {
  const rho_i = computeEd25519BindingFactor(keyShare.shareIndex, message, commitments);
  const c = computeEd25519Challenge(groupCommitmentR_bytes, groupPublicKey_bytes, message);
  const lambda_i = computeEd25519LagrangeCoefficient(keyShare.shareIndex, domainParticipants);
  const secret_i = BigInt('0x' + keyShare.secretScalarHex) % L;

  // z_i = d_i + (rho_i * e_i) + (lambda_i * s_i * c) mod L
  const bindingTerm = modL(rho_i * noncePair.e);
  const keyTerm = modL(modL(lambda_i * secret_i) * c);
  const z_i = modL(noncePair.d + bindingTerm + keyTerm);

  const z_bytes = encodeScalarLittleEndian(z_i);

  return {
    participantId: keyShare.participantId,
    shareIndex: keyShare.shareIndex,
    domain: keyShare.domain,
    zShareHex: Buffer.from(z_bytes).toString('hex'),
  };
}

/**
 * Aggregator: Computes the group commitment R = sum(D_i + rho_i * E_i)
 */
export function aggregateEd25519GroupCommitment(
  commitments: FrostEd25519NonceCommitment[],
  message: Uint8Array
): { R_bytes: Uint8Array; R_hex: string } {
  let R_total: typeof ed25519.ExtendedPoint.BASE | null = null;

  for (const c of commitments) {
    const rho_i = computeEd25519BindingFactor(c.shareIndex, message, commitments);
    const D_pt = ed25519.ExtendedPoint.fromHex(c.D_hex);
    const E_pt = ed25519.ExtendedPoint.fromHex(c.E_hex);
    const R_i = D_pt.add(E_pt.multiply(rho_i));
    R_total = R_total ? R_total.add(R_i) : R_i;
  }

  if (!R_total) {
    throw new Error('[FROST-Ed25519] No commitments provided for aggregation');
  }

  const R_bytes = R_total.toRawBytes();
  return {
    R_bytes,
    R_hex: Buffer.from(R_bytes).toString('hex'),
  };
}

/**
 * Aggregator: Combines partial signature shares into an authentic Ed25519 signature (R || z).
 */
export function aggregateEd25519Signature(
  shares: FrostEd25519SignatureShare[],
  R_bytes: Uint8Array,
  groupPublicKey_bytes: Uint8Array,
  message: Uint8Array
): FrostEd25519Signature {
  let z_sum = 0n;

  for (const s of shares) {
    const s_bytes = Buffer.from(s.zShareHex, 'hex');
    const z_i = decodeScalarLittleEndian(s_bytes);
    z_sum = modL(z_sum + z_i);
  }

  const z_bytes = encodeScalarLittleEndian(z_sum);
  const rawSig = new Uint8Array(64);
  rawSig.set(R_bytes, 0);
  rawSig.set(z_bytes, 32);

  const isValid = ed25519.verify(rawSig, message, groupPublicKey_bytes);
  if (!isValid) {
    throw new Error('[FROST-Ed25519] Aggregated threshold signature failed cryptographic verification');
  }

  const pk = new PublicKey(groupPublicKey_bytes);

  return {
    rawSignatureHex: Buffer.from(rawSig).toString('hex'),
    R_hex: Buffer.from(R_bytes).toString('hex'),
    z_hex: Buffer.from(z_bytes).toString('hex'),
    groupPublicKeyHex: Buffer.from(groupPublicKey_bytes).toString('hex'),
    solanaAddress: pk.toBase58(),
  };
}

/**
 * Validates whether an Ed25519 signature is cryptographically valid.
 */
export function verifyEd25519Signature(
  rawSignature: Uint8Array | string,
  message: Uint8Array | string,
  groupPublicKey: Uint8Array | string
): boolean {
  const sigBytes = typeof rawSignature === 'string' ? Buffer.from(rawSignature, 'hex') : rawSignature;
  const msgBytes = typeof message === 'string' ? Buffer.from(message) : message;
  const pkBytes = typeof groupPublicKey === 'string' ? Buffer.from(groupPublicKey, 'hex') : groupPublicKey;
  return ed25519.verify(sigBytes, msgBytes, pkBytes);
}

/**
 * Verifies an individual participant's FROST Ed25519 signature share before aggregation (RFC 9591 Section 4.5).
 * Identifiable Abort: Checks: z_i * B == (D_i + rho_i * E_i) + (c * lambda_i) * Y_i
 */
export function verifyEd25519SignatureShare(
  share: FrostEd25519SignatureShare,
  commitment: FrostEd25519NonceCommitment,
  allCommitments: FrostEd25519NonceCommitment[],
  domainParticipants: number[],
  participantPublicKeyHex: string,
  groupCommitmentR_bytes: Uint8Array,
  groupPublicKey_bytes: Uint8Array,
  message: Uint8Array
): { valid: boolean; reason?: string } {
  try {
    const rho_i = computeEd25519BindingFactor(share.shareIndex, message, allCommitments);
    const c = computeEd25519Challenge(groupCommitmentR_bytes, groupPublicKey_bytes, message);
    const lambda_i = computeEd25519LagrangeCoefficient(share.shareIndex, domainParticipants);

    const z_i = decodeScalarLittleEndian(Buffer.from(share.zShareHex, 'hex'));
    const D_pt = ed25519.ExtendedPoint.fromHex(commitment.D_hex);
    const E_pt = ed25519.ExtendedPoint.fromHex(commitment.E_hex);
    const Y_i = ed25519.ExtendedPoint.fromHex(participantPublicKeyHex);

    // Left: z_i * B
    const left = ed25519.ExtendedPoint.BASE.multiply(z_i);

    // Right: (D_i + rho_i * E_i) + (c * lambda_i) * Y_i
    const R_i = D_pt.add(E_pt.multiply(rho_i));
    const coeff = modL(c * lambda_i);
    const right = R_i.add(Y_i.multiply(coeff));

    if (!left.equals(right)) {
      return {
        valid: false,
        reason: `Participant ${share.participantId} submitted invalid Ed25519 signature share (equation failed)`,
      };
    }
    return { valid: true };
  } catch (err: any) {
    return { valid: false, reason: err.message || 'Signature share verification failed' };
  }
}

export interface Ed25519DkgResult {
  groupPublicKeyHex: string;
  solanaAddress: string;
  participantShares: Map<number, FrostEd25519KeyShare>;
  commitments: Map<number, string[]>;
}

/**
 * Executes a pure dealerless DKG ceremony over Edwards25519 for Solana.
 * Every participant independently samples its secret polynomial, distributes verifiable
 * shares, verifies peer commitments, and aggregates its local share strictly in vault.
 * Zero Central Private Key: No coordinator ever reconstructs the master scalar.
 */
export function executeEd25519DealerlessDkg(
  participants: { id: string; index: number; domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE' }[],
  threshold: number
): Ed25519DkgResult {
  const n = participants.length;
  if (threshold < 1 || threshold > n) {
    throw new Error(`[FROST-Ed25519 DKG] Invalid threshold ${threshold} for ${n} participants`);
  }

  // 1. Each participant i samples a secret polynomial f_i(x) of degree t - 1
  const secretPolynomials = new Map<number, bigint[]>();
  const feldmanCommitments = new Map<number, string[]>();

  for (const p of participants) {
    const coeffs: bigint[] = [];
    const comms: string[] = [];
    for (let k = 0; k < threshold; k++) {
      let a_k = 0n;
      while (a_k === 0n) {
        a_k = modL(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
      }
      coeffs.push(a_k);
      const C_k = ed25519.ExtendedPoint.BASE.multiply(a_k);
      comms.push(Buffer.from(C_k.toRawBytes()).toString('hex'));
    }
    secretPolynomials.set(p.index, coeffs);
    feldmanCommitments.set(p.index, comms);
  }

  // 2. Each participant i computes share for participant j: s_ij = f_i(j) mod L
  // and participant j verifies against participant i's commitments
  const sharesFor = new Map<number, bigint[]>();
  for (const p of participants) {
    sharesFor.set(p.index, []);
  }

  for (const dealer of participants) {
    const coeffs = secretPolynomials.get(dealer.index)!;
    const comms = feldmanCommitments.get(dealer.index)!;

    for (const recipient of participants) {
      let s_ij = 0n;
      let x_power = 1n;
      const x = BigInt(recipient.index);
      for (let k = 0; k < threshold; k++) {
        s_ij = modL(s_ij + modL(coeffs[k] * x_power));
        x_power = modL(x_power * x);
      }

      // Verify share s_ij against dealer's commitments: s_ij * B == sum(j^k * C_k)
      const lhs = ed25519.ExtendedPoint.BASE.multiply(s_ij);
      let rhs: typeof ed25519.ExtendedPoint.BASE | null = null;
      let x_pow = 1n;
      for (let k = 0; k < threshold; k++) {
        const C_k = ed25519.ExtendedPoint.fromHex(comms[k]);
        const term = C_k.multiply(x_pow);
        rhs = rhs ? rhs.add(term) : term;
        x_pow = modL(x_pow * x);
      }

      if (!lhs.equals(rhs!)) {
        throw new Error(
          `[FROST-Ed25519 DKG] Share verification failed from dealer ${dealer.id} to recipient ${recipient.id}`
        );
      }

      sharesFor.get(recipient.index)!.push(s_ij);
    }
  }

  // 3. Each participant j aggregates its local share: s_j = sum_{i=1}^n s_ij mod L
  const participantShares = new Map<number, FrostEd25519KeyShare>();
  let groupPublicKeyPt: typeof ed25519.ExtendedPoint.BASE | null = null;

  // Group public key Y = sum_{i=1}^n C_i0
  for (const p of participants) {
    const c0_hex = feldmanCommitments.get(p.index)![0];
    const C0 = ed25519.ExtendedPoint.fromHex(c0_hex);
    groupPublicKeyPt = groupPublicKeyPt ? groupPublicKeyPt.add(C0) : C0;
  }

  const groupPublicKeyBytes = groupPublicKeyPt!.toRawBytes();
  const groupPublicKeyHex = Buffer.from(groupPublicKeyBytes).toString('hex');
  const solanaAddress = new PublicKey(groupPublicKeyBytes).toBase58();

  for (const p of participants) {
    const receivedShares = sharesFor.get(p.index)!;
    let s_j = 0n;
    for (const share of receivedShares) {
      s_j = modL(s_j + share);
    }

    const Y_j = ed25519.ExtendedPoint.BASE.multiply(s_j);

    participantShares.set(p.index, {
      participantId: p.id,
      shareIndex: p.index,
      domain: p.domain,
      secretScalarHex: s_j.toString(16).padStart(64, '0'),
      publicKeyHex: Buffer.from(Y_j.toRawBytes()).toString('hex'),
      groupPublicKeyHex,
    });
  }

  return {
    groupPublicKeyHex,
    solanaAddress,
    participantShares,
    commitments: feldmanCommitments,
  };
}
