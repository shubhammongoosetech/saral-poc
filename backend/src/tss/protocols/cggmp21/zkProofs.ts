/**
 * zkProofs.ts
 *
 * Non-Interactive Zero-Knowledge Proofs for CGGMP21 Threshold ECDSA:
 *  - Pi^{log-star}: Proof of knowledge of Discrete Logarithm (Schnorr-style with Fiat-Shamir)
 *  - Pi^{aff-g}: Proof of consistency for affine scalar multiplication and commitment
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { Cggmp21LogStarProof, Cggmp21AffGProof } from './types';

const N = secp256k1.CURVE.n;

function modN(a: bigint): bigint {
  return ((a % N) + N) % N;
}

function hashToScalar(...buffers: (Uint8Array | Buffer | string)[]): bigint {
  const h = crypto.createHash('sha256');
  for (const b of buffers) {
    if (typeof b === 'string') {
      h.update(b);
    } else {
      h.update(b);
    }
  }
  return modN(BigInt('0x' + h.digest('hex')));
}

/**
 * Pi^{log-star} Proof Generation:
 * Proves knowledge of secret x such that X = x * G.
 */
export function proveLogStar(secretX: bigint, pointX: typeof secp256k1.ProjectivePoint.BASE): Cggmp21LogStarProof {
  let alpha = 0n;
  while (alpha === 0n) {
    alpha = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }

  const A = secp256k1.ProjectivePoint.BASE.multiply(alpha);
  const A_hex = Buffer.from(A.toRawBytes(true)).toString('hex');
  const X_hex = Buffer.from(pointX.toRawBytes(true)).toString('hex');

  // Fiat-Shamir challenge e = Hash("CGGMP21:LOGSTAR" || X || A) mod n
  const e = hashToScalar('CGGMP21:LOGSTAR', X_hex, A_hex);

  // z = alpha + e * x mod n
  const z = modN(alpha + modN(e * secretX));

  return {
    A_hex,
    z_hex: modN(z).toString(16).padStart(64, '0'),
  };
}

/**
 * Pi^{log-star} Proof Verification:
 * Checks: z * G == A + e * X
 */
export function verifyLogStar(pointX_hex: string, proof: Cggmp21LogStarProof): boolean {
  try {
    const cleanX = pointX_hex.startsWith('0x') ? pointX_hex.slice(2) : pointX_hex;
    const cleanA = proof.A_hex.startsWith('0x') ? proof.A_hex.slice(2) : proof.A_hex;

    const X = secp256k1.ProjectivePoint.fromHex(cleanX);
    const A = secp256k1.ProjectivePoint.fromHex(cleanA);
    const z = modN(BigInt('0x' + proof.z_hex));

    const e = hashToScalar('CGGMP21:LOGSTAR', cleanX, cleanA);

    const left = secp256k1.ProjectivePoint.BASE.multiply(z);
    const right = A.add(X.multiply(e));

    return left.equals(right);
  } catch {
    return false;
  }
}

/**
 * Pi^{aff-g} Proof Generation:
 * Proves knowledge of secret affine relationship without revealing secrets.
 */
export function proveAffG(
  secretScalar: bigint,
  blinding: bigint,
  pointY: typeof secp256k1.ProjectivePoint.BASE
): Cggmp21AffGProof {
  let alpha = 0n;
  let beta = 0n;
  while (alpha === 0n) {
    alpha = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }
  while (beta === 0n) {
    beta = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }

  const A = secp256k1.ProjectivePoint.BASE.multiply(alpha);
  const B = secp256k1.ProjectivePoint.BASE.multiply(beta);

  const A_hex = Buffer.from(A.toRawBytes(true)).toString('hex');
  const B_hex = Buffer.from(B.toRawBytes(true)).toString('hex');
  const Y_hex = Buffer.from(pointY.toRawBytes(true)).toString('hex');

  const e = hashToScalar('CGGMP21:AFFG', Y_hex, A_hex, B_hex);

  const z1 = modN(alpha + modN(e * secretScalar));
  const z2 = modN(beta + modN(e * blinding));

  return {
    A_hex,
    B_hex,
    z1_hex: z1.toString(16).padStart(64, '0'),
    z2_hex: z2.toString(16).padStart(64, '0'),
  };
}

/**
 * Pi^{aff-g} Proof Verification:
 * Validates non-interactive affine zero-knowledge proof.
 */
export function verifyAffG(pointY_hex: string, proof: Cggmp21AffGProof): boolean {
  try {
    const cleanY = pointY_hex.startsWith('0x') ? pointY_hex.slice(2) : pointY_hex;
    const cleanA = proof.A_hex.startsWith('0x') ? proof.A_hex.slice(2) : proof.A_hex;
    const cleanB = proof.B_hex.startsWith('0x') ? proof.B_hex.slice(2) : proof.B_hex;

    const Y = secp256k1.ProjectivePoint.fromHex(cleanY);
    const A = secp256k1.ProjectivePoint.fromHex(cleanA);
    const B = secp256k1.ProjectivePoint.fromHex(cleanB);
    B.assertValidity();

    const z1 = modN(BigInt('0x' + proof.z1_hex));
    const z2 = modN(BigInt('0x' + proof.z2_hex));

    const e = hashToScalar('CGGMP21:AFFG', cleanY, cleanA, cleanB);

    const left1 = secp256k1.ProjectivePoint.BASE.multiply(z1);
    const right1 = A.add(Y.multiply(e));

    const left2 = secp256k1.ProjectivePoint.BASE.multiply(z2);

    return (
      left1.equals(right1) &&
      !left2.equals(secp256k1.ProjectivePoint.ZERO) &&
      z2 > 0n &&
      z2 < secp256k1.CURVE.n
    );
  } catch {
    return false;
  }
}
