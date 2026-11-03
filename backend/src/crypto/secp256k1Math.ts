/**
 * secp256k1Math.ts
 *
 * Mathematically rigorous finite-field arithmetic over secp256k1 curve
 * and its scalar field F_n.
 *
 * Curve parameters:
 *   y^2 = x^3 + 7 (mod p)
 *   p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 *   n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import crypto from 'crypto';

export const CURVE_ORDER = secp256k1.CURVE.n; // n
export const FIELD_PRIME = secp256k1.CURVE.Fp.ORDER; // p
export const G = secp256k1.ProjectivePoint.BASE; // Base generator point

/**
 * Normalizes any BigInt to [0, n - 1] in F_n.
 */
export function modN(a: bigint): bigint {
  const result = a % CURVE_ORDER;
  return result >= 0n ? result : result + CURVE_ORDER;
}

/**
 * Computes modular inverse a^(-1) mod n using the Extended Euclidean Algorithm.
 */
export function modInverse(a: bigint, m: bigint = CURVE_ORDER): bigint {
  let [old_r, r] = [modN(a), m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }

  if (old_r !== 1n) {
    throw new Error('Modular inverse does not exist (inputs not coprime)');
  }

  return (old_s % m + m) % m;
}

/**
 * Generates a cryptographically secure random non-zero scalar in F_n.
 */
export function randomScalar(): bigint {
  while (true) {
    const bytes = crypto.randomBytes(32);
    const scalar = BigInt('0x' + bytes.toString('hex'));
    if (scalar > 0n && scalar < CURVE_ORDER) {
      return scalar;
    }
  }
}

/**
 * Multiplies generator point G by scalar k.
 */
export function scalarMultiplyG(k: bigint) {
  const normK = modN(k);
  if (normK === 0n) {
    throw new Error('Cannot multiply G by zero scalar');
  }
  return G.multiply(normK);
}

/**
 * Adds two secp256k1 projective points.
 */
export function pointAdd(
  p1: typeof G,
  p2: typeof G
): typeof G {
  return p1.add(p2);
}

/**
 * Converts a 32-byte hex string or Buffer to BigInt scalar in F_n.
 */
export function hexToScalar(hex: string | Buffer): bigint {
  const cleanHex = Buffer.isBuffer(hex)
    ? hex.toString('hex')
    : hex.startsWith('0x')
    ? hex.slice(2)
    : hex;
  return modN(BigInt('0x' + cleanHex));
}

/**
 * Converts a BigInt scalar to a 32-byte (64-character) hex string.
 */
export function scalarToHex(scalar: bigint): string {
  return modN(scalar).toString(16).padStart(64, '0');
}

