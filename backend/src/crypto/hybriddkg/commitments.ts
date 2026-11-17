/**
 * commitments.ts
 *
 * DLog commitment matrices (paper sec 5.3) over secp256k1 curve and mathematical verification predicates.
 *
 * Reference:
 *   "Distributed Key Generation in the Wild" (Kate, Huang, Goldberg), Section 3.1 & 4.
 *   - Commitment matrix C_jl = phi_jl * G, symmetric: C_jl = C_lj
 *   - verify-poly(C, i, a): a_l * G == sum_{j=0}^t i^j * C_jl for all l in 0..t
 *   - verify-point(C, i, m, alpha): alpha * G == sum_{j,l=0}^t m^j * i^l * C_jl
 *   - verify-reconstruct-share(C, m, sigma): sigma * G == sum_{j=0}^t m^j * C_j0
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  scalarMultiplyG,
  G,
} from '../secp256k1Math';
import type { SymmetricBivariatePoly } from './bivariatePolynomial';

export type Point = typeof G;

const pointParseCache = new Map<string, Point>();
const expectedPointCache = new Map<string, Point>();
const rowPointCache = new Map<string, Point>();
const matrixValidityCache = new Map<string, boolean>();
const verifyPolyCache = new Map<string, boolean>();
const pointVerifyCache = new Map<string, boolean>();

/**
 * Safely parses and validates a compressed secp256k1 point hex.
 * Points are asserted to be on-curve.
 */
export function parseCurvePoint(hex: string): Point {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const cached = pointParseCache.get(clean);
  if (cached) return cached;

  const pt = secp256k1.ProjectivePoint.fromHex(clean);
  pt.assertValidity();
  if (pointParseCache.size >= 10000) pointParseCache.clear();
  pointParseCache.set(clean, pt);
  return pt;
}

/**
 * Multiplies generator G by scalar k mod n, returning ProjectivePoint.ZERO if k == 0 mod n.
 */
export function scalarMultiplyGSafe(scalar: bigint): Point {
  const norm = modN(scalar);
  if (norm === 0n) {
    return secp256k1.ProjectivePoint.ZERO;
  }
  return scalarMultiplyG(norm);
}

/**
 * Multiplies an arbitrary projective point by a scalar mod n.
 */
export function pointMultiplySafe(pt: Point, scalar: bigint): Point {
  const norm = modN(scalar);
  if (norm === 0n || pt.equals(secp256k1.ProjectivePoint.ZERO)) {
    return secp256k1.ProjectivePoint.ZERO;
  }
  return pt.multiply(norm);
}

/**
 * Computes commitment matrix C_jl = phi_jl * G for a symmetric bivariate polynomial.
 * Returns (t+1) x (t+1) matrix in compressed hex format.
 */
export function computeCommitmentMatrix(poly: SymmetricBivariatePoly): string[][] {
  const t = poly.degree;
  const size = t + 1;
  const C: string[][] = Array.from({ length: size }, () => new Array<string>(size));

  for (let j = 0; j <= t; j++) {
    for (let l = j; l <= t; l++) {
      const coeff = poly.coeffs[j][l];
      const pt = scalarMultiplyGSafe(coeff);
      const hex = pt.toHex(true);
      C[j][l] = hex;
      C[l][j] = hex; // Enforce symmetry C_jl == C_lj
    }
  }

  return C;
}

/**
 * Computes a deterministic SHA-256 hash over the commitment matrix.
 */
export function computeMatrixHash(C: string[][]): string {
  const hash = crypto.createHash('sha256');
  for (const row of C) {
    for (const cell of row) {
      hash.update(cell);
    }
  }
  return hash.digest('hex');
}

/**
 * Validates structural and cryptographic invariants of a commitment matrix C:
 *   - Dimension (t+1) x (t+1)
 *   - Every entry is a valid on-curve point
 *   - Strictly symmetric: C_jl == C_lj
 */
export function validateCommitmentMatrix(C: string[][], expectedT: number): boolean {
  if (!Array.isArray(C) || C.length !== expectedT + 1) {
    return false;
  }

  // 1. Strict symmetry check upfront
  for (let j = 0; j <= expectedT; j++) {
    if (!Array.isArray(C[j]) || C[j].length !== expectedT + 1) {
      return false;
    }
    for (let l = 0; l <= expectedT; l++) {
      if (typeof C[j][l] !== 'string') return false;
      if (j !== l && C[j][l] !== C[l][j]) {
        return false; // Violates symmetry
      }
    }
  }

  // 2. Point validity check with cache
  const cacheKey = `${expectedT}:${C[0][0]}:${C[0][expectedT]}:${C[expectedT][expectedT]}`;
  const cached = matrixValidityCache.get(cacheKey);
  if (cached !== undefined) return cached;

  for (let j = 0; j <= expectedT; j++) {
    for (let l = 0; l <= expectedT; l++) {
      try {
        parseCurvePoint(C[j][l]);
      } catch {
        matrixValidityCache.set(cacheKey, false);
        return false;
      }
    }
  }

  if (matrixValidityCache.size >= 5000) matrixValidityCache.clear();
  matrixValidityCache.set(cacheKey, true);
  return true;
}

/**
 * Paper Section 3.1 & 4: verify-poly(C, i, a)
 * Verifies that the row polynomial a_i(y) = sum_{l=0}^t a_l y^l given to node i satisfies:
 *   a_l * G == sum_{j=0}^t (i^j * C_jl)   for all l in [0, t]
 */
export function verifyPoly(
  C: string[][],
  iIndex: number,
  aCoeffs: bigint[]
): boolean {
  try {
    const t = C.length - 1;
    if (aCoeffs.length !== t + 1) return false;
    if (!validateCommitmentMatrix(C, t)) return false;

    const cacheKey = `${C[0]?.[0] || ''}:${iIndex}:${aCoeffs.map((c) => c.toString(16)).join(':')}`;
    const cached = verifyPolyCache.get(cacheKey);
    if (cached !== undefined) return cached;

    const i = BigInt(iIndex);

    for (let l = 0; l <= t; l++) {
      // LHS: a_l * G
      const lhs = scalarMultiplyGSafe(aCoeffs[l]);

      // RHS: sum_{j=0}^t i^j * C_jl
      let rhs: Point = secp256k1.ProjectivePoint.ZERO;
      let iPow = 1n;
      for (let j = 0; j <= t; j++) {
        const C_jl = parseCurvePoint(C[j][l]);
        if (iPow !== 0n) {
          const term = pointMultiplySafe(C_jl, iPow);
          rhs = rhs.add(term);
        }
        iPow = modN(iPow * i);
      }

      if (!lhs.equals(rhs)) {
        verifyPolyCache.set(cacheKey, false);
        return false;
      }
    }

    if (verifyPolyCache.size >= 5000) verifyPolyCache.clear();
    verifyPolyCache.set(cacheKey, true);
    return true;
  } catch {
    return false;
  }
}

/**
 * Computes and caches row point R_j(i) = sum_{l=0}^t i^l * C_jl.
 * Factorizes the double sum into two single sums:
 *   sum_{j,l} m^j i^l C_jl = sum_{j=0}^t m^j R_j(i)
 * Reduces arbitrary curve scalar multiplications from (t+1)^2 to (t+1).
 */
function getRowPoint(C: string[][], iIndex: number, j: number): Point {
  const t = C.length - 1;
  const key = `${C[0]?.[0] || ''}:${C[0]?.[t] || ''}:${iIndex}:${j}`;
  const cached = rowPointCache.get(key);
  if (cached) return cached;

  const i = BigInt(iIndex);
  let pt: Point = secp256k1.ProjectivePoint.ZERO;
  let iPow = 1n;
  for (let l = 0; l <= t; l++) {
    const C_jl = parseCurvePoint(C[j][l]);
    if (iPow !== 0n) {
      const term = pointMultiplySafe(C_jl, iPow);
      pt = pt.add(term);
    }
    iPow = modN(iPow * i);
  }

  if (rowPointCache.size >= 5000) rowPointCache.clear();
  rowPointCache.set(key, pt);
  return pt;
}

/**
 * Evaluates the expected point sum_{j=0}^t sum_{l=0}^t (m^j * i^l * C_jl).
 * Uses row point factorization and caches by (C-hash, iIndex, mIndex).
 */
function getExpectedPoint(C: string[][], iIndex: number, mIndex: number): Point {
  const t = C.length - 1;
  const cacheKey = `${C[0]?.[0] || ''}:${C[0]?.[t] ?? ''}:${iIndex}:${mIndex}`;
  const cached = expectedPointCache.get(cacheKey);
  if (cached) return cached;

  const m = BigInt(mIndex);
  let rhs: Point = secp256k1.ProjectivePoint.ZERO;
  let mPow = 1n;

  for (let j = 0; j <= t; j++) {
    if (mPow !== 0n) {
      const R_j = getRowPoint(C, iIndex, j);
      const term = pointMultiplySafe(R_j, mPow);
      rhs = rhs.add(term);
    }
    mPow = modN(mPow * m);
  }

  if (expectedPointCache.size >= 10000) expectedPointCache.clear();
  expectedPointCache.set(cacheKey, rhs);
  return rhs;
}

/**
 * Paper Section 3.1 & 4: verify-point(C, i, m, alpha)
 * Verifies that a point evaluation alpha = a_m(i) sent from node m to node i satisfies:
 *   alpha * G == sum_{j=0}^t sum_{l=0}^t (m^j * i^l * C_jl)
 */
export function verifyPoint(
  C: string[][],
  iIndex: number, // recipient index
  mIndex: number, // sender index
  alpha: bigint
): boolean {
  try {
    const t = C.length - 1;
    if (!validateCommitmentMatrix(C, t)) return false;

    const normAlpha = modN(alpha);
    if (normAlpha === 0n || normAlpha >= CURVE_ORDER) return false;

    const cacheKey = `${C[0]?.[0] || ''}:${iIndex}:${mIndex}:${normAlpha}`;
    const cached = pointVerifyCache.get(cacheKey);
    if (cached !== undefined) return cached;

    const lhs = scalarMultiplyGSafe(normAlpha);
    const rhs = getExpectedPoint(C, iIndex, mIndex);
    const isValid = lhs.equals(rhs);

    if (pointVerifyCache.size >= 10000) pointVerifyCache.clear();
    pointVerifyCache.set(cacheKey, isValid);
    return isValid;
  } catch {
    return false;
  }
}

/**
 * Paper Section 3.1 (Rec): verify-reconstruct-share(C, m, sigma)
 * Verifies that a node's reconstructed final share sigma = s_m satisfies:
 *   sigma * G == sum_{j=0}^t (m^j * C_j0)
 */
export function verifyReconstructShare(
  C: string[][],
  mIndex: number,
  sigma: bigint
): boolean {
  try {
    const t = C.length - 1;
    if (!validateCommitmentMatrix(C, t)) return false;

    const normSigma = modN(sigma);
    if (normSigma === 0n || normSigma >= CURVE_ORDER) return false;

    const lhs = scalarMultiplyGSafe(normSigma);

    const m = BigInt(mIndex);
    let rhs: Point = secp256k1.ProjectivePoint.ZERO;
    let mPow = 1n;

    for (let j = 0; j <= t; j++) {
      const C_j0 = parseCurvePoint(C[j][0]);
      if (mPow !== 0n) {
        const term = pointMultiplySafe(C_j0, mPow);
        rhs = rhs.add(term);
      }
      mPow = modN(mPow * m);
    }

    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

/**
 * Adds two commitment matrices entry-wise on secp256k1.
 * (C1 + C2)_jl = C1_jl + C2_jl
 */
export function addCommitmentMatrices(C1: string[][], C2: string[][]): string[][] {
  const size = C1.length;
  if (C2.length !== size) {
    throw new Error('[CommitmentMatrix] Matrix size mismatch in addition');
  }

  const result: string[][] = Array.from({ length: size }, () => new Array<string>(size));

  for (let j = 0; j < size; j++) {
    for (let l = 0; l < size; l++) {
      const p1 = parseCurvePoint(C1[j][l]);
      const p2 = parseCurvePoint(C2[j][l]);
      const sum = p1.add(p2);
      result[j][l] = sum.toHex(true);
    }
  }

  return result;
}
