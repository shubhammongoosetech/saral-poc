/**
 * shamirField.ts
 *
 * Cryptographically sound Shamir Secret Sharing over the finite scalar field F_n
 * of secp256k1.
 *
 * Features:
 *  - Polynomial evaluation & interpolation strictly modulo curve order n.
 *  - Feldman Verifiable Secret Sharing (VSS) point commitments.
 *  - Lagrange basis coefficient derivation for non-reconstructing MPC.
 *  - Tamper & invalid share detection.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  modInverse,
  randomScalar,
  scalarMultiplyG,
  G,
} from './secp256k1Math';

export interface FieldShare {
  index: number; // x-coordinate (1..N)
  value: bigint; // y-coordinate in F_n
}

export interface VerifiableSecretSharingResult {
  shares: FieldShare[];
  commitments: string[]; // Feldman commitments C_k = a_k * G in hex
  threshold: number;
  totalShares: number;
}

/**
 * Evaluates polynomial P(x) = c_0 + c_1*x + ... + c_{d}*x^d (mod n)
 */
export function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
  let result = 0n;
  let powerOfX = 1n;

  for (let i = 0; i < coefficients.length; i++) {
    const term = modN(coefficients[i] * powerOfX);
    result = modN(result + term);
    powerOfX = modN(powerOfX * x);
  }

  return result;
}

/**
 * Splits a secret scalar into N shares with threshold T over F_n.
 * Generates Feldman VSS commitments C_k = a_k * G for share verification.
 */
export function splitSecretField(
  secret: bigint,
  totalShares: number,
  threshold: number
): VerifiableSecretSharingResult {
  if (threshold < 1 || threshold > totalShares) {
    throw new Error(`Invalid threshold: must be 1 <= threshold <= totalShares (${totalShares})`);
  }
  if (totalShares > 255) {
    throw new Error('Total shares cannot exceed 255');
  }

  const normSecret = modN(secret);
  if (normSecret === 0n) {
    throw new Error('Secret cannot be zero in F_n');
  }

  // Coefficients: a_0 = secret, a_1..a_{threshold-1} = random scalars in F_n
  const coefficients: bigint[] = [normSecret];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomScalar());
  }

  // Feldman commitments C_k = a_k * G
  const commitments: string[] = coefficients.map((coeff) => {
    const pt = scalarMultiplyG(coeff);
    return pt.toHex(true);
  });

  // Evaluate at x = 1, 2, ..., totalShares
  const shares: FieldShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = BigInt(i);
    const value = evaluatePolynomial(coefficients, x);
    shares.push({ index: i, value });
  }

  return {
    shares,
    commitments,
    threshold,
    totalShares,
  };
}

/**
 * Verifies that a given share (index, value) matches the Feldman commitments.
 * Check: value * G == sum_{k=0}^{T-1} (index^k) * C_k
 */
export function verifyShareWithCommitments(
  share: FieldShare,
  commitmentsHex: string[]
): boolean {
  try {
    if (share.index < 1 || share.value <= 0n || share.value >= CURVE_ORDER) {
      return false;
    }
    const sharePoint = scalarMultiplyG(share.value);
    const x = BigInt(share.index);

    let expectedPoint: typeof G | null = null;
    let powerOfX = 1n;

    for (const commHex of commitmentsHex) {
      const cleanHex = commHex.startsWith('0x') ? commHex.slice(2) : commHex;
      const C_k = secp256k1.ProjectivePoint.fromHex(cleanHex);
      const term = C_k.multiply(powerOfX);

      expectedPoint = expectedPoint ? expectedPoint.add(term) : term;
      powerOfX = modN(powerOfX * x);
    }

    if (!expectedPoint) return false;
    return sharePoint.equals(expectedPoint);
  } catch {
    return false;
  }
}

/**
 * Generates a Zero-Polynomial for Proactive Secret Sharing (PSS) key refresh:
 *   h(z) = b_1 * z + b_2 * z^2 + ... + b_{threshold-1} * z^{threshold-1} (mod n)
 * Notice: h(0) = 0. The constant term is strictly zero.
 */
export function generateZeroPolynomial(threshold: number): bigint[] {
  if (threshold < 2) {
    throw new Error('Zero-polynomial requires threshold >= 2');
  }
  const coefficients: bigint[] = [0n]; // b_0 = 0
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomScalar());
  }
  return coefficients;
}

/**
 * Evaluates a zero-polynomial at position x:
 *   delta = h(x) = sum_{k=1}^{t-1} b_k * x^k (mod n)
 */
export function evaluateZeroPolynomial(coefficients: bigint[], x: bigint): bigint {
  return evaluatePolynomial(coefficients, x);
}

/**
 * Refreshes an existing field share using a zero-polynomial contribution:
 *   s_i' = (s_i + h(i)) mod n
 * Reconstructed secret f'(0) = f(0) + h(0) = secret + 0 = secret (mod n).
 */
export function proactiveRefreshShare(
  oldShare: FieldShare,
  zeroPolyOrDelta: bigint[] | bigint
): FieldShare {
  const delta = Array.isArray(zeroPolyOrDelta)
    ? evaluateZeroPolynomial(zeroPolyOrDelta, BigInt(oldShare.index))
    : zeroPolyOrDelta;
  const refreshedValue = modN(oldShare.value + delta);
  return {
    index: oldShare.index,
    value: refreshedValue,
  };
}

/**
 * Updates Feldman commitments for the refreshed polynomial:
 *   C_0' = C_0  (constant term unchanged: public key is preserved!)
 *   C_k' = C_k + (b_k * G) for k >= 1
 */
export function refreshFeldmanCommitments(
  oldCommitmentsHex: string[],
  zeroPolyCoeffs: bigint[]
): string[] {
  const newCommitments: string[] = [];

  for (let k = 0; k < oldCommitmentsHex.length; k++) {
    const cleanHex = oldCommitmentsHex[k].startsWith('0x')
      ? oldCommitmentsHex[k].slice(2)
      : oldCommitmentsHex[k];
    const oldPoint = secp256k1.ProjectivePoint.fromHex(cleanHex);

    if (k === 0 || k >= zeroPolyCoeffs.length) {
      // C_0 is unchanged because b_0 = 0
      newCommitments.push(oldPoint.toHex(true));
    } else {
      const b_k = zeroPolyCoeffs[k];
      const deltaPoint = scalarMultiplyG(b_k);
      const updatedPoint = oldPoint.add(deltaPoint);
      newCommitments.push(updatedPoint.toHex(true));
    }
  }

  return newCommitments;
}

/**
 * Computes the Lagrange basis coefficient lambda_j(0) for party j in a subset S:
 *   lambda_j(0) = prod_{m in S, m != j} (0 - m) / (j - m)  (mod n)
 */
export function computeLagrangeCoefficient(
  jIndex: number,
  allIndices: number[]
): bigint {
  if (!allIndices.includes(jIndex)) {
    throw new Error(`Index ${jIndex} is not in the active subset`);
  }

  const j = BigInt(jIndex);
  let numerator = 1n;
  let denominator = 1n;

  for (const mIndex of allIndices) {
    if (mIndex === jIndex) continue;
    const m = BigInt(mIndex);
    numerator = modN(numerator * modN(-m));
    denominator = modN(denominator * modN(j - m));
  }

  const denominatorInv = modInverse(denominator, CURVE_ORDER);
  return modN(numerator * denominatorInv);
}

/**
 * Reconstructs the secret scalar from at least threshold shares using Lagrange interpolation.
 */
export function reconstructSecretField(
  shares: FieldShare[],
  threshold: number
): bigint {
  if (shares.length < threshold) {
    throw new Error(`Insufficient shares: need ${threshold}, provided ${shares.length}`);
  }

  // Deduplicate and validate indices
  const uniqueIndices = new Set<number>();
  for (const s of shares) {
    if (s.index < 1) throw new Error(`Invalid share index: ${s.index}`);
    if (uniqueIndices.has(s.index)) {
      throw new Error(`Duplicate share index detected: ${s.index}`);
    }
    uniqueIndices.add(s.index);
  }

  const activeSubset = shares.slice(0, threshold);
  const activeIndices = activeSubset.map((s) => s.index);

  let secret = 0n;
  for (const s of activeSubset) {
    const lambda = computeLagrangeCoefficient(s.index, activeIndices);
    const term = modN(lambda * s.value);
    secret = modN(secret + term);
  }

  return secret;
}
