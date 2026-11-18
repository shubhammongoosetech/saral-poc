/**
 * feldmanVss.ts
 *
 * Feldman Verifiable Secret Sharing (VSS) over secp256k1 scalar field F_n.
 * Reference: P. Feldman, "A practical scheme for non-interactive verifiable secret sharing", FOCS 1987.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  modInverse,
  randomScalar,
  scalarMultiplyG,
  G,
} from '../crypto/secp256k1Math';
import {
  VssShare,
  FeldmanVssPackage,
  VssComplaint,
  VssComplaintResolution,
} from './types';

/**
 * Evaluates polynomial P(x) = sum_{k=0}^{threshold-1} a_k * x^k (mod n)
 */
export function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
  let result = 0n;
  let powerOfX = 1n;
  const normX = modN(x);

  for (let i = 0; i < coefficients.length; i++) {
    const term = modN(coefficients[i] * powerOfX);
    result = modN(result + term);
    powerOfX = modN(powerOfX * normX);
  }

  return result;
}

/**
 * Generates a Feldman VSS distribution for a dealer.
 * P(0) = secret.
 * Commitments: C_k = a_k * G for k in 0..threshold-1.
 */
export function generateFeldmanVss(
  secret: bigint,
  totalShares: number,
  threshold: number,
  dealerId: string = 'dealer-1',
  dealerIndex: number = 1
): FeldmanVssPackage {
  if (threshold < 1 || threshold > totalShares) {
    throw new Error(`[FeldmanVSS] Invalid threshold: 1 <= threshold (${threshold}) <= totalShares (${totalShares}) required`);
  }
  if (totalShares > 255) {
    throw new Error('[FeldmanVSS] Total shares cannot exceed 255');
  }

  const normSecret = modN(secret);
  if (normSecret === 0n) {
    throw new Error('[FeldmanVSS] Secret cannot be zero mod n');
  }

  // Polynomial: a_0 = secret, a_1..a_{threshold-1} = random scalars
  const coefficients: bigint[] = [normSecret];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomScalar());
  }

  // Commitments: C_k = a_k * G
  const commitments: string[] = coefficients.map((coeff) => {
    return scalarMultiplyG(coeff).toHex(true);
  });

  // Shares: s_i = P(i) for i in 1..totalShares
  const shares: VssShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const val = evaluatePolynomial(coefficients, BigInt(i));
    shares.push({ index: i, value: val });
  }

  return {
    dealerId,
    dealerIndex,
    threshold,
    totalShares,
    commitments,
    shares,
    createdAt: Date.now(),
  };
}

/**
 * Verifies that a participant's received share s_i matches commitments C_k.
 * Check: s_i * G == sum_{k=0}^{threshold-1} (i^k * C_k)
 */
export function verifyFeldmanShare(
  share: VssShare,
  commitments: string[]
): boolean {
  try {
    if (share.index < 1 || share.value <= 0n || share.value >= CURVE_ORDER) {
      return false;
    }
    if (!commitments || commitments.length === 0) {
      return false;
    }

    const sharePoint = scalarMultiplyG(share.value);
    const i = BigInt(share.index);

    let expectedPoint: typeof G | null = null;
    let powerOfI = 1n;

    for (const commHex of commitments) {
      const cleanHex = commHex.startsWith('0x') ? commHex.slice(2) : commHex;
      const C_k = secp256k1.ProjectivePoint.fromHex(cleanHex);
      C_k.assertValidity();

      const term = C_k.multiply(powerOfI);
      expectedPoint = expectedPoint ? expectedPoint.add(term) : term;
      powerOfI = modN(powerOfI * i);
    }

    if (!expectedPoint) return false;
    return sharePoint.equals(expectedPoint);
  } catch {
    return false;
  }
}

/**
 * Reconstructs the secret scalar strictly for validation and testing purposes.
 * Uses Lagrange interpolation at x = 0: s = sum_{j in S} (lambda_j(0) * s_j) mod n.
 */
export function reconstructSecret(
  shares: VssShare[],
  threshold: number
): bigint {
  if (shares.length < threshold) {
    throw new Error(`[FeldmanVSS] Insufficient shares for reconstruction: need ${threshold}, got ${shares.length}`);
  }

  const activeSubset = shares.slice(0, threshold);
  const indices = activeSubset.map((s) => s.index);

  // Check unique indices
  const set = new Set(indices);
  if (set.size !== indices.length) {
    throw new Error('[FeldmanVSS] Duplicate participant indices in reconstruction subset');
  }

  let reconstructedSecret = 0n;

  for (let idx = 0; idx < activeSubset.length; idx++) {
    const jIndex = activeSubset[idx].index;
    const s_j = activeSubset[idx].value;

    let numerator = 1n;
    let denominator = 1n;
    const j = BigInt(jIndex);

    for (let mIdx = 0; mIdx < indices.length; mIdx++) {
      if (mIdx === idx) continue;
      const m = BigInt(indices[mIdx]);
      numerator = modN(numerator * modN(-m));
      denominator = modN(denominator * modN(j - m));
    }

    const denominatorInv = modInverse(denominator, CURVE_ORDER);
    const lambda_j = modN(numerator * denominatorInv);
    reconstructedSecret = modN(reconstructedSecret + modN(lambda_j * s_j));
  }

  return reconstructedSecret;
}

/**
 * Resolves a complaint against a dealer.
 * Dealer provides the claimed share for the complainer.
 * If the revealed share is valid against commitments, complainer lodged a false complaint.
 * If the revealed share fails verification, dealer is proven malicious.
 */
export function resolveFeldmanComplaint(
  complaint: VssComplaint,
  commitments: string[],
  dealerShares: VssShare[]
): VssComplaintResolution {
  const targetShare = dealerShares.find((s) => s.index === complaint.complainerIndex);

  if (!targetShare) {
    return {
      dealerIndex: complaint.dealerIndex,
      complainerIndex: complaint.complainerIndex,
      isDealerMalicious: true,
      reason: `Dealer failed to provide share for participant index ${complaint.complainerIndex}`,
    };
  }

  const isValid = verifyFeldmanShare(targetShare, commitments);

  if (!isValid) {
    return {
      dealerIndex: complaint.dealerIndex,
      complainerIndex: complaint.complainerIndex,
      isDealerMalicious: true,
      revealedShare: targetShare,
      reason: 'Dealer provided invalid share that fails commitment verification',
    };
  }

  return {
    dealerIndex: complaint.dealerIndex,
    complainerIndex: complaint.complainerIndex,
    isDealerMalicious: false,
    revealedShare: targetShare,
    reason: 'Dealer provided valid share matching public commitments; complaint dismissed',
  };
}
