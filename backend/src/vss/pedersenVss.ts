/**
 * pedersenVss.ts
 *
 * Pedersen Verifiable Secret Sharing (VSS) over secp256k1.
 * Reference: T. Pedersen, "Non-Interactive and Information-Theoretic Secure Verifiable Secret-Sharing", CRYPTO 1991.
 *
 * Provides information-theoretically hiding commitments:
 *   C_k = a_k * G + b_k * H
 * where H is an independent Nothing-Up-My-Sleeve (NUMS) generator with unknown discrete log w.r.t. G.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  randomScalar,
  G,
} from '../crypto/secp256k1Math';
import {
  PedersenShare,
  PedersenVssPackage,
  VssComplaint,
  VssComplaintResolution,
} from './types';
import { evaluatePolynomial } from './feldmanVss';

// Pre-computed Nothing-Up-My-Sleeve (NUMS) generator H
export const PEDERSEN_NUMS_H_HEX = '024a70ea32e409182e39c9173486c8e3e40f0ebb882183b863a4089da3314de4f1';
let cachedH: typeof G | null = null;

export function getPedersenGeneratorH(): typeof G {
  if (!cachedH) {
    cachedH = secp256k1.ProjectivePoint.fromHex(PEDERSEN_NUMS_H_HEX);
    cachedH.assertValidity();
  }
  return cachedH;
}

/**
 * Computes Pedersen commitment: C = a * G + b * H
 */
export function computePedersenCommitment(a: bigint, b: bigint): typeof G {
  const normA = modN(a);
  const normB = modN(b);
  const H = getPedersenGeneratorH();

  const termA = normA === 0n ? secp256k1.ProjectivePoint.ZERO : G.multiply(normA);
  const termB = normB === 0n ? secp256k1.ProjectivePoint.ZERO : H.multiply(normB);

  return termA.add(termB);
}

/**
 * Generates Pedersen VSS package for a dealer.
 * - Secret polynomial P(x) of degree threshold - 1, P(0) = secret.
 * - Blinding polynomial Q(x) of degree threshold - 1, Q(0) = blindingSecret.
 * - Commitments C_k = a_k * G + b_k * H for k in 0..threshold - 1.
 * - Shares: (s_i, t_i) = (P(i), Q(i)) for i in 1..totalShares.
 */
export function generatePedersenVss(
  secret: bigint,
  totalShares: number,
  threshold: number,
  dealerId: string = 'dealer-1',
  dealerIndex: number = 1,
  customBlindingSecret?: bigint
): PedersenVssPackage {
  if (threshold < 1 || threshold > totalShares) {
    throw new Error(`[PedersenVSS] Invalid threshold: 1 <= threshold (${threshold}) <= totalShares (${totalShares})`);
  }
  if (totalShares > 255) {
    throw new Error('[PedersenVSS] Total shares cannot exceed 255');
  }

  const normSecret = modN(secret);
  if (normSecret === 0n) {
    throw new Error('[PedersenVSS] Secret cannot be zero mod n');
  }

  const blindingSecret = customBlindingSecret !== undefined ? modN(customBlindingSecret) : randomScalar();

  const aCoeffs: bigint[] = [normSecret];
  const bCoeffs: bigint[] = [blindingSecret];

  for (let i = 1; i < threshold; i++) {
    aCoeffs.push(randomScalar());
    bCoeffs.push(randomScalar());
  }

  const commitments: string[] = [];
  for (let k = 0; k < threshold; k++) {
    const commPoint = computePedersenCommitment(aCoeffs[k], bCoeffs[k]);
    commitments.push(commPoint.toHex(true));
  }

  const shares: PedersenShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = BigInt(i);
    const value = evaluatePolynomial(aCoeffs, x);
    const blindingValue = evaluatePolynomial(bCoeffs, x);
    shares.push({
      index: i,
      value,
      blindingValue,
    });
  }

  return {
    dealerId,
    dealerIndex,
    threshold,
    totalShares,
    commitments,
    shares,
    generatorH: PEDERSEN_NUMS_H_HEX,
    createdAt: Date.now(),
  };
}

/**
 * Verifies that a received Pedersen share (s_i, t_i) matches commitments C_k.
 * Check: s_i * G + t_i * H == sum_{k=0}^{threshold-1} (i^k * C_k)
 */
export function verifyPedersenShare(
  share: PedersenShare,
  commitments: string[]
): boolean {
  try {
    if (share.index < 1 || share.value <= 0n || share.value >= CURVE_ORDER) {
      return false;
    }
    if (share.blindingValue <= 0n || share.blindingValue >= CURVE_ORDER) {
      return false;
    }
    if (!commitments || commitments.length === 0) {
      return false;
    }

    // LHS: s_i * G + t_i * H
    const lhs = computePedersenCommitment(share.value, share.blindingValue);

    // RHS: sum_{k=0}^{threshold-1} i^k * C_k
    const i = BigInt(share.index);
    let rhs: typeof G | null = null;
    let powerOfI = 1n;

    for (const commHex of commitments) {
      const cleanHex = commHex.startsWith('0x') ? commHex.slice(2) : commHex;
      const C_k = secp256k1.ProjectivePoint.fromHex(cleanHex);
      C_k.assertValidity();

      const term = C_k.multiply(powerOfI);
      rhs = rhs ? rhs.add(term) : term;
      powerOfI = modN(powerOfI * i);
    }

    if (!rhs) return false;
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

/**
 * Resolves a complaint against a dealer under Pedersen VSS.
 */
export function resolvePedersenComplaint(
  complaint: VssComplaint,
  commitments: string[],
  dealerShares: PedersenShare[]
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

  const isValid = verifyPedersenShare(targetShare, commitments);

  if (!isValid) {
    return {
      dealerIndex: complaint.dealerIndex,
      complainerIndex: complaint.complainerIndex,
      isDealerMalicious: true,
      revealedShare: targetShare,
      reason: 'Dealer provided invalid share failing Pedersen commitment verification',
    };
  }

  return {
    dealerIndex: complaint.dealerIndex,
    complainerIndex: complaint.complainerIndex,
    isDealerMalicious: false,
    revealedShare: targetShare,
    reason: 'Dealer provided valid share matching Pedersen commitments; complaint dismissed',
  };
}
