/**
 * bivariatePolynomial.ts
 *
 * Symmetric bivariate polynomials and polynomial algebra over secp256k1 scalar field F_n.
 *
 * Reference:
 *   "Distributed Key Generation in the Wild" (Kate, Huang, Goldberg), Section 3.1 & Figure 1.
 *   - Phi(x, y) = sum_{j,l=0}^t phi_jl * x^j * y^l  where phi_jl = phi_lj mod n
 *   - Constant term phi_00 = s (secret)
 *   - Row polynomial a_j(y) = Phi(j, y)
 *   - Exact Lagrange polynomial interpolation in F_n
 */

import {
  CURVE_ORDER,
  modN,
  modInverse,
  randomScalar,
} from '../secp256k1Math';
import type { Rng } from './types';

export interface SymmetricBivariatePoly {
  degree: number;       // degree t
  coeffs: bigint[][];   // (t+1) x (t+1) symmetric matrix over F_n
}

/**
 * Samples a random symmetric bivariate polynomial of degree t.
 * Coeffs satisfy phi_jl = phi_lj mod n.
 * Constant term phi_00 = secret mod n (or random scalar if secret is omitted).
 */
export function sampleSymmetricBivariatePoly(
  degree: number,
  secret?: bigint,
  rng?: Rng
): SymmetricBivariatePoly {
  if (degree < 0) {
    throw new Error(`[BivariatePoly] Degree must be non-negative, got ${degree}`);
  }
  const size = degree + 1;
  const coeffs: bigint[][] = Array.from({ length: size }, () => new Array(size).fill(0n));

  const sampleScalar = (): bigint => {
    if (rng) {
      return modN(rng.randomScalar());
    }
    return randomScalar();
  };

  // Set constant term phi_00 = secret mod n
  coeffs[0][0] = secret !== undefined ? modN(secret) : sampleScalar();

  // Populate symmetric coefficients: phi_jl = phi_lj
  for (let j = 0; j < size; j++) {
    for (let l = j; l < size; l++) {
      if (j === 0 && l === 0) continue;
      const r = sampleScalar();
      coeffs[j][l] = r;
      coeffs[l][j] = r;
    }
  }

  return { degree, coeffs };
}

/**
 * Evaluates bivariate polynomial Phi(x, y) mod n.
 */
export function evaluateBivariate(
  poly: SymmetricBivariatePoly,
  x: bigint,
  y: bigint
): bigint {
  const normX = modN(x);
  const normY = modN(y);
  const size = poly.degree + 1;
  let total = 0n;

  for (let j = 0; j < size; j++) {
    let xPow = 1n;
    for (let p = 0; p < j; p++) {
      xPow = modN(xPow * normX);
    }
    for (let l = 0; l < size; l++) {
      let yPow = 1n;
      for (let q = 0; q < l; q++) {
        yPow = modN(yPow * normY);
      }
      const term = modN(poly.coeffs[j][l] * modN(xPow * yPow));
      total = modN(total + term);
    }
  }

  return total;
}

/**
 * Derives the univariate row polynomial for peer jIndex:
 *   a_j(y) = Phi(j, y) = sum_{l=0}^t a_l * y^l
 * where:
 *   a_l = sum_{k=0}^t phi_kl * j^k mod n
 *
 * Paper Figure 1: dealer sends a_j(y) = Phi(j, y) to party P_j.
 */
export function deriveRowPolynomial(
  poly: SymmetricBivariatePoly,
  jIndex: number
): bigint[] {
  const size = poly.degree + 1;
  const j = BigInt(jIndex);
  const rowCoeffs = new Array<bigint>(size).fill(0n);

  for (let l = 0; l < size; l++) {
    let coeffL = 0n;
    let jPow = 1n;
    for (let k = 0; k < size; k++) {
      coeffL = modN(coeffL + poly.coeffs[k][l] * jPow);
      jPow = modN(jPow * j);
    }
    rowCoeffs[l] = coeffL;
  }

  return rowCoeffs;
}

/**
 * Evaluates a univariate polynomial P(y) = sum_{l=0}^t c_l * y^l mod n.
 */
export function evaluateUnivariate(coeffs: bigint[], y: bigint): bigint {
  let result = 0n;
  let yPow = 1n;
  const normY = modN(y);

  for (let l = 0; l < coeffs.length; l++) {
    result = modN(result + coeffs[l] * yPow);
    yPow = modN(yPow * normY);
  }

  return result;
}

/**
 * Exact Lagrange polynomial interpolation in F_n.
 * Given k distinct points (x_m, y_m), reconstructs the degree-(k-1) polynomial
 * coefficients [c_0, c_1, ..., c_{k-1}] such that P(x_m) = y_m mod n.
 */
export function interpolatePolynomial(points: { x: bigint; y: bigint }[]): bigint[] {
  const k = points.length;
  if (k === 0) {
    throw new Error('[BivariatePoly] Cannot interpolate with 0 points');
  }
  if (k === 1) {
    return [modN(points[0].y)];
  }

  const resultCoeffs = new Array<bigint>(k).fill(0n);

  for (let i = 0; i < k; i++) {
    const xi = modN(points[i].x);
    const yi = modN(points[i].y);

    // Denominator D_i = prod_{j != i} (xi - xj) mod n
    let denominator = 1n;
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      const xj = modN(points[j].x);
      const diff = modN(xi - xj);
      if (diff === 0n) {
        throw new Error(`[BivariatePoly] Duplicate interpolation x-coordinate: ${xi}`);
      }
      denominator = modN(denominator * diff);
    }

    const denInv = modInverse(denominator, CURVE_ORDER);
    const weight = modN(yi * denInv);

    // Compute polynomial numerator N_i(X) = prod_{j != i} (X - xj)
    let poly = [1n];
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      const xj = modN(points[j].x);
      const newPoly = new Array<bigint>(poly.length + 1).fill(0n);
      const negXj = modN(-xj);

      for (let p = 0; p < poly.length; p++) {
        // -xj * poly[p] -> degree p
        newPoly[p] = modN(newPoly[p] + modN(poly[p] * negXj));
        // X * poly[p] -> degree p + 1
        newPoly[p + 1] = modN(newPoly[p + 1] + poly[p]);
      }
      poly = newPoly;
    }

    // Accumulate weight * poly(X) into resultCoeffs
    for (let p = 0; p < k; p++) {
      resultCoeffs[p] = modN(resultCoeffs[p] + modN(weight * poly[p]));
    }
  }

  return resultCoeffs;
}

/**
 * Lagrange interpolation directly evaluated at 0:
 *   P(0) = sum_{i=0}^{k-1} y_i * prod_{j != i} (0 - x_j) / (x_i - x_j) mod n
 */
export function interpolateAtZero(points: { x: bigint; y: bigint }[]): bigint {
  const k = points.length;
  if (k === 0) {
    throw new Error('[BivariatePoly] Cannot interpolate with 0 points');
  }
  if (k === 1) {
    return modN(points[0].y);
  }

  let secret = 0n;
  for (let i = 0; i < k; i++) {
    const xi = modN(points[i].x);
    const yi = modN(points[i].y);
    let num = 1n;
    let den = 1n;

    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      const xj = modN(points[j].x);
      num = modN(num * modN(-xj));
      den = modN(den * modN(xi - xj));
    }

    const denInv = modInverse(den, CURVE_ORDER);
    const lambda_i = modN(num * denInv);
    secret = modN(secret + modN(yi * lambda_i));
  }

  return secret;
}

/**
 * Zeroizes secret coefficient arrays in place to prevent memory leakage.
 */
export function zeroizeBigIntArray(arr: bigint[]): void {
  arr.fill(0n);
}

/**
 * Zeroizes secret bivariate polynomial matrix in place.
 */
export function zeroizeBigIntMatrix(matrix: bigint[][]): void {
  for (const row of matrix) {
    row.fill(0n);
  }
}

