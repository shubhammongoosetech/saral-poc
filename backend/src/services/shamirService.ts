// @ts-ignore
import secrets from 'secrets.js-grempe';

export interface ShamirConfig {
  n: number;
  threshold: number;
}

/**
 * Validates Shamir parameters: 2 <= threshold <= n <= 255
 */
export function validateShamirParams(n: number, threshold: number): void {
  if (!Number.isInteger(n) || !Number.isInteger(threshold)) {
    throw new Error('Share total (n) and threshold must be integers');
  }
  if (n < 2 || n > 255) {
    throw new Error(`Total shares (n) must be between 2 and 255. Received: ${n}`);
  }
  if (threshold < 2 || threshold > n) {
    throw new Error(
      `Threshold must be between 2 and ${n}. Received: ${threshold}`
    );
  }
}

/**
 * Splits a hexadecimal secret into n shares with a minimum reconstruction threshold
 */
export function splitSecret(
  secretHex: string,
  n: number,
  threshold: number
): string[] {
  validateShamirParams(n, threshold);
  const cleanHex = secretHex.startsWith('0x') ? secretHex.slice(2) : secretHex;
  const shares: string[] = secrets.share(cleanHex, n, threshold);
  return shares;
}

/**
 * Reconstructs the hexadecimal secret from a threshold subset of shares
 */
export function reconstructSecret(shares: string[]): string {
  if (!shares || shares.length === 0) {
    throw new Error('At least one share must be provided for reconstruction');
  }
  const secretHex: string = secrets.combine(shares);
  return secretHex;
}
