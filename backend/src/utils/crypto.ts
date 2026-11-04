/**
 * crypto.ts
 *
 * SARAL Cryptographic Utility Functions
 *
 * Includes:
 *   - Secure buffer wipe / memory zeroization.
 *   - Constant-time string & token comparison (anti-timing attacks).
 *   - AES-256-GCM authenticated encryption with HKDF domain separation.
 *   - Legacy 3-way XOR compatibility functions with strict zeroization.
 */

import crypto from 'crypto';
import { env } from '../config/env';
import {
  encryptShareGcm,
  decryptShareGcm,
  deriveDomainKey,
} from '../crypto/secureEncryption';

export {
  encryptShareGcm,
  decryptShareGcm,
  deriveDomainKey,
};

/**
 * Legacy AES-256-GCM encryption wrapper (for backward compatibility).
 */
export function encryptShare(plainText: string): string {
  const res = encryptShareGcm(plainText, 'LEGACY');
  return res.serialized;
}

/**
 * Legacy AES-256-GCM decryption wrapper (for backward compatibility).
 */
export function decryptShare(encryptedData: string): string {
  return decryptShareGcm(encryptedData, 'LEGACY');
}

/**
 * Overwrites all bytes of a buffer with zeros to purge secrets from RAM.
 */
export function wipeBuffer(buf?: Buffer | Uint8Array | null): void {
  if (buf && (Buffer.isBuffer(buf) || buf instanceof Uint8Array)) {
    buf.fill(0);
  }
}

/**
 * Secure constant-time comparison for OTPs, tokens, and hashes (prevents timing attacks).
 */
export function secureCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
