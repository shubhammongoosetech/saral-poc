import crypto from 'crypto';
import { env } from '../config/env';

/**
 * Derives a clean 32-byte key from MASTER_ENCRYPTION_KEY
 */
function getMasterKey(): Buffer {
  const rawKey = env.MASTER_ENCRYPTION_KEY;
  if (/^[0-9a-fA-F]{64}$/.test(rawKey)) {
    return Buffer.from(rawKey, 'hex');
  }
  // Otherwise derive a consistent 32-byte key using SHA-256
  return crypto.createHash('sha256').update(rawKey).digest();
}

/**
 * AES-256-GCM encryption of a share string
 * Output format: iv:authTag:ciphertext (all in hex)
 */
export function encryptShare(plainText: string): string {
  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);

  const encrypted = Buffer.concat([
    cipher.update(plainText, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * AES-256-GCM decryption of an encrypted share string
 */
export function decryptShare(encryptedData: string): string {
  const masterKey = getMasterKey();
  const parts = encryptedData.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted share format');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const ciphertext = Buffer.from(parts[2], 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Splits a 32-byte private key into 3 categories: PUBLIC, INSTITUTIONAL, SOVEREIGN
 * using a 3-way XOR secret sharing scheme:
 * Part1 (PUBLIC) = random 32 bytes
 * Part2 (INSTITUTIONAL) = random 32 bytes
 * Part3 (SOVEREIGN) = privateKey ^ Part1 ^ Part2
 *
 * Reconstructing: Part1 ^ Part2 ^ Part3 = privateKey
 */
export function splitPrivateKey3Ways(privateKeyHex: string): {
  PUBLIC: string;
  INSTITUTIONAL: string;
  SOVEREIGN: string;
} {
  const cleanHex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
  const keyBytes = Buffer.from(cleanHex.padStart(64, '0'), 'hex');

  const part1 = crypto.randomBytes(32);
  const part2 = crypto.randomBytes(32);
  const part3 = Buffer.alloc(32);

  for (let i = 0; i < 32; i++) {
    part3[i] = keyBytes[i] ^ part1[i] ^ part2[i];
  }

  return {
    PUBLIC: part1.toString('hex'),
    INSTITUTIONAL: part2.toString('hex'),
    SOVEREIGN: part3.toString('hex'),
  };
}

/**
 * Reconstructs the private key by XORing the 3 parts
 */
export function combinePrivateKey3Ways(
  part1Hex: string,
  part2Hex: string,
  part3Hex: string
): string {
  const b1 = Buffer.from(part1Hex, 'hex');
  const b2 = Buffer.from(part2Hex, 'hex');
  const b3 = Buffer.from(part3Hex, 'hex');

  if (b1.length !== 32 || b2.length !== 32 || b3.length !== 32) {
    throw new Error('Invalid part length for 3-way reconstruction');
  }

  const result = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    result[i] = b1[i] ^ b2[i] ^ b3[i];
  }

  return '0x' + result.toString('hex');
}

/**
 * Secure constant-time comparison for OTP or sensitive tokens
 */
export function secureCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Constant time dummy comparison
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}
