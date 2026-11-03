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
 * Overwrites all bytes of a buffer with zeros to purge secrets immediately from RAM.
 */
export function wipeBuffer(buf?: Buffer | Uint8Array | null): void {
  if (buf && (Buffer.isBuffer(buf) || buf instanceof Uint8Array)) {
    buf.fill(0);
  }
}

/**
 * Splits a 32-byte private key into 3 categories: PUBLIC, INSTITUTIONAL, SOVEREIGN
 * using a 3-way XOR secret sharing scheme.
 * Securely zeros out the raw key and intermediate buffers from RAM.
 */
export function splitPrivateKey3Ways(privateKeyHexOrBuf: string | Buffer): {
  PUBLIC: string;
  INSTITUTIONAL: string;
  SOVEREIGN: string;
} {
  let keyBytes: Buffer;
  if (Buffer.isBuffer(privateKeyHexOrBuf)) {
    keyBytes = Buffer.from(privateKeyHexOrBuf);
  } else {
    const cleanHex = privateKeyHexOrBuf.startsWith('0x') ? privateKeyHexOrBuf.slice(2) : privateKeyHexOrBuf;
    keyBytes = Buffer.from(cleanHex.padStart(64, '0'), 'hex');
  }

  const part1 = crypto.randomBytes(32);
  const part2 = crypto.randomBytes(32);
  const part3 = Buffer.alloc(32);

  try {
    for (let i = 0; i < 32; i++) {
      part3[i] = keyBytes[i] ^ part1[i] ^ part2[i];
    }

    return {
      PUBLIC: part1.toString('hex'),
      INSTITUTIONAL: part2.toString('hex'),
      SOVEREIGN: part3.toString('hex'),
    };
  } finally {
    // Explicitly zeroize raw key bytes and intermediate buffers from memory
    keyBytes.fill(0);
    part1.fill(0);
    part2.fill(0);
    part3.fill(0);
  }
}

/**
 * Reconstructs the private key by XORing the 3 parts into a 32-byte zeroizable Buffer.
 * Parts b1, b2, and b3 are immediately zeroized from RAM in the finally block.
 */
export function combinePrivateKey3WaysAsBuffer(
  part1Hex: string,
  part2Hex: string,
  part3Hex: string
): Buffer {
  const b1 = Buffer.from(part1Hex, 'hex');
  const b2 = Buffer.from(part2Hex, 'hex');
  const b3 = Buffer.from(part3Hex, 'hex');

  if (b1.length !== 32 || b2.length !== 32 || b3.length !== 32) {
    b1.fill(0);
    b2.fill(0);
    b3.fill(0);
    throw new Error('Invalid part length for 3-way reconstruction');
  }

  const result = Buffer.alloc(32);
  try {
    for (let i = 0; i < 32; i++) {
      result[i] = b1[i] ^ b2[i] ^ b3[i];
    }
    return result;
  } finally {
    b1.fill(0);
    b2.fill(0);
    b3.fill(0);
  }
}

/**
 * Reconstructs the private key as a string (legacy compatibility).
 */
export function combinePrivateKey3Ways(
  part1Hex: string,
  part2Hex: string,
  part3Hex: string
): string {
  const buf = combinePrivateKey3WaysAsBuffer(part1Hex, part2Hex, part3Hex);
  try {
    return '0x' + buf.toString('hex');
  } finally {
    buf.fill(0);
  }
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
