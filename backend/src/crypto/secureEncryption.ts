/**
 * secureEncryption.ts
 *
 * Production-grade AES-256-GCM authenticated encryption for SARAL key shares.
 *
 * Security guarantees:
 *  - Unique cryptographically random 96-bit (12-byte) IV for every encryption call.
 *  - 128-bit (16-byte) GMAC authentication tag verification (preventing bit-flipping/tampering).
 *  - HKDF (RFC 5869) domain separation: derives independent encryption keys per trust domain.
 *  - Constant-time verification & zeroization of ephemeral plaintext buffers.
 *  - Key versioning metadata format: v1:domain:iv:authTag:ciphertext (hex encoded).
 */

import crypto from 'crypto';
import { env } from '../config/env';

/**
 * Derives a domain-separated 32-byte encryption key using HKDF-SHA256
 */
export function deriveDomainKey(domain: string, salt: string = 'saral-v1-salt'): Buffer {
  const masterKey = env.MASTER_ENCRYPTION_KEY;
  const ikm = /^[0-9a-fA-F]{64}$/.test(masterKey)
    ? Buffer.from(masterKey, 'hex')
    : crypto.createHash('sha256').update(masterKey).digest();

  // HKDF: Extract and Expand
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const info = Buffer.from(`saral-encryption-domain-${domain.toLowerCase()}`, 'utf8');

  // HKDF Expand (1 block of 32 bytes)
  const okm = crypto.createHmac('sha256', prk).update(Buffer.concat([info, Buffer.from([0x01])])).digest();
  return okm;
}

export interface EncryptedSharePayload {
  version: 'v1';
  domain: string;
  iv: string; // 12-byte hex
  authTag: string; // 16-byte hex
  ciphertext: string; // hex
  serialized: string; // 'v1:domain:iv:authTag:ciphertext'
}

/**
 * Encrypts a plaintext share string with AES-256-GCM under the domain-derived key.
 */
export function encryptShareGcm(
  plainText: string,
  domain: string = 'DEFAULT'
): EncryptedSharePayload {
  const domainKey = deriveDomainKey(domain);
  const iv = crypto.randomBytes(12); // NIST SP 800-38D recommended 96-bit IV

  const cipher = crypto.createCipheriv('aes-256-gcm', domainKey, iv);
  cipher.setAAD(Buffer.from(domain, 'utf8')); // Additional Authenticated Data binds ciphertext to domain

  const plainBuf = Buffer.from(plainText, 'utf8');
  let encrypted: Buffer;
  try {
    encrypted = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  } finally {
    // Zero out memory
    plainBuf.fill(0);
  }

  const authTag = cipher.getAuthTag();

  const ivHex = iv.toString('hex');
  const tagHex = authTag.toString('hex');
  const cipherHex = encrypted.toString('hex');
  const serialized = `v1:${domain}:${ivHex}:${tagHex}:${cipherHex}`;

  return {
    version: 'v1',
    domain,
    iv: ivHex,
    authTag: tagHex,
    ciphertext: cipherHex,
    serialized,
  };
}

/**
 * Decrypts an AES-256-GCM encrypted share payload, strictly verifying the auth tag and domain.
 */
export function decryptShareGcm(
  serializedOrPayload: string | EncryptedSharePayload,
  expectedDomain?: string
): string {
  let domain = 'DEFAULT';
  let ivHex = '';
  let authTagHex = '';
  let cipherHex = '';

  if (typeof serializedOrPayload === 'string') {
    const parts = serializedOrPayload.split(':');
    if (parts.length === 5 && parts[0] === 'v1') {
      // v1 format: v1:domain:iv:authTag:ciphertext
      domain = parts[1];
      ivHex = parts[2];
      authTagHex = parts[3];
      cipherHex = parts[4];
    } else if (parts.length === 3) {
      // Legacy compatibility: iv:authTag:ciphertext
      domain = expectedDomain || 'DEFAULT';
      ivHex = parts[0];
      authTagHex = parts[1];
      cipherHex = parts[2];
    } else {
      throw new Error('Invalid encrypted share format: unrecognized structure');
    }
  } else {
    domain = serializedOrPayload.domain;
    ivHex = serializedOrPayload.iv;
    authTagHex = serializedOrPayload.authTag;
    cipherHex = serializedOrPayload.ciphertext;
  }

  if (expectedDomain && domain.toUpperCase() !== expectedDomain.toUpperCase()) {
    throw new Error(`Domain mismatch: ciphertext is bound to ${domain}, expected ${expectedDomain}`);
  }

  const domainKey = deriveDomainKey(domain);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = Buffer.from(cipherHex, 'hex');

  if (iv.length !== 12) {
    throw new Error(`Invalid IV length: expected 12 bytes, got ${iv.length}`);
  }
  if (authTag.length !== 16) {
    throw new Error(`Invalid auth tag length: expected 16 bytes, got ${authTag.length}`);
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', domainKey, iv);
  decipher.setAuthTag(authTag);
  if (parts_has_domain(serializedOrPayload)) {
    decipher.setAAD(Buffer.from(domain, 'utf8'));
  }

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    const plainText = decrypted.toString('utf8');
    decrypted.fill(0);
    return plainText;
  } catch (err: any) {
    throw new Error('AES-GCM decryption failed: authentication tag verification failed (tampered or corrupted data)');
  }
}

function parts_has_domain(payload: string | EncryptedSharePayload): boolean {
  if (typeof payload === 'string') {
    return payload.startsWith('v1:');
  }
  return true;
}

