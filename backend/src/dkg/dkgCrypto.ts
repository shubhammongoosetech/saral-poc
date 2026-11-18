/**
 * dkgCrypto.ts
 *
 * Cryptographic helpers for dealerless DKG:
 *  - Peer-to-peer ECDH key agreement over secp256k1
 *  - Domain-separated HKDF-SHA256 key derivation
 *  - AES-256-GCM authenticated encryption for private share distribution
 *  - Digital signatures for protocol message integrity
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { modN } from '../crypto/secp256k1Math';

/**
 * Derives a shared symmetric key between party A (private key) and party B (public key)
 * using secp256k1 Diffie-Hellman and domain-separated HKDF-SHA256.
 */
export function deriveEcdhKey(
  privateKeyHex: string,
  peerPublicKeyHex: string,
  sessionId: string
): Buffer {
  const cleanPriv = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
  const cleanPub = peerPublicKeyHex.startsWith('0x') ? peerPublicKeyHex.slice(2) : peerPublicKeyHex;

  const privScalar = BigInt('0x' + cleanPriv);
  const peerPoint = secp256k1.ProjectivePoint.fromHex(cleanPub);
  peerPoint.assertValidity();

  // Shared point S = privScalar * peerPoint
  const sharedPoint = peerPoint.multiply(modN(privScalar));
  const sharedBytes = Buffer.from(sharedPoint.toHex(true), 'hex');

  // HKDF-SHA256
  const salt = crypto.createHash('sha256').update(`saral-dkg-salt:${sessionId}`).digest();
  const info = Buffer.from('saral-dealerless-dkg-v1', 'utf8');

  const derived = crypto.hkdfSync('sha256', sharedBytes, salt, info, 32);
  return Buffer.from(derived);
}

/**
 * Encrypts a plaintext payload using AES-256-GCM with a shared key.
 */
export function encryptPayloadGcm(
  payload: string,
  key: Buffer
): { ciphertextHex: string; ivHex: string; authTagHex: string } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(payload, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    ciphertextHex: encrypted,
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
  };
}

/**
 * Decrypts an AES-256-GCM ciphertext using a shared key.
 */
export function decryptPayloadGcm(
  ciphertextHex: string,
  ivHex: string,
  authTagHex: string,
  key: Buffer
): string {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Signs a DKG payload using a secp256k1 private key.
 */
export function signDkgPayload(payload: string, privateKeyHex: string): string {
  const cleanPriv = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
  const hash = crypto.createHash('sha256').update(payload).digest();
  const sig = secp256k1.sign(hash, cleanPriv);
  return sig.toCompactHex();
}

/**
 * Verifies a DKG signature against a secp256k1 public key.
 */
export function verifyDkgSignature(
  payload: string,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const cleanPub = publicKeyHex.startsWith('0x') ? publicKeyHex.slice(2) : publicKeyHex;
    const hash = crypto.createHash('sha256').update(payload).digest();
    return secp256k1.verify(signatureHex, hash, cleanPub);
  } catch {
    return false;
  }
}
