/**
 * SARAL Protocol V3 — Multi-Factor Authentication (MFA) & TOTP Service
 *
 * Implements:
 * 1. RFC 6238 Time-Based One-Time Password (TOTP) algorithm in pure Node.js crypto.
 * 2. Authenticated AES-256-GCM encryption for TOTP secrets at rest.
 * 3. SHA-256 hashed single-use recovery codes.
 * 4. Timing-safe verification with window drift (+/- 1 step).
 * 5. Abuse prevention with attempt limits and lockout.
 */

import crypto from 'crypto';
import { DataStore } from '../storage/store';

const store = DataStore.getInstance();

// Derive 32-byte encryption key for TOTP secrets at rest
function getTotpEncryptionKey(): Buffer {
  const masterSecret = process.env.MFA_ENCRYPTION_KEY || process.env.SARAL_ADMIN_KEY || 'saral-mfa-protection-key-2026-v3';
  return crypto.scryptSync(masterSecret, 'saral-totp-storage-salt', 32, { N: 16384, r: 8, p: 1 });
}

// Encrypt secret with AES-256-GCM
export function encryptTotpSecret(plaintext: string): string {
  const key = getTotpEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

// Decrypt secret with AES-256-GCM
export function decryptTotpSecret(ciphertext: string): string {
  const parts = ciphertext.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted secret format');
  const [ivHex, authTagHex, encHex] = parts;
  const key = getTotpEncryptionKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const enc = Buffer.from(encHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(enc), decipher.final()]);
  return decrypted.toString('utf8');
}

// Base32 Alphabet RFC 4648
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateBase32Secret(length = 20): string {
  const bytes = crypto.randomBytes(length);
  let bits = '';
  for (let i = 0; i < bytes.length; i++) {
    bits += bytes[i].toString(2).padStart(8, '0');
  }
  let base32 = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substring(i, i + 5);
    if (chunk.length < 5) break;
    const val = parseInt(chunk, 2);
    base32 += BASE32_ALPHABET[val];
  }
  return base32;
}

function base32ToBuffer(base32: string): Buffer {
  const clean = base32.toUpperCase().replace(/=+$/, '').replace(/[\s-]/g, '');
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    const byteStr = bits.substring(i, i + 8);
    if (byteStr.length === 8) {
      bytes.push(parseInt(byteStr, 2));
    }
  }
  return Buffer.from(bytes);
}

/**
 * Computes RFC 6238 TOTP token for given secret and time step counter.
 */
export function computeTotpToken(secretBase32: string, timeStepCounter: number): string {
  const key = base32ToBuffer(secretBase32);
  const counterBuffer = Buffer.alloc(8);
  // Write 64-bit big endian integer
  counterBuffer.writeBigUInt64BE(BigInt(timeStepCounter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

/**
 * Verifies TOTP code allowing +/- 1 window drift (30-second steps).
 */
export function verifyTotpToken(secretBase32: string, token: string, timeStep = 30): boolean {
  const currentStep = Math.floor(Date.now() / 1000 / timeStep);
  const cleanToken = token.trim();
  if (cleanToken.length !== 6) return false;

  for (let drift = -1; drift <= 1; drift++) {
    const expected = computeTotpToken(secretBase32, currentStep + drift);
    if (crypto.timingSafeEqual(Buffer.from(cleanToken), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

/**
 * Generates 8 one-time backup recovery codes formatted as XXXX-XXXX.
 */
export function generateRecoveryCodes(): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  const hashes: string[] = [];

  for (let i = 0; i < 8; i++) {
    const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
    const formatted = `${raw.substring(0, 4)}-${raw.substring(4, 8)}`;
    codes.push(formatted);
    const hash = crypto.createHash('sha256').update(formatted).digest('hex');
    hashes.push(hash);
  }

  return { codes, hashes };
}

// Track in-memory rate limiting for MFA attempts
interface MfaAttemptTracker {
  attempts: number;
  lockoutUntil: number;
}
const mfaAttempts = new Map<string, MfaAttemptTracker>();

function checkMfaRateLimit(userId: string): void {
  const record = mfaAttempts.get(userId);
  const now = Date.now();
  if (record && now < record.lockoutUntil) {
    const secs = Math.ceil((record.lockoutUntil - now) / 1000);
    throw new Error(`Too many failed MFA attempts. Account temporarily locked for ${secs}s.`);
  }
}

function recordFailedMfaAttempt(userId: string): void {
  const now = Date.now();
  const record = mfaAttempts.get(userId) || { attempts: 0, lockoutUntil: 0 };
  record.attempts += 1;
  if (record.attempts >= 5) {
    record.lockoutUntil = now + 15 * 60 * 1000; // 15-minute lockout
    record.attempts = 0;
  }
  mfaAttempts.set(userId, record);
}

function resetMfaAttempts(userId: string): void {
  mfaAttempts.delete(userId);
}

// Enrollment flow: Initiate TOTP setup
export function enrollTotp(userId: string, userEmailOrPhone: string): {
  secret: string;
  qrUri: string;
  recoveryCodes: string[];
} {
  const secret = generateBase32Secret(20);
  const encSecret = encryptTotpSecret(secret);
  const { codes, hashes } = generateRecoveryCodes();

  // Save unverified MFA record
  store.saveMfa({
    userId,
    type: 'totp',
    totpSecretEncrypted: encSecret,
    recoveryCodesHashed: hashes,
    updatedAt: new Date().toISOString(),
  });

  const encodedIssuer = encodeURIComponent('SARAL Protocol');
  const encodedAccount = encodeURIComponent(userEmailOrPhone);
  const qrUri = `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;

  return {
    secret,
    qrUri,
    recoveryCodes: codes,
  };
}

// Verification flow: Verify challenge
export function verifyMfaChallenge(userId: string, codeOrRecovery: string): { verified: boolean; method: string } {
  checkMfaRateLimit(userId);

  const clean = codeOrRecovery.trim().toUpperCase();
  const mfaRecord = store.getMfa(userId);
  if (!mfaRecord) {
    throw new Error('MFA record not found for user');
  }

  // 1. Check recovery code if format is XXXX-XXXX
  if (/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(clean)) {
    const codeHash = crypto.createHash('sha256').update(clean).digest('hex');
    const existingHashes = mfaRecord.recoveryCodesHashed || [];
    const index = existingHashes.indexOf(codeHash);

    if (index !== -1) {
      // Consume recovery code
      existingHashes.splice(index, 1);
      mfaRecord.recoveryCodesHashed = existingHashes;
      mfaRecord.verifiedAt = new Date().toISOString();
      mfaRecord.updatedAt = new Date().toISOString();
      store.saveMfa(mfaRecord);
      resetMfaAttempts(userId);

      store.logSecurity({
        id: crypto.randomUUID(),
        userId,
        eventType: 'MFA_RECOVERY_CODE_CONSUMED',
        severity: 'WARN',
        details: { remainingCodes: existingHashes.length },
        timestamp: new Date().toISOString(),
      });

      return { verified: true, method: 'recovery-code' };
    }
  }

  // 2. Check TOTP 6-digit code
  if (mfaRecord.totpSecretEncrypted) {
    const secret = decryptTotpSecret(mfaRecord.totpSecretEncrypted);
    const isValid = verifyTotpToken(secret, clean);

    if (isValid) {
      mfaRecord.verifiedAt = new Date().toISOString();
      mfaRecord.updatedAt = new Date().toISOString();
      store.saveMfa(mfaRecord);
      resetMfaAttempts(userId);

      store.logSecurity({
        id: crypto.randomUUID(),
        userId,
        eventType: 'MFA_TOTP_VERIFICATION_SUCCESS',
        severity: 'INFO',
        timestamp: new Date().toISOString(),
      });

      return { verified: true, method: 'totp' };
    }
  }

  recordFailedMfaAttempt(userId);
  store.logSecurity({
    id: crypto.randomUUID(),
    userId,
    eventType: 'MFA_VERIFICATION_FAILED',
    severity: 'WARN',
    timestamp: new Date().toISOString(),
  });

  throw new Error('Invalid MFA authentication code');
}
