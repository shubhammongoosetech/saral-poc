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
import { decryptTotpSecret, encryptTotpSecret } from '../utils/crypto';

export { decryptTotpSecret, encryptTotpSecret };

const store = DataStore.getInstance();

export class MfaChallengeError extends Error {
  constructor(message: string, readonly rateLimited = false) {
    super(message);
  }
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
  return matchTotpStep(secretBase32, token, timeStep) !== undefined;
}

function matchTotpStep(secretBase32: string, token: string, timeStep = 30): number | undefined {
  const currentStep = Math.floor(Date.now() / 1000 / timeStep);
  const cleanToken = token.trim();
  if (!/^\d{6}$/.test(cleanToken)) return undefined;

  for (const drift of [0, -1, 1]) {
    const expected = computeTotpToken(secretBase32, currentStep + drift);
    if (crypto.timingSafeEqual(Buffer.from(cleanToken), Buffer.from(expected))) {
      return currentStep + drift;
    }
  }
}

/**
 * Generates 8 one-time backup recovery codes with 80 bits of entropy per code.
 */
export function generateRecoveryCodes(): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  const hashes: string[] = [];

  for (let i = 0; i < 8; i++) {
    const raw = crypto.randomBytes(10).toString('hex').toUpperCase();
    const formatted = raw.match(/.{4}/g)!.join('-');
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
    throw new MfaChallengeError(`Too many failed MFA attempts. Account temporarily locked for ${secs}s.`, true);
  }
}

function recordMfaAttempt(userId: string): void {
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
export async function enrollTotp(userId: string, userEmailOrPhone: string): Promise<{
  secret: string;
  qrUri: string;
  recoveryCodes: string[];
}> {
  if ((await store.findPersistedMfa(userId))?.verifiedAt) throw new Error('MFA is already enrolled');
  const secret = generateBase32Secret(20);
  const encSecret = encryptTotpSecret(secret);
  const { codes, hashes } = generateRecoveryCodes();

  // Save unverified MFA record
  await store.saveMfa({
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
export async function verifyMfaChallenge(userId: string, codeOrRecovery: string): Promise<{ verified: boolean; method: 'totp' | 'recovery-code' }> {
  checkMfaRateLimit(userId);
  recordMfaAttempt(userId);

  const clean = codeOrRecovery.trim().toUpperCase();
  const mfaRecord = await store.findPersistedMfa(userId);
  if (!mfaRecord) {
    throw new MfaChallengeError('MFA enrollment is required');
  }

  const lastVerifiedAt = mfaRecord.verifiedAt ? Date.parse(mfaRecord.verifiedAt) : 0;
  if (mfaRecord.verifiedAt && /^[A-F0-9]{4}(?:-[A-F0-9]{4}){1,4}$/.test(clean)) {
    const codeHash = crypto.createHash('sha256').update(clean).digest('hex');
    const existingHashes = mfaRecord.recoveryCodesHashed ?? [];
    const remainingHashes = existingHashes.filter((hash) => hash !== codeHash);
    if (remainingHashes.length < existingHashes.length) {
      const verifiedAt = new Date(Math.max(Date.now(), lastVerifiedAt));
      if (!await store.saveVerifiedMfa(mfaRecord, verifiedAt, remainingHashes, codeHash)) {
        throw new MfaChallengeError('Invalid or already used recovery code');
      }
      resetMfaAttempts(userId);

      store.logSecurity({
        id: crypto.randomUUID(),
        userId,
        eventType: 'MFA_RECOVERY_CODE_CONSUMED',
        severity: 'WARN',
        details: { remainingCodes: remainingHashes.length },
        timestamp: new Date().toISOString(),
      });

      return { verified: true, method: 'recovery-code' };
    }
  }

  // 2. Check TOTP 6-digit code
  if (mfaRecord.totpSecretEncrypted) {
    const secret = decryptTotpSecret(mfaRecord.totpSecretEncrypted);
    const step = matchTotpStep(secret, clean);

    if (step !== undefined) {
      if (step <= Math.floor(lastVerifiedAt / 30_000)) {
        throw new MfaChallengeError('This authenticator code was already used. Wait for the next code.');
      }
      const verifiedAt = new Date(step * 30_000);
      if (!await store.saveVerifiedMfa(mfaRecord, verifiedAt, mfaRecord.recoveryCodesHashed ?? [])) {
        throw new MfaChallengeError('MFA state changed. Try again with a fresh code.');
      }
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

  store.logSecurity({
    id: crypto.randomUUID(),
    userId,
    eventType: 'MFA_VERIFICATION_FAILED',
    severity: 'WARN',
    timestamp: new Date().toISOString(),
  });

  throw new MfaChallengeError('Invalid MFA authentication code');
}
