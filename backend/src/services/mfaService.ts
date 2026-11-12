/**
 * mfaService.ts
 *
 * SARAL Multi-Factor Authentication (MFA) & Custody Service
 *
 * Security Enhancements:
 *  - Cryptographically secure CSPRNG (crypto.randomInt) instead of Math.random().
 *  - HMAC-SHA256 OTP storage: OTPs are NEVER stored in plaintext in PostgreSQL.
 *  - Authenticated AES-256-GCM encryption for TOTP (RFC 6238) authenticator secrets.
 *  - Tamper-evident security audit logging via hash-chained audit service.
 */

import crypto from 'crypto';
import { prisma } from '../config/db';
import { env } from '../config/env';
import { signToken } from '../utils/jwt';
import { secureCompare } from '../utils/crypto';
import { encryptShareGcm, decryptShareGcm } from '../crypto/secureEncryption';
import { logSecurityEvent } from './auditLogService';

export interface MfaVerificationResult {
  success: boolean;
  token: string;
  hasPolicy: boolean;
  hasWallet: boolean;
}

/**
 * Derives an HMAC-SHA256 commitment of an OTP code.
 * Raw OTPs are never stored in the database.
 */
export function hashOtpCode(code: string, purpose: string): string {
  const otpKey = crypto.createHmac('sha256', env.JWT_SECRET).update('saral-otp-key').digest();
  return crypto
    .createHmac('sha256', otpKey)
    .update(`saral-otp:${purpose}:${code}`)
    .digest('hex');
}

/**
 * Dispatches an ephemeral MFA OTP challenge using cryptographically secure PRNG.
 */
export async function sendMfaOtp(
  userId: string
): Promise<{ success: boolean; message: string; devOtp?: string }> {
  // Use cryptographically secure random integers [100000, 999999]
  const code = crypto.randomInt(100000, 1000000).toString();
  const codeHash = hashOtpCode(code, 'mfa');

  await prisma.$transaction([
    // Invalidate old active MFA OTPs
    prisma.otp.updateMany({
      where: { userId, purpose: 'mfa', used: false },
      data: { used: true },
    }),
    // Store ONLY the HMAC hash of the OTP in the database
    prisma.otp.create({
      data: {
        userId,
        code: codeHash,
        purpose: 'mfa',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        used: false,
      },
    }),
  ]);

  if (process.env.NODE_ENV === 'development') {
    console.log(`[MFA OTP CHALLENGE] User: ${userId} | Dispatched Code: ${code}`);
  }

  await logSecurityEvent({
    userId,
    eventType: 'MFA_CHALLENGE_DISPATCHED',
    severity: 'INFO',
    details: { purpose: 'mfa', expiresMinutes: 10 },
  }).catch(() => null);

  return {
    success: true,
    message: 'MFA verification code dispatched.',
    devOtp: env.NODE_ENV === 'development' ? code : undefined,
  };
}

/**
 * Verifies an MFA OTP challenge using timing-safe comparison over HMAC digests.
 */
export async function verifyMfaOtp(
  userId: string,
  otpCode: string
): Promise<MfaVerificationResult> {
  const cleanCode = otpCode.trim();
  const expectedHash = hashOtpCode(cleanCode, 'mfa');

  const otpRecord = await prisma.otp.findFirst({
    where: {
      userId,
      purpose: 'mfa',
      used: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    select: { id: true, code: true },
  });

  if (!otpRecord) {
    await logSecurityEvent({
      userId,
      eventType: 'MFA_VERIFICATION_FAILED',
      severity: 'WARN',
      details: { reason: 'No active OTP record or expired' },
    }).catch(() => null);
    throw new Error('Invalid or expired MFA code. Please request a new code.');
  }

  // Compare against HMAC hash, with legacy fallback for unhashed records
  const isMatch =
    secureCompare(otpRecord.code, expectedHash) ||
    secureCompare(otpRecord.code, cleanCode);

  if (!isMatch) {
    await logSecurityEvent({
      userId,
      eventType: 'MFA_INCORRECT_CODE',
      severity: 'WARN',
      details: { reason: 'Incorrect code entered' },
    }).catch(() => null);
    throw new Error('Incorrect MFA code entered.');
  }

  // Mark OTP used + update MFA record — in one transaction
  await prisma.$transaction([
    prisma.otp.update({
      where: { id: otpRecord.id },
      data: { used: true },
    }),
    prisma.mfa.upsert({
      where: { userId },
      update: { verifiedAt: new Date() },
      create: { userId, type: 'otp', verifiedAt: new Date() },
    }),
  ]);

  await logSecurityEvent({
    userId,
    eventType: 'MFA_VERIFICATION_SUCCESS',
    severity: 'INFO',
    details: { type: 'otp' },
  }).catch(() => null);

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { loginMethod: true },
  });
  const loginMethod = (user?.loginMethod ?? 'google') as 'google' | 'mobile';

  const [policy, shareCount, walletCount] = await Promise.all([
    prisma.workPolicy.findUnique({ where: { userId }, select: { id: true } }).catch(() => null),
    prisma.keyShare.count({ where: { userId } }).catch(() => 0),
    prisma.walletPlacement.count({ where: { userId } }).catch(() => 0),
  ]);

  const token = signToken({ userId, loginMethod, mfaVerified: true });

  return {
    success: true,
    token,
    hasPolicy: !!policy,
    hasWallet: shareCount > 0 || walletCount > 0,
  };
}

/**
 * Base32 Alphabet for RFC 6238 TOTP
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(str: string): Buffer {
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  const cleanStr = str.toUpperCase().replace(/=+$/, '');
  for (let i = 0; i < cleanStr.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleanStr[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Computes RFC 6238 TOTP code at specified counter
 */
export function computeTotpCode(secretBytes: Buffer, timeStepSeconds: number = 30, offset: number = 0): string {
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds) + offset;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', secretBytes).update(buf).digest();
  const offsetByte = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offsetByte] & 0x7f) << 24) |
    ((hmac[offsetByte + 1] & 0xff) << 16) |
    ((hmac[offsetByte + 2] & 0xff) << 8) |
    (hmac[offsetByte + 3] & 0xff);

  const otp = binary % 1_000_000;
  return otp.toString().padStart(6, '0');
}

/**
 * Generates an encrypted TOTP enrollment secret for authenticator apps.
 */
export async function generateTotpEnrollment(userId: string): Promise<{
  secretBase32: string;
  otpAuthUrl: string;
}> {
  const secretBytes = crypto.randomBytes(20);
  const secretBase32 = base32Encode(secretBytes);

  // Authenticated encryption under domain key 'MFA-TOTP'
  const encrypted = encryptShareGcm(secretBase32, 'MFA-TOTP');

  await prisma.mfa.upsert({
    where: { userId },
    update: { secret: encrypted.serialized, type: 'totp' },
    create: { userId, secret: encrypted.serialized, type: 'totp' },
  });

  const otpAuthUrl = `otpauth://totp/SARAL%20Wallet:${userId.slice(0, 8)}?secret=${secretBase32}&issuer=SARAL`;

  return { secretBase32, otpAuthUrl };
}

/**
 * Verifies a TOTP authenticator app code with +/- 1 time-step window.
 */
export async function verifyTotpToken(
  userId: string,
  token: string
): Promise<MfaVerificationResult> {
  const mfa = await prisma.mfa.findUnique({ where: { userId } });
  if (!mfa || !mfa.secret) {
    throw new Error('TOTP authenticator has not been enrolled for this account');
  }

  const decryptedBase32 = decryptShareGcm(mfa.secret, 'MFA-TOTP');
  const secretBytes = base32Decode(decryptedBase32);

  // Allow time-drift of +/- 1 window (90 seconds total tolerance)
  const cleanToken = token.trim();
  let isValid = false;

  for (const offset of [-1, 0, 1]) {
    const expected = computeTotpCode(secretBytes, 30, offset);
    if (secureCompare(expected, cleanToken)) {
      isValid = true;
      break;
    }
  }

  if (!isValid) {
    await logSecurityEvent({
      userId,
      eventType: 'TOTP_VERIFICATION_FAILED',
      severity: 'WARN',
      details: { reason: 'Invalid authenticator code' },
    }).catch(() => null);
    throw new Error('Invalid TOTP authenticator code');
  }

  await prisma.mfa.update({
    where: { userId },
    data: { verifiedAt: new Date() },
  });

  await logSecurityEvent({
    userId,
    eventType: 'TOTP_VERIFICATION_SUCCESS',
    severity: 'INFO',
    details: { type: 'totp' },
  }).catch(() => null);

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { loginMethod: true },
  });
  const loginMethod = (user?.loginMethod ?? 'google') as 'google' | 'mobile';

  const [policy, shareCount, walletCount] = await Promise.all([
    prisma.workPolicy.findUnique({ where: { userId }, select: { id: true } }).catch(() => null),
    prisma.keyShare.count({ where: { userId } }).catch(() => 0),
    prisma.walletPlacement.count({ where: { userId } }).catch(() => 0),
  ]);

  const authToken = signToken({ userId, loginMethod, mfaVerified: true });

  return {
    success: true,
    token: authToken,
    hasPolicy: !!policy,
    hasWallet: shareCount > 0 || walletCount > 0,
  };
}
