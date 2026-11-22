/**
 * SARAL Protocol V3 — Account Authentication & Identity Linking Service
 *
 * Implements:
 * 1. Google OAuth2 / OpenID Connect authentication.
 * 2. E.164 mobile phone normalization with HMAC-SHA256 OTP challenges.
 * 3. Timing-safe OTP verification and rate-limiting.
 * 4. Explicit authenticated account linking (Google + Mobile -> One User ID).
 * 5. Strict prevention of silent wallet bifurcation or collision.
 */

import crypto from 'crypto';
import { DataStore, UserRecord } from '../storage/store';
import { createAccountSession } from '../auth/accountSession';
import { verifyGoogleIdentity } from '../auth/google';
import { canDisplayDevOtp } from '../config/auth';

const store = DataStore.getInstance();

const PEPPER = process.env.OTP_PEPPER || 'saral-otp-cryptographic-pepper-2026';

export class PhoneAuthError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

export function hashOtp(code: string, userId: string, purpose: string): string {
  return crypto
    .createHmac('sha256', PEPPER)
    .update(`${userId}:${purpose}:${code.trim()}`)
    .digest('hex');
}

/**
 * Normalizes phone numbers to standard E.164 format.
 * Defaults to India (+91) if 10 digits provided.
 */
export function normalizeE164(raw: string): string {
  const phone = raw.trim().replace(/[\s()-]/g, '');
  if (/^\+[1-9]\d{7,14}$/.test(phone)) return phone;
  if (/^\d{10}$/.test(phone)) return `+91${phone}`;
  if (/^91\d{10}$/.test(phone)) return `+${phone}`;
  throw new PhoneAuthError('Valid mobile number required', 400);
}

// Track resend cooldowns in-memory
const cooldowns = new Map<string, number>();
let cooldownCleanupAt = 0;

export function checkOtpCooldown(mobile: string): void {
  const now = Date.now();
  if (now >= cooldownCleanupAt) {
    for (const [number, sentAt] of cooldowns) {
      if (now - sentAt >= 30_000) cooldowns.delete(number);
    }
    cooldownCleanupAt = now + 30_000;
  }
  const lastSent = cooldowns.get(mobile);
  if (lastSent && now - lastSent < 30 * 1000) {
    const remaining = Math.ceil((30 * 1000 - (now - lastSent)) / 1000);
    throw new PhoneAuthError(`Please wait ${remaining} seconds before requesting a new OTP.`, 429);
  }
  cooldowns.delete(mobile);
}

/**
 * Requests a mobile login OTP.
 */
export async function requestPhoneOtp(mobileRaw: string): Promise<{
  success: boolean;
  mobile: string;
  cooldownSeconds: number;
  devOtp?: string;
}> {
  if (!canDisplayDevOtp()) throw new PhoneAuthError('SMS code delivery is unavailable', 503);
  const mobile = normalizeE164(mobileRaw);
  checkOtpCooldown(mobile);
  cooldowns.set(mobile, Date.now());

  // 1. Resolve or create user identity
  let user = await store.findPersistedUser({ mobile });
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      mobile,
      loginMethod: 'mobile',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await store.saveUser(user);
  }

  // 2. Generate cryptographically secure 6-digit OTP
  const otpCode = crypto.randomInt(100000, 1000000).toString();
  const codeHash = hashOtp(otpCode, user.id, 'login');

  // Invalidate any old OTPs for this purpose
  const existingOtp = store.getActiveOtp(user.id, 'login');
  if (existingOtp) {
    await store.markOtpUsed(existingOtp.id);
  }

  // Save new OTP challenge
  const otpId = crypto.randomUUID();
  await store.saveOtp({
    id: otpId,
    userId: user.id,
    mobile,
    codeHash,
    purpose: 'login',
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    used: false,
    attempts: 0,
    createdAt: Date.now(),
  });

  store.logSecurity({
    id: crypto.randomUUID(),
    userId: user.id,
    eventType: 'OTP_REQUESTED',
    severity: 'INFO',
    details: { mobile: mobile.slice(0, 4) + '****' + mobile.slice(-2) },
    timestamp: new Date().toISOString(),
  });

  return {
    success: true,
    mobile,
    cooldownSeconds: 30,
    devOtp: otpCode,
  };
}

/**
 * Verifies mobile phone OTP.
 */
export async function verifyPhoneOtp(
  mobileRaw: string,
  code: string
): Promise<{
  user: UserRecord;
  token: string;
  mfaEnrolled: boolean;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
}> {
  if (!canDisplayDevOtp()) throw new PhoneAuthError('SMS code delivery is unavailable', 503);
  const mobile = normalizeE164(mobileRaw);
  const user = store.findUserByMobile(mobile);
  if (!user) {
    throw new Error('User not found for this mobile number.');
  }

  const activeOtp = store.getActiveOtp(user.id, 'login');
  if (!activeOtp) {
    throw new Error('No active OTP found or code expired. Please request a new one.');
  }

  if (activeOtp.attempts >= 5) {
    await store.markOtpUsed(activeOtp.id);
    throw new Error('Too many failed attempts. This OTP is now invalidated.');
  }

  const expectedHash = hashOtp(code.trim(), user.id, 'login');
  const isMatch = crypto.timingSafeEqual(
    Buffer.from(activeOtp.codeHash, 'hex'),
    Buffer.from(expectedHash, 'hex')
  );

  if (!isMatch) {
    store.incrementOtpAttempts(activeOtp.id);
    throw new Error('Incorrect OTP code.');
  }

  // Success: mark used
  if (!await store.markOtpUsed(activeOtp.id)) throw new Error('Invalid or expired OTP code');

  // Check user status
  const [mfa, policy, wallet] = await Promise.all([
    store.findPersistedMfa(user.id), store.loadPolicy(user.id), store.loadWallet(user.id),
  ]);

  // Issue temporary primary auth token (mfaVerified: false until MFA completes)
  const token = await createAccountSession(user.id, false);

  store.logSecurity({
    id: crypto.randomUUID(),
    userId: user.id,
    eventType: 'OTP_VERIFICATION_SUCCESS',
    severity: 'INFO',
    timestamp: new Date().toISOString(),
  });

  return {
    user,
    token,
    mfaEnrolled: !!mfa?.totpSecretEncrypted,
    mfaVerified: !!mfa?.verifiedAt,
    hasPolicy: !!policy,
    hasWallet: !!wallet && wallet.status === 'READY',
  };
}

/**
 * Google Sign-In verification.
 */
export async function verifyGoogleToken(idToken: string, nonce?: string): Promise<{
  user: UserRecord;
  token: string;
  mfaEnrolled: boolean;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
}> {
  const { subject: googleId, email, name } = await verifyGoogleIdentity(idToken, nonce);
  let user = await store.findPersistedUser({ googleId });

  if (!user) {
    const emailOwner = email ? await store.findPersistedUser({ email }) : null;
    if (emailOwner) throw new Error('This email is already associated with a different account');
    user = {
      id: crypto.randomUUID(),
      name,
      email,
      googleId,
      loginMethod: 'google',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    try {
      await store.saveUser(user);
    } catch (err) {
      if (typeof err !== 'object' || !err || !('code' in err) || err.code !== 'P2002') throw err;
      user = await store.findPersistedUser({ googleId });
      if (!user) throw err;
    }
  }

  const [mfa, policy, wallet] = await Promise.all([
    store.findPersistedMfa(user.id), store.loadPolicy(user.id), store.loadWallet(user.id),
  ]);

  const token = await createAccountSession(user.id, false);

  store.logSecurity({
    id: crypto.randomUUID(),
    userId: user.id,
    eventType: 'GOOGLE_AUTH_SUCCESS',
    severity: 'INFO',
    timestamp: new Date().toISOString(),
  });

  return {
    user,
    token,
    mfaEnrolled: !!mfa?.totpSecretEncrypted,
    mfaVerified: !!mfa?.verifiedAt,
    hasPolicy: !!policy,
    hasWallet: !!wallet && wallet.status === 'READY',
  };
}

/**
 * Links an additional authentication method (Google or Phone) to an existing user.
 */
export async function linkAccount(
  userId: string,
  targetMethod: 'google' | 'mobile',
  identifier: string
): Promise<{ success: boolean; user: UserRecord }> {
  if (targetMethod !== 'google') throw new Error('Mobile account linking requires verified SMS delivery');
  const { subject } = await verifyGoogleIdentity(identifier);
  const existing = await store.findPersistedUser({ googleId: subject });
  if (existing && existing.id !== userId) {
    throw new Error('This Google account is already linked to another SARAL identity.');
  }
  const user = await store.attachGoogleIdentity(userId, subject);

  store.logSecurity({
    id: crypto.randomUUID(),
    userId,
    eventType: 'ACCOUNT_LINKED',
    severity: 'INFO',
    details: { method: targetMethod },
    timestamp: new Date().toISOString(),
  });

  return { success: true, user };
}
