import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { prisma } from '../config/db';
import { env } from '../config/env';
import { signAccessToken, signRefreshToken } from '../utils/jwt';
import { secureCompare } from '../utils/crypto';
import { hashOtpCode } from './mfaService';

const googleClient = new OAuth2Client(env.GOOGLE_CLIENT_ID);

export interface AuthResult {
  user: {
    id: string;
    name?: string;
    loginMethod: 'google' | 'mobile';
    mobile?: string;
    googleId?: string;
    email?: string;
  };
  // TODO: Remove token from response body once all frontend clients
  //       have migrated to reading from httpOnly cookie (D-07).
  token: string;
  accessToken: string;
  refreshToken: string;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
}

// ---------------------------------------------------------------------------
// OTP attempt tracking (in-memory for POC — D-07 / 1.7)
//
// POC NOTE: In production this must be backed by Redis or the database to
// survive process restarts and work across multiple instances.
// ---------------------------------------------------------------------------
interface OtpAttemptRecord {
  count: number;
  resetAt: number; // epoch ms
}

const otpAttempts = new Map<string, OtpAttemptRecord>();

const OTP_MAX_ATTEMPTS = 5;
const OTP_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function getAttemptKey(userId: string, purpose: string): string {
  return `${userId}:${purpose}`;
}

function checkAndIncrementAttempt(userId: string, purpose: string): void {
  const key = getAttemptKey(userId, purpose);
  const now = Date.now();
  const record = otpAttempts.get(key);

  if (record && now < record.resetAt) {
    if (record.count >= OTP_MAX_ATTEMPTS) {
      const remainingSecs = Math.ceil((record.resetAt - now) / 1000);
      throw new Error(
        `Too many failed OTP attempts. Try again in ${remainingSecs} seconds.`
      );
    }
    record.count += 1;
  } else {
    // Window expired or first attempt
    otpAttempts.set(key, { count: 1, resetAt: now + OTP_LOCKOUT_MS });
  }
}

function resetAttempts(userId: string, purpose: string): void {
  otpAttempts.delete(getAttemptKey(userId, purpose));
}

// ---------------------------------------------------------------------------
// Status lookup helper
// ---------------------------------------------------------------------------
async function getUserStatus(userId: string) {
  const [mfa, policy, shareCount, walletCount] = await Promise.all([
    prisma.mfa.findUnique({ where: { userId }, select: { verifiedAt: true } }).catch(() => null),
    prisma.workPolicy.findUnique({ where: { userId }, select: { id: true } }).catch(() => null),
    prisma.keyShare.count({ where: { userId } }).catch(() => 0),
    prisma.walletPlacement.count({ where: { userId } }).catch(() => 0),
  ]);

  return {
    mfaVerified: !!mfa?.verifiedAt,
    hasPolicy: !!policy,
    hasWallet: shareCount > 0 || walletCount > 0,
  };
}

// ---------------------------------------------------------------------------
// Google OAuth authentication
// ---------------------------------------------------------------------------
export async function verifyGoogleAuth(credential: string): Promise<AuthResult> {
  const ticket = await googleClient.verifyIdToken({
    idToken: credential,
    audience: env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  if (!payload?.sub) throw new Error('Invalid Google credential payload');

  const googleId = payload.sub;
  const email = payload.email ?? null;
  const name = payload.name ?? null;

  // Find by google_id OR email
  let user = await prisma.user.findFirst({
    where: {
      OR: [
        { googleId },
        ...(email ? [{ email }] : []),
      ],
    },
  });

  if (!user) {
    user = await prisma.user.create({
      data: { googleId, email, name, loginMethod: 'google' },
    });
  } else {
    const updateData: { email?: string; name?: string } = {};
    if (!user.email && email) updateData.email = email;
    if ((!user.name || user.name !== name) && name) updateData.name = name;
    if (Object.keys(updateData).length > 0) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: updateData,
      });
    }
  }

  const status = await getUserStatus(user.id);

  const accessToken = signAccessToken({
    userId: user.id,
    loginMethod: 'google',
    mfaVerified: false,
  });
  const refreshToken = signRefreshToken(user.id);

  return {
    user: {
      id: user.id,
      name: user.name ?? undefined,
      loginMethod: 'google',
      googleId: user.googleId ?? undefined,
      email: user.email ?? undefined,
    },
    token: accessToken, // TODO: remove once frontend reads cookie
    accessToken,
    refreshToken,
    ...status,
  };
}

// ---------------------------------------------------------------------------
// Mobile phone OTP authentication
// ---------------------------------------------------------------------------
export async function requestMobileOtp(
  mobile: string
): Promise<{ success: boolean; message: string; devOtp?: string }> {
  // Upsert user
  const user = await prisma.user.upsert({
    where: { mobile },
    update: {},
    create: { mobile, loginMethod: 'mobile' },
    select: { id: true },
  });

  const code = crypto.randomInt(100000, 1000000).toString();
  const codeHash = hashOtpCode(code, 'login');

  // Invalidate old login OTPs, then insert fresh one (in a transaction)
  await prisma.$transaction([
    prisma.otp.updateMany({
      where: { userId: user.id, purpose: 'login', used: false },
      data: { used: true },
    }),
    prisma.otp.create({
      data: {
        userId: user.id,
        code: codeHash,
        purpose: 'login',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        used: false,
      },
    }),
  ]);

  if (env.NODE_ENV === 'development') {
    console.log(`[SMS OTP AUTH] Mobile: ${mobile} | Code: ${code}`);
  }

  return {
    success: true,
    message: 'OTP dispatched successfully.',
    devOtp: env.NODE_ENV === 'development' ? code : undefined,
  };
}

export async function verifyMobileOtp(
  mobile: string,
  otpCode: string
): Promise<AuthResult> {
  const user = await prisma.user.findUnique({
    where: { mobile },
    select: { id: true, name: true, mobile: true, loginMethod: true },
  });
  if (!user) throw new Error('User not found for this mobile number');

  // Lockout check before comparing (1.7)
  checkAndIncrementAttempt(user.id, 'login');

  const cleanCode = otpCode.trim();
  const expectedHash = hashOtpCode(cleanCode, 'login');

  const otpRecord = await prisma.otp.findFirst({
    where: {
      userId: user.id,
      purpose: 'login',
      used: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    select: { id: true, code: true },
  });

  if (!otpRecord) {
    throw new Error('Invalid or expired OTP code. Please request a new code.');
  }

  const isMatch =
    secureCompare(otpRecord.code, expectedHash) ||
    secureCompare(otpRecord.code, cleanCode);

  if (!isMatch) {
    throw new Error('Incorrect OTP code');
  }

  // Success — reset attempt counter
  resetAttempts(user.id, 'login');

  // Mark OTP used
  await prisma.otp.update({
    where: { id: otpRecord.id },
    data: { used: true },
  });

  const status = await getUserStatus(user.id);

  const accessToken = signAccessToken({
    userId: user.id,
    loginMethod: 'mobile',
    mfaVerified: false,
  });
  const refreshToken = signRefreshToken(user.id);

  return {
    user: {
      id: user.id,
      name: user.name ?? undefined,
      loginMethod: 'mobile',
      mobile: user.mobile ?? undefined,
    },
    token: accessToken, // TODO: remove once frontend reads cookie
    accessToken,
    refreshToken,
    ...status,
  };
}
