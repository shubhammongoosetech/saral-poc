import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { prisma } from '../config/db';
import { env } from '../config/env';
import { signToken } from '../utils/jwt';
import { secureCompare } from '../utils/crypto';
import { hashOtpCode } from './mfaService';

const googleClient = new OAuth2Client(env.GOOGLE_CLIENT_ID);

export interface AuthResult {
  user: {
    id: string;
    loginMethod: 'google' | 'mobile';
    mobile?: string;
    googleId?: string;
    email?: string;
  };
  token: string;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
}

// Status lookup helper
async function getUserStatus(userId: string) {
  const [mfa, policy, shareCount, walletCount] = await Promise.all([
    prisma.mfa.findUnique({ where: { userId }, select: { verifiedAt: true } }).catch(() => null),
    prisma.workPolicy.findUnique({ where: { userId }, select: { id: true } }).catch(() => null),
    prisma.keyShare.count({ where: { userId } }).catch(() => 0),
    prisma.wallet.count({ where: { userId } }).catch(() => 0),
  ]);

  return {
    mfaVerified: !!mfa?.verifiedAt,
    hasPolicy: !!policy,
    hasWallet: shareCount > 0 || walletCount > 0,
  };
}

// Google OAuth authentication
export async function verifyGoogleAuth(credential: string): Promise<AuthResult> {
  const ticket = await googleClient.verifyIdToken({
    idToken: credential,
    audience: env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  if (!payload?.sub) throw new Error('Invalid Google credential payload');

  const googleId = payload.sub;
  const email = payload.email ?? null;

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
      data: { googleId, email, loginMethod: 'google' },
    });
  } else if (!user.email && email) {
    user = await prisma.user.update({
      where: { id: user.id },
      data: { email },
    });
  }

  const status = await getUserStatus(user.id);

  const token = signToken({
    userId: user.id,
    loginMethod: 'google',
    mfaVerified: false,
  });

  return {
    user: {
      id: user.id,
      loginMethod: 'google',
      googleId: user.googleId ?? undefined,
      email: user.email ?? undefined,
    },
    token,
    ...status,
  };
}

// Mobile phone OTP authentication
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
    select: { id: true, mobile: true, loginMethod: true },
  });
  if (!user) throw new Error('User not found for this mobile number');

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

  // Mark OTP used
  await prisma.otp.update({
    where: { id: otpRecord.id },
    data: { used: true },
  });

  const status = await getUserStatus(user.id);

  const token = signToken({
    userId: user.id,
    loginMethod: 'mobile',
    mfaVerified: false,
  });

  return {
    user: {
      id: user.id,
      loginMethod: 'mobile',
      mobile: user.mobile ?? undefined,
    },
    token,
    ...status,
  };
}
