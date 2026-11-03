import { prisma } from '../config/db';
import { env } from '../config/env';
import { signToken } from '../utils/jwt';
import { secureCompare } from '../utils/crypto';

export interface MfaVerificationResult {
  success:   boolean;
  token:     string;
  hasPolicy: boolean;
  hasWallet: boolean;
}

export async function sendMfaOtp(
  userId: string
): Promise<{ success: boolean; message: string; devOtp?: string }> {
  const code = Math.floor(100000 + Math.random() * 900000).toString();

  await prisma.$transaction([
    // Invalidate old MFA OTPs
    prisma.otp.updateMany({
      where: { userId, purpose: 'mfa', used: false },
      data:  { used: true },
    }),
    // Insert fresh one
    prisma.otp.create({
      data: {
        userId,
        code,
        purpose:   'mfa',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        used:      false,
      },
    }),
  ]);

  console.log('───────────────────────────────────────────────────────');
  console.log(`[MFA OTP CODE] User: ${userId} | CODE: ${code}`);
  console.log('───────────────────────────────────────────────────────');

  return {
    success: true,
    message: 'MFA verification code dispatched.',
    devOtp:  env.NODE_ENV === 'development' ? code : undefined,
  };
}

export async function verifyMfaOtp(
  userId: string,
  otpCode: string
): Promise<MfaVerificationResult> {
  const otpRecord = await prisma.otp.findFirst({
    where: {
      userId,
      purpose:   'mfa',
      used:      false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    select:  { id: true, code: true },
  });

  if (!otpRecord) {
    throw new Error('Invalid or expired MFA code. Please request a new code.');
  }
  if (!secureCompare(otpRecord.code, otpCode)) {
    throw new Error('Incorrect MFA code entered.');
  }

  // Mark OTP used + upsert MFA record — in one transaction
  await prisma.$transaction([
    prisma.otp.update({
      where: { id: otpRecord.id },
      data:  { used: true },
    }),
    prisma.mfa.upsert({
      where:  { userId },
      update: { verifiedAt: new Date() },
      create: { userId, type: 'otp', verifiedAt: new Date() },
    }),
  ]);

  const user = await prisma.user.findUnique({
    where:  { id: userId },
    select: { loginMethod: true },
  });
  const loginMethod = (user?.loginMethod ?? 'google') as 'google' | 'mobile';

  const [policy, shareCount] = await Promise.all([
    prisma.workPolicy.findUnique({ where: { userId }, select: { id: true } }),
    prisma.keyShare.count({ where: { userId } }),
  ]);

  const token = signToken({ userId, loginMethod, mfaVerified: true });

  return {
    success:   true,
    token,
    hasPolicy: !!policy,
    hasWallet: shareCount > 0,
  };
}
