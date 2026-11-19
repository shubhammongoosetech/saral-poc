import crypto from 'crypto';
import { authRepository } from './auth.repository';
import { KeyManager } from '../../auth/token';
import { normalizeE164, hashOtp } from '../../utils/crypto';
import { prisma } from '../../database/prisma';
import { env } from '../../config/env';

const keyManager = KeyManager.getInstance();
const cooldowns = new Map<string, number>();

export class AuthService {
  public checkOtpCooldown(mobile: string): void {
    const lastSent = cooldowns.get(mobile);
    const now = Date.now();
    if (lastSent && now - lastSent < 30 * 1000) {
      const remaining = Math.ceil((30 * 1000 - (now - lastSent)) / 1000);
      throw new Error(`Please wait ${remaining} seconds before requesting a new OTP.`);
    }
  }

  public async requestPhoneOtp(mobileRaw: string): Promise<{
    success: boolean;
    mobile: string;
    cooldownSeconds: number;
    devOtp?: string;
  }> {
    const mobile = normalizeE164(mobileRaw);
    this.checkOtpCooldown(mobile);

    let user = await authRepository.findUserByMobile(mobile);
    if (!user) {
      user = await authRepository.createUser({
        mobile,
        loginMethod: 'mobile',
      });
    }

    // Generate secure 6-digit OTP
    const otpCode = crypto.randomInt(100000, 1000000).toString();
    const codeHash = hashOtp(otpCode, user.id, 'login');

    // Invalidate existing unused login OTPs
    await prisma.oTPChallenge.updateMany({
      where: {
        userId: user.id,
        purpose: 'login',
        used: false,
      },
      data: { used: true },
    });

    // Save OTP challenge to Prisma
    await prisma.oTPChallenge.create({
      data: {
        userId: user.id,
        code: codeHash,
        purpose: 'login',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
        used: false,
      },
    });

    cooldowns.set(mobile, Date.now());

    await prisma.securityAuditEvent.create({
      data: {
        userId: user.id,
        eventType: 'OTP_REQUESTED',
        severity: 'INFO',
        details: JSON.stringify({ mobile: mobile.slice(0, 4) + '****' + mobile.slice(-2) }),
      },
    });

    return {
      success: true,
      mobile,
      cooldownSeconds: 30,
      devOtp: env.isDev || env.isTest ? otpCode : undefined,
    };
  }

  public async verifyPhoneOtp(
    mobileRaw: string,
    code: string
  ): Promise<{
    user: any;
    token: string;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    const mobile = normalizeE164(mobileRaw);
    const user = await authRepository.findUserByMobile(mobile);
    if (!user) {
      throw new Error('User not found for this mobile number.');
    }

    const activeOtp = await prisma.oTPChallenge.findFirst({
      where: {
        userId: user.id,
        purpose: 'login',
        used: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!activeOtp) {
      throw new Error('No active OTP found or code expired. Please request a new one.');
    }

    const expectedHash = hashOtp(code.trim(), user.id, 'login');
    const isMatch = crypto.timingSafeEqual(
      Buffer.from(activeOtp.code, 'hex'),
      Buffer.from(expectedHash, 'hex')
    );

    if (!isMatch) {
      throw new Error('Incorrect OTP code.');
    }

    // Mark OTP as used
    await prisma.oTPChallenge.update({
      where: { id: activeOtp.id },
      data: { used: true },
    });

    // Check relations
    const [mfa, policy, wallet] = await Promise.all([
      prisma.mFAEnrollment.findUnique({ where: { userId: user.id } }),
      prisma.workingPolicy.findUnique({ where: { userId: user.id } }),
      prisma.walletIdentity.findUnique({ where: { userId: user.id } }),
    ]);

    const token = keyManager.issueToken(user.id, 'operator', false);

    await prisma.securityAuditEvent.create({
      data: {
        userId: user.id,
        eventType: 'OTP_VERIFICATION_SUCCESS',
        severity: 'INFO',
      },
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

  public async verifyGoogleToken(idToken: string): Promise<{
    user: any;
    token: string;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    let payload: any;
    try {
      const parts = idToken.split('.');
      if (parts.length === 3) {
        payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      }
    } catch (_) {}

    if (!payload || (!payload.sub && !payload.email)) {
      throw new Error('Invalid Google credential token.');
    }

    const googleId = payload.sub || `google-${Date.now()}`;
    const email = payload.email || undefined;
    const name = payload.name || undefined;

    let user = await authRepository.findUserByGoogleId(googleId);
    if (!user && email) {
      user = await authRepository.findUserByEmail(email);
      if (user && !user.googleId) {
        user = await authRepository.updateUser(user.id, { googleId });
      }
    }

    if (!user) {
      user = await authRepository.createUser({
        name,
        email,
        googleId,
        loginMethod: 'google',
      });
    }

    const [mfa, policy, wallet] = await Promise.all([
      prisma.mFAEnrollment.findUnique({ where: { userId: user.id } }),
      prisma.workingPolicy.findUnique({ where: { userId: user.id } }),
      prisma.walletIdentity.findUnique({ where: { userId: user.id } }),
    ]);

    const token = keyManager.issueToken(user.id, 'operator', false);

    return {
      user,
      token,
      mfaEnrolled: !!mfa?.totpSecretEncrypted,
      mfaVerified: !!mfa?.verifiedAt,
      hasPolicy: !!policy,
      hasWallet: !!wallet && wallet.status === 'READY',
    };
  }

  public async linkAccount(
    userId: string,
    provider: 'google' | 'mobile',
    tokenOrNumber: string
  ): Promise<any> {
    const user = await authRepository.findUserById(userId);
    if (!user) throw new Error('User not found.');

    if (provider === 'mobile') {
      const mobile = normalizeE164(tokenOrNumber);
      const existing = await authRepository.findUserByMobile(mobile);
      if (existing && existing.id !== userId) {
        throw new Error('This mobile number is already linked to another account.');
      }
      return authRepository.updateUser(userId, { mobile });
    } else if (provider === 'google') {
      let googleId = tokenOrNumber;
      let email: string | undefined;
      try {
        const parts = tokenOrNumber.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
          if (payload.sub) googleId = payload.sub;
          if (payload.email) email = payload.email;
        }
      } catch (_) {}

      const existing = await authRepository.findUserByGoogleId(googleId);
      if (existing && existing.id !== userId) {
        throw new Error('This Google account is already linked to another user.');
      }

      return authRepository.updateUser(userId, { googleId, ...(email ? { email } : {}) });
    }

    throw new Error('Unsupported identity provider.');
  }
}

export const authService = new AuthService();
