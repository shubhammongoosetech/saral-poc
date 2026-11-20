import { Request, Response } from 'express';
import crypto from 'crypto';
import { KeyManager } from '../auth/token';
import { DataStore } from '../storage/store';
import {
  enrollTotp,
  verifyMfaChallenge,
  decryptTotpSecret,
  computeTotpToken,
} from '../services/mfaService';

const keyManager = KeyManager.getInstance();
const store = DataStore.getInstance();

/**
 * MfaController
 * Feature: Multi-Factor Authentication (RFC 6238 TOTP & SMS fallback)
 * 
 * Handles:
 * - MFA status inquiry
 * - TOTP enrollment & QR code uri generation
 * - Fallback MFA OTP dispatch
 * - TOTP / Backup recovery code verification & token elevation
 */
export class MfaController {
  /**
   * GET /mfa/status
   * Hinglish: User ka MFA enrollment aur verification status return karta hai.
   */
  public static getStatus(req: Request, res: Response): void {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        res.status(401).json({ success: false, error: 'Authorization token required' });
        return;
      }
      const token = authHeader.replace(/^Bearer\s+/i, '');
      const decoded = keyManager.verifyToken(token);
      const userId = decoded.sub;
      const mfa = store.getMfa(userId);

      const enrolled = !!(mfa && mfa.totpSecretEncrypted && mfa.verifiedAt);
      res.json({
        success: true,
        enrolled,
        type: mfa?.type || 'totp',
        verified: !!mfa?.verifiedAt,
      });
    } catch (err: any) {
      res.status(401).json({ success: false, error: err.message || 'Unauthorized' });
    }
  }

  /**
   * POST /mfa/enroll
   * Hinglish: RFC 6238 compliant TOTP secret aur 8 recovery codes generate karta hai.
   */
  public static enroll(req: Request, res: Response): void {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        res.status(401).json({ success: false, error: 'Authorization token required' });
        return;
      }
      const token = authHeader.replace(/^Bearer\s+/i, '');
      const decoded = keyManager.verifyToken(token);
      const userId = decoded.sub;
      const user = store.findUserById(userId);

      const emailOrPhone = user?.email || user?.mobile || 'saral-user';
      const enrollment = enrollTotp(userId, emailOrPhone);

      const isDev =
        process.env.ENABLE_DEV_AUTH === 'true' ||
        process.env.NODE_ENV === 'development' ||
        process.env.NODE_ENV === 'test' ||
        !process.env.NODE_ENV ||
        process.env.AUTH_DEV_OTP_DISPLAY === 'true';

      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const devOtp = isDev ? computeTotpToken(enrollment.secret, currentStep) : undefined;

      res.json({
        success: true,
        secret: enrollment.secret,
        qrUri: enrollment.qrUri,
        recoveryCodes: enrollment.recoveryCodes,
        devOtp,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'MFA enrollment failed' });
    }
  }

  /**
   * POST /mfa/send
   * Hinglish: Registered user ke liye MFA OTP challenge trigger karta hai.
   */
  public static sendOtp(req: Request, res: Response): void {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        res.status(401).json({ success: false, error: 'Authorization token required' });
        return;
      }
      const token = authHeader.replace(/^Bearer\s+/i, '');
      const decoded = keyManager.verifyToken(token);
      const userId = decoded.sub;
      const user = store.findUserById(userId);

      const mfaOtpCode = crypto.randomInt(100000, 1000000).toString();
      const codeHash = crypto.createHmac('sha256', 'mfa-salt').update(`${userId}:mfa:${mfaOtpCode}`).digest('hex');

      store.saveOtp({
        id: crypto.randomUUID(),
        userId,
        mobile: user?.mobile || 'mfa-totp',
        codeHash,
        purpose: 'mfa',
        expiresAt: Date.now() + 10 * 60 * 1000,
        used: false,
        attempts: 0,
        createdAt: Date.now(),
      });

      const isDev =
        process.env.ENABLE_DEV_AUTH === 'true' ||
        process.env.NODE_ENV === 'development' ||
        process.env.NODE_ENV === 'test' ||
        !process.env.NODE_ENV ||
        process.env.AUTH_DEV_OTP_DISPLAY === 'true';

      let devOtp: string | undefined = undefined;
      if (isDev) {
        const existingMfa = store.getMfa(userId);
        if (existingMfa?.totpSecretEncrypted) {
          try {
            const secret = decryptTotpSecret(existingMfa.totpSecretEncrypted);
            const currentStep = Math.floor(Date.now() / 1000 / 30);
            devOtp = computeTotpToken(secret, currentStep);
          } catch (_) { }
        }
        if (!devOtp) {
          devOtp = mfaOtpCode;
        }
      }

      res.json({
        success: true,
        message: 'MFA challenge initiated',
        devOtp,
      });
    } catch (err: any) {
      res.status(401).json({ success: false, error: err.message || 'Failed to dispatch MFA code' });
    }
  }

  /**
   * POST /mfa/verify
   * Hinglish: TOTP authenticator code ya backup recovery code verify karke token upgrade karta hai.
   */
  public static verify(req: Request, res: Response): void {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        res.status(401).json({ success: false, error: 'Authorization token required' });
        return;
      }
      const token = authHeader.replace(/^Bearer\s+/i, '');
      const decoded = keyManager.verifyToken(token);
      const userId = decoded.sub;

      const code = req.body?.otp || req.body?.code || req.body?.recoveryCode;
      if (!code) {
        res.status(400).json({ success: false, error: 'MFA code required' });
        return;
      }

      // Check if matching mfa OTP in store
      const activeMfaOtp = store.getActiveOtp(userId, 'mfa');
      let verified = false;
      if (activeMfaOtp) {
        const computedHash = crypto.createHmac('sha256', 'mfa-salt').update(`${userId}:mfa:${code.trim()}`).digest('hex');
        if (crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(activeMfaOtp.codeHash))) {
          store.markOtpUsed(activeMfaOtp.id);
          verified = true;
        }
      }

      if (!verified) {
        verifyMfaChallenge(userId, code);
        verified = true;
      }

      // Issue upgraded token with mfaVerified: true
      const upgradedToken = keyManager.issueToken(userId, 'operator', true);
      const policy = store.getPolicy(userId);
      const wallet = store.getWalletByUserId(userId);

      // Save MFA verified
      const existingMfa = store.getMfa(userId);
      store.saveMfa({
        userId,
        type: existingMfa?.type || 'totp',
        totpSecretEncrypted: existingMfa?.totpSecretEncrypted,
        recoveryCodesHashed: existingMfa?.recoveryCodesHashed,
        verifiedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      res.json({
        success: true,
        token: upgradedToken,
        hasPolicy: !!policy,
        hasWallet: !!wallet && wallet.status === 'READY',
      });
    } catch (err: any) {
      res.status(401).json({ success: false, error: err.message || 'MFA verification failed' });
    }
  }
}

