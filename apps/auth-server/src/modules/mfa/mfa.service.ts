import crypto from 'crypto';
import { mfaRepository } from './mfa.repository';
import {
  generateBase32Secret,
  encryptTotpSecret,
  decryptTotpSecret,
  computeTotpToken,
  generateRecoveryCodes,
  hashRecoveryCode,
} from '../../utils/crypto';
import { KeyManager } from '../../auth/token';
import { env } from '../../config/env';

const keyManager = KeyManager.getInstance();

export class MfaService {
  public async enrollTotp(
    userId: string,
    accountLabel = 'SARAL Wallet'
  ): Promise<{
    secret: string;
    qrUri: string;
    recoveryCodes: string[];
    devOtp?: string;
  }> {
    const rawSecret = generateBase32Secret(20);
    const encryptedSecret = encryptTotpSecret(rawSecret);
    const recoveryCodes = generateRecoveryCodes(8);
    const hashedCodes = recoveryCodes.map((c) => hashRecoveryCode(c));

    const mfa = await mfaRepository.upsertMfaEnrollment({
      userId,
      type: 'totp',
      totpSecretEncrypted: encryptedSecret,
      recoveryCodesHashed: hashedCodes,
    });

    await mfaRepository.storeRecoveryCodes(mfa.id, hashedCodes);

    const issuer = 'SARAL';
    const qrUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(
      accountLabel
    )}?secret=${rawSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    const devOtp = env.isDev || env.isTest ? computeTotpToken(rawSecret) : undefined;

    return {
      secret: rawSecret,
      qrUri,
      recoveryCodes,
      devOtp,
    };
  }

  public async verifyMfaChallenge(
    userId: string,
    codeOrRecovery: string
  ): Promise<{
    success: boolean;
    token: string;
    methodUsed: 'totp' | 'recovery';
  }> {
    const mfa = await mfaRepository.getMfaByUserId(userId);
    if (!mfa || !mfa.totpSecretEncrypted) {
      throw new Error('User has not enrolled in Multi-Factor Authentication.');
    }

    const input = codeOrRecovery.trim();

    // Check if recovery code (format: XXXX-XXXX)
    if (/^[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}$/.test(input)) {
      const codeHash = hashRecoveryCode(input);
      let consumed = await mfaRepository.consumeRecoveryCode(mfa.id, codeHash);

      if (!consumed) {
        // Fallback check against array
        const index = mfa.recoveryCodesHashed.indexOf(codeHash);
        if (index === -1) {
          throw new Error('Invalid or already used recovery code.');
        }
        consumed = true;
      }

      await mfaRepository.setMfaVerified(userId);
      const token = keyManager.issueToken(userId, 'operator', true);

      return {
        success: true,
        token,
        methodUsed: 'recovery',
      };
    }

    // Check 6-digit TOTP
    if (!/^\d{6}$/.test(input)) {
      throw new Error('MFA code must be exactly 6 digits or a valid recovery code.');
    }

    const rawSecret = decryptTotpSecret(mfa.totpSecretEncrypted);

    // Timing-safe check with +/- 1 window drift (past, current, next 30s)
    let matched = false;
    for (const offset of [0, -1, 1]) {
      const expected = computeTotpToken(rawSecret, 30, offset);
      if (crypto.timingSafeEqual(Buffer.from(input), Buffer.from(expected))) {
        matched = true;
        break;
      }
    }

    if (!matched) {
      throw new Error('Invalid TOTP verification code.');
    }

    await mfaRepository.setMfaVerified(userId);
    const token = keyManager.issueToken(userId, 'operator', true);

    return {
      success: true,
      token,
      methodUsed: 'totp',
    };
  }

  public async getMfaStatus(userId: string): Promise<{
    enrolled: boolean;
    type: string;
    verified: boolean;
  }> {
    const mfa = await mfaRepository.getMfaByUserId(userId);
    return {
      enrolled: !!mfa?.totpSecretEncrypted,
      type: mfa?.type || 'totp',
      verified: !!mfa?.verifiedAt,
    };
  }
}

export const mfaService = new MfaService();

