import { createAccountSession } from '../../auth/accountSession';
import { canDisplayDevOtp } from '../../config/auth';
import { computeTotpToken, enrollTotp, verifyMfaChallenge } from '../../services/mfaService';
import { DataStore } from '../../storage/store';

const store = DataStore.getInstance();

export class MfaService {
  public async enrollTotp(userId: string, accountLabel = 'SARAL Wallet') {
    const enrollment = await enrollTotp(userId, accountLabel);
    const currentStep = Math.floor(Date.now() / 30_000);
    const devOtp = canDisplayDevOtp() ? computeTotpToken(enrollment.secret, currentStep) : undefined;
    return { ...enrollment, devOtp };
  }

  public async verifyMfaChallenge(userId: string, codeOrRecovery: string) {
    const result = await verifyMfaChallenge(userId, codeOrRecovery);
    const token = await createAccountSession(userId, true);
    return {
      success: result.verified,
      token,
      methodUsed: result.method === 'recovery-code' ? 'recovery' : 'totp',
    };
  }

  public async getMfaStatus(userId: string) {
    const mfa = await store.findPersistedMfa(userId);
    return {
      enrolled: !!mfa?.totpSecretEncrypted,
      type: mfa?.type || 'totp',
      verified: !!mfa?.verifiedAt,
    };
  }
}

export const mfaService = new MfaService();

