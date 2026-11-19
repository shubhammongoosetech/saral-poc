import { prisma } from '../../database/prisma';
import { MFAEnrollment } from '@prisma/client';

export class MfaRepository {
  public async getMfaByUserId(userId: string): Promise<MFAEnrollment | null> {
    return prisma.mFAEnrollment.findUnique({
      where: { userId },
      include: { recoveryCodeRecords: true },
    });
  }

  public async upsertMfaEnrollment(data: {
    userId: string;
    type?: string;
    totpSecretEncrypted: string;
    recoveryCodesHashed: string[];
    verifiedAt?: Date;
  }): Promise<MFAEnrollment> {
    return prisma.mFAEnrollment.upsert({
      where: { userId: data.userId },
      create: {
        userId: data.userId,
        type: data.type || 'totp',
        totpSecretEncrypted: data.totpSecretEncrypted,
        recoveryCodesHashed: data.recoveryCodesHashed,
        verifiedAt: data.verifiedAt,
      },
      update: {
        totpSecretEncrypted: data.totpSecretEncrypted,
        recoveryCodesHashed: data.recoveryCodesHashed,
        verifiedAt: data.verifiedAt,
      },
    });
  }

  public async setMfaVerified(userId: string): Promise<MFAEnrollment> {
    return prisma.mFAEnrollment.update({
      where: { userId },
      data: { verifiedAt: new Date() },
    });
  }

  public async storeRecoveryCodes(mfaId: string, hashedCodes: string[]): Promise<void> {
    await prisma.mFARecoveryCode.createMany({
      data: hashedCodes.map((codeHash) => ({
        mfaId,
        codeHash,
        used: false,
      })),
    });
  }

  public async consumeRecoveryCode(mfaId: string, codeHash: string): Promise<boolean> {
    const code = await prisma.mFARecoveryCode.findFirst({
      where: { mfaId, codeHash, used: false },
    });

    if (!code) return false;

    await prisma.mFARecoveryCode.update({
      where: { id: code.id },
      data: { used: true, usedAt: new Date() },
    });

    return true;
  }
}

export const mfaRepository = new MfaRepository();
