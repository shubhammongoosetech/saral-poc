import { prisma } from '../../database/prisma';
import { OTPChallenge } from '@prisma/client';

export class OtpRepository {
  public async createOtpChallenge(data: {
    userId: string;
    codeHash: string;
    purpose: string;
    expiresAt: Date;
  }): Promise<OTPChallenge> {
    return prisma.oTPChallenge.create({
      data: {
        userId: data.userId,
        code: data.codeHash,
        purpose: data.purpose,
        expiresAt: data.expiresAt,
        used: false,
      },
    });
  }

  public async findValidOtp(userId: string, purpose: string): Promise<OTPChallenge | null> {
    return prisma.oTPChallenge.findFirst({
      where: {
        userId,
        purpose,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
  }

  public async markOtpUsed(id: string): Promise<void> {
    await prisma.oTPChallenge.update({
      where: { id },
      data: { used: true },
    });
  }
}

export const otpRepository = new OtpRepository();
