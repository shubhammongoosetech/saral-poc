import { prisma } from '../../database/prisma';
import { WalletIdentity, WalletCreationJob } from '@prisma/client';

export class WalletRepository {
  public async getWalletByUserId(userId: string): Promise<WalletIdentity | null> {
    return prisma.walletIdentity.findUnique({
      where: { userId },
      include: { keyReferenceRecords: true },
    });
  }

  public async getWalletByWalletId(walletId: string): Promise<WalletIdentity | null> {
    return prisma.walletIdentity.findUnique({
      where: { walletId },
      include: { keyReferenceRecords: true },
    });
  }

  public async createWallet(data: {
    userId: string;
    walletId: string;
    status?: string;
    keyReferences: Record<string, any>;
  }): Promise<WalletIdentity> {
    return prisma.$transaction(async (tx) => {
      const wallet = await tx.walletIdentity.create({
        data: {
          userId: data.userId,
          walletId: data.walletId,
          status: data.status || 'READY',
          keyReferences: data.keyReferences,
        },
      });

      // Insert individual key references (scalar string keys only)
      const entries = Object.entries(data.keyReferences).filter(
        ([_, v]) => typeof v === 'string'
      ) as [string, string][];
      if (entries.length > 0) {
        await tx.walletKeyReference.createMany({
          data: entries.map(([chain, keyRef]) => ({
            walletId: data.walletId,
            chain,
            keyRef,
            status: 'ACTIVE',
          })),
          skipDuplicates: true,
        });
      }

      return wallet;
    });
  }

  public async updateWalletKeyReferences(
    walletId: string,
    keyReferences: Record<string, any>
  ): Promise<WalletIdentity> {
    return prisma.$transaction(async (tx) => {
      const wallet = await tx.walletIdentity.update({
        where: { walletId },
        data: {
          keyReferences,
          updatedAt: new Date(),
        },
      });

      const entries = Object.entries(keyReferences).filter(
        ([_, v]) => typeof v === 'string'
      ) as [string, string][];
      for (const [chain, keyRef] of entries) {
        await tx.walletKeyReference.upsert({
          where: {
            walletId_chain: {
              walletId,
              chain,
            },
          },
          create: {
            walletId,
            chain,
            keyRef,
            status: 'ACTIVE',
          },
          update: {
            keyRef,
            status: 'ACTIVE',
          },
        });
      }

      return wallet;
    });
  }

  public async createJob(userId: string): Promise<WalletCreationJob> {
    return prisma.walletCreationJob.create({
      data: {
        userId,
        status: 'PENDING',
      },
    });
  }

  public async updateJobStatus(
    id: string,
    status: 'PROCESSING' | 'COMPLETED' | 'FAILED',
    error?: string
  ): Promise<void> {
    await prisma.walletCreationJob.update({
      where: { id },
      data: {
        status,
        error,
        updatedAt: new Date(),
      },
    });
  }
}

export const walletRepository = new WalletRepository();
