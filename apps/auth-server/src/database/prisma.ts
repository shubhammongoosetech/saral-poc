import { PrismaClient } from '@prisma/client';

declare global {
  // eslint-disable-next-line no-var
  var __saral_prisma: PrismaClient | undefined;
}

export const prisma: PrismaClient =
  global.__saral_prisma ||
  new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['warn', 'error']
        : ['error'],
  });

if (process.env.NODE_ENV !== 'production') {
  global.__saral_prisma = prisma;
}

export async function connectPrisma(): Promise<boolean> {
  try {
    await prisma.$connect();
    console.log('[Prisma] Connected successfully to PostgreSQL database');
    return true;
  } catch (err: any) {
    console.error('[Prisma] Failed to connect to PostgreSQL database:', err.message);
    return false;
  }
}

export async function disconnectPrisma(): Promise<void> {
  await prisma.$disconnect();
}
