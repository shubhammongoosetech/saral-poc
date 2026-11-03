import { PrismaClient } from '@prisma/client';

/**
 * Single shared PrismaClient instance for the entire application.
 * In development, attaches to `globalThis` to survive hot-reloads (tsx watch).
 */
const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma: PrismaClient =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'warn', 'error']
        : ['warn', 'error'],
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

export async function testConnection(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT NOW()`;
    console.log('[DB] Prisma connected to PostgreSQL');
    return true;
  } catch (err) {
    console.error('[DB] Failed to connect via Prisma:', err);
    return false;
  }
}
