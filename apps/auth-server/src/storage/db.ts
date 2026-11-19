/**
 * db.ts
 *
 * PostgreSQL & Prisma ORM Connectivity for SARAL Authentication Server.
 * Backwards-compatible export wrapping Prisma connection lifecycle.
 */

import { Pool } from 'pg';
import { connectPrisma, disconnectPrisma, prisma } from '../database/prisma';
import { env } from '../config/env';

export const pgPool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

let isConnected = false;

export async function initPostgres(): Promise<boolean> {
  try {
    const success = await connectPrisma();
    isConnected = success;
    return success;
  } catch (err: any) {
    isConnected = false;
    console.warn('[PostgreSQL/Prisma] Database connection warning:', err.message);
    return false;
  }
}

export function getIsPgConnected(): boolean {
  return isConnected;
}

export { prisma, connectPrisma, disconnectPrisma };
