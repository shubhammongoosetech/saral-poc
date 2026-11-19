/**
 * db.ts
 *
 * PostgreSQL Client & Schema Migration for SARAL Authentication Server.
 * Supports connection pooling with automatic schema initialization.
 * Fallback-resilient: if PostgreSQL is not available, the application
 * gracefully falls back to the hardened atomic file store.
 */

import { Pool, PoolClient } from 'pg';

const DATABASE_URL =
  process.env.DATABASE_URL ||
  'postgresql://saral:saral_secret@localhost:5432/saral';

export const pgPool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

let isPgConnected = false;

export async function initPostgres(): Promise<boolean> {
  let client: PoolClient | null = null;
  try {
    client = await pgPool.connect();
    isPgConnected = true;
    console.log('[PostgreSQL] Connected successfully to database');

    // Run schema creation if tables do not exist
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255),
        google_id VARCHAR(255) UNIQUE,
        email VARCHAR(255) UNIQUE,
        mobile VARCHAR(50) UNIQUE,
        login_method VARCHAR(50) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS mfa (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL DEFAULT 'totp',
        secret TEXT,
        totp_secret_encrypted TEXT,
        recovery_codes TEXT[],
        recovery_codes_hashed TEXT[],
        verified_at TIMESTAMP WITH TIME ZONE,
        CONSTRAINT unique_user_mfa UNIQUE (user_id)
      );

      ALTER TABLE mfa ADD COLUMN IF NOT EXISTS totp_secret_encrypted TEXT;
      ALTER TABLE mfa ADD COLUMN IF NOT EXISTS recovery_codes_hashed TEXT[];

      CREATE TABLE IF NOT EXISTS work_policy (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        start_time VARCHAR(10) NOT NULL,
        end_time VARCHAR(10) NOT NULL,
        timezone VARCHAR(100) NOT NULL DEFAULT 'Asia/Kolkata',
        city VARCHAR(255) NOT NULL,
        lat DOUBLE PRECISION NOT NULL,
        lng DOUBLE PRECISION NOT NULL,
        radius_km DOUBLE PRECISION NOT NULL DEFAULT 25.0,
        time_restriction_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        location_restriction_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        geofence_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        set_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT unique_user_work_policy UNIQUE (user_id)
      );

      ALTER TABLE work_policy ADD COLUMN IF NOT EXISTS time_restriction_enabled BOOLEAN DEFAULT TRUE;
      ALTER TABLE work_policy ADD COLUMN IF NOT EXISTS location_restriction_enabled BOOLEAN DEFAULT FALSE;
      ALTER TABLE work_policy ADD COLUMN IF NOT EXISTS geofence_enabled BOOLEAN DEFAULT FALSE;

      CREATE TABLE IF NOT EXISTS otps (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code VARCHAR(255) NOT NULL,
        purpose VARCHAR(50) NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        used BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS wallets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        wallet_id VARCHAR(100) NOT NULL UNIQUE,
        status VARCHAR(50) NOT NULL DEFAULT 'CREATING',
        key_references JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT unique_user_wallet UNIQUE (user_id)
      );

      CREATE TABLE IF NOT EXISTS access_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        lat DOUBLE PRECISION,
        lng DOUBLE PRECISION,
        allowed BOOLEAN NOT NULL,
        reason TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_event_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        event_type VARCHAR(100) NOT NULL,
        severity VARCHAR(50) NOT NULL DEFAULT 'INFO',
        ip_address VARCHAR(100),
        user_agent VARCHAR(255),
        details TEXT,
        previous_hash VARCHAR(64),
        entry_hash VARCHAR(64),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        chain VARCHAR(50) NOT NULL DEFAULT 'mst-testnet',
        tx_hash VARCHAR(255) NOT NULL UNIQUE,
        to_address VARCHAR(255) NOT NULL,
        amount VARCHAR(100) NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('[PostgreSQL] Database tables verified & initialized');
    return true;
  } catch (err: any) {
    isPgConnected = false;
    console.warn('[PostgreSQL] Database unavailable, falling back to atomic file store:', err.message);
    return false;
  } finally {
    if (client) client.release();
  }
}

export function getIsPgConnected(): boolean {
  return isPgConnected;
}
