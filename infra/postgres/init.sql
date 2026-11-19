-- SARAL Protocol — PostgreSQL Initialization & Migration Schema
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

-- Additional models for Prisma ORM integration
CREATE TABLE IF NOT EXISTS auth_identities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,
  provider_id VARCHAR(255) NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_provider_identity UNIQUE (provider, provider_id)
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mfa_id UUID NOT NULL REFERENCES mfa(id) ON DELETE CASCADE,
  code_hash VARCHAR(64) NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  used_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_jti VARCHAR(255) NOT NULL UNIQUE,
  mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ip_address VARCHAR(100),
  user_agent VARCHAR(255),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wallet_key_references (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id VARCHAR(100) NOT NULL REFERENCES wallets(wallet_id) ON DELETE CASCADE,
  chain VARCHAR(50) NOT NULL,
  key_ref VARCHAR(100) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_wallet_chain UNIQUE (wallet_id, chain)
);

CREATE TABLE IF NOT EXISTS wallet_creation_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
  error TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed key references for pre-seeded wallet
INSERT INTO wallet_key_references (wallet_id, chain, key_ref, status)
VALUES
  ('wal-aa583bf2-9e66-415b-90c6-d8eda93bd540', 'mst', 'key-mst-7d57a501e008f36f', 'ACTIVE'),
  ('wal-aa583bf2-9e66-415b-90c6-d8eda93bd540', 'solana', 'key-sol-b06a5d5b49696a4f', 'ACTIVE'),
  ('wal-aa583bf2-9e66-415b-90c6-d8eda93bd540', 'bitcoin', 'key-btc-48ea9f6ba5a7de2a', 'ACTIVE')
ON CONFLICT (wallet_id, chain) DO NOTHING;

-- Preserve existing user and wallet metadata
INSERT INTO users (id, name, google_id, email, mobile, login_method, created_at)
VALUES (
  'b79f86f3-44a6-48f9-be43-a1abb6456172',
  'SARAL Operator',
  NULL,
  NULL,
  '+919825669385',
  'mobile',
  '2026-11-18T21:12:58.163Z'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO wallets (id, user_id, wallet_id, status, key_references, created_at, updated_at)
VALUES (
  '3d2e140d-dd97-403e-9ed4-da6f17669b55',
  'b79f86f3-44a6-48f9-be43-a1abb6456172',
  'wal-aa583bf2-9e66-415b-90c6-d8eda93bd540',
  'READY',
  '{"mst": "key-mst-7d57a501e008f36f", "solana": "key-sol-b06a5d5b49696a4f", "bitcoin": "key-btc-48ea9f6ba5a7de2a"}'::jsonb,
  '2026-11-18T21:12:58.294Z',
  '2026-11-18T21:12:58.294Z'
) ON CONFLICT (user_id) DO NOTHING;

INSERT INTO work_policy (id, user_id, start_time, end_time, timezone, city, lat, lng, radius_km, time_restriction_enabled, location_restriction_enabled, geofence_enabled, set_at)
VALUES (
  '66336ce6-4ec7-40c6-a3de-3019061e6d7b',
  'b79f86f3-44a6-48f9-be43-a1abb6456172',
  '00:00',
  '23:59',
  'Asia/Kolkata',
  'Indore',
  22.7196,
  75.8577,
  50.0,
  TRUE,
  FALSE,
  FALSE,
  '2026-11-18T21:12:58.360Z'
) ON CONFLICT (user_id) DO NOTHING;
