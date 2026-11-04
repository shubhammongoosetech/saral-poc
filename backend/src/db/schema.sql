-- SARAL Wallet PostgreSQL Database Schema
-- Patent Architecture Aligned: Zero-Key Storage & Separation of Powers

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  google_id VARCHAR(255) UNIQUE,
  email VARCHAR(255) UNIQUE,
  mobile VARCHAR(50) UNIQUE,
  login_method VARCHAR(50) NOT NULL, -- 'google' | 'mobile'
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL DEFAULT 'otp', -- 'otp' | 'totp'
  verified_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT unique_user_mfa UNIQUE (user_id)
);

CREATE TABLE IF NOT EXISTS work_policy (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  start_time VARCHAR(10) NOT NULL, -- '10:00'
  end_time VARCHAR(10) NOT NULL,   -- '18:00'
  timezone VARCHAR(100) NOT NULL DEFAULT 'Asia/Kolkata',
  city VARCHAR(255) NOT NULL,
  lat DOUBLE PRECISION NOT NULL,
  lng DOUBLE PRECISION NOT NULL,
  radius_km DOUBLE PRECISION NOT NULL DEFAULT 25.0,
  set_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_user_work_policy UNIQUE (user_id)
);

CREATE TABLE IF NOT EXISTS wallets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  address VARCHAR(255) NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  protocol_version VARCHAR(50) NOT NULL DEFAULT 'MPC-secp256k1-v1',
  threshold INTEGER NOT NULL DEFAULT 5,
  n INTEGER NOT NULL DEFAULT 9,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_shares (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category       VARCHAR(50)  NOT NULL, -- 'FOUNDATION' | 'PUBLIC' | 'PRIVATE' (or legacy 'INSTITUTIONAL' | 'SOVEREIGN')
  share_index    INTEGER      NOT NULL,
  n              INTEGER      NOT NULL DEFAULT 9,
  threshold      INTEGER      NOT NULL DEFAULT 5,
  -- Cryptographic share lives ONLY in container/node vault - NEVER in PostgreSQL!
  container_id   VARCHAR(100) NOT NULL,
  container_name VARCHAR(255) NOT NULL,
  created_at     TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_user_category_share UNIQUE (user_id, category, share_index)
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

CREATE TABLE IF NOT EXISTS recovery_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  request_id VARCHAR(100) NOT NULL UNIQUE,
  state VARCHAR(50) NOT NULL DEFAULT 'PENDING_TIMELOCK',
  timelock_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  authorized_custodians TEXT,
  reason TEXT,
  executed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tx_hash VARCHAR(255) NOT NULL UNIQUE,
  to_address VARCHAR(255) NOT NULL,
  amount VARCHAR(100) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'BROADCASTED',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS otps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(255) NOT NULL,
  purpose VARCHAR(50) NOT NULL, -- 'login' | 'mfa'
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indices for high performance
CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets(address);
CREATE INDEX IF NOT EXISTS idx_key_shares_user_id ON key_shares(user_id);
CREATE INDEX IF NOT EXISTS idx_key_shares_container_name ON key_shares(container_name);
CREATE INDEX IF NOT EXISTS idx_access_logs_user_id ON access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_logs_user_event ON security_event_logs(user_id, event_type);
CREATE INDEX IF NOT EXISTS idx_recovery_records_user_state ON recovery_records(user_id, state);
CREATE INDEX IF NOT EXISTS idx_otps_user_purpose ON otps(user_id, purpose, used);
