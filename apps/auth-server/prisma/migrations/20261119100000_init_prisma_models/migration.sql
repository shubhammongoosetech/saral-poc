-- SARAL Protocol — Initial Prisma Migration
-- Preserves existing user, wallet, mfa, and policy data while introducing Prisma model relations

-- CreateTable
CREATE TABLE IF NOT EXISTS "auth_identities" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "provider" VARCHAR(50) NOT NULL,
    "provider_id" VARCHAR(255) NOT NULL,
    "metadata" JSONB DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_identities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE IF NOT EXISTS "mfa_recovery_codes" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "mfa_id" UUID NOT NULL,
    "code_hash" VARCHAR(64) NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "used_at" TIMESTAMPTZ(6),

    CONSTRAINT "mfa_recovery_codes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE IF NOT EXISTS "auth_sessions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "token_jti" VARCHAR(255) NOT NULL,
    "mfa_verified" BOOLEAN NOT NULL DEFAULT false,
    "ip_address" VARCHAR(100),
    "user_agent" VARCHAR(255),
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE IF NOT EXISTS "wallet_key_references" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "wallet_id" VARCHAR(100) NOT NULL,
    "chain" VARCHAR(50) NOT NULL,
    "key_ref" VARCHAR(100) NOT NULL,
    "status" VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "wallet_key_references_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE IF NOT EXISTS "wallet_creation_jobs" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "status" VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    "error" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "wallet_creation_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "auth_identities_user_id_idx" ON "auth_identities"("user_id");
CREATE UNIQUE INDEX IF NOT EXISTS "auth_identities_provider_provider_id_key" ON "auth_identities"("provider", "provider_id");

CREATE INDEX IF NOT EXISTS "mfa_recovery_codes_mfa_id_idx" ON "mfa_recovery_codes"("mfa_id");

CREATE UNIQUE INDEX IF NOT EXISTS "auth_sessions_token_jti_key" ON "auth_sessions"("token_jti");
CREATE INDEX IF NOT EXISTS "auth_sessions_user_id_idx" ON "auth_sessions"("user_id");

CREATE UNIQUE INDEX IF NOT EXISTS "wallet_key_references_wallet_id_chain_key" ON "wallet_key_references"("wallet_id", "chain");

CREATE INDEX IF NOT EXISTS "wallet_creation_jobs_user_id_idx" ON "wallet_creation_jobs"("user_id");

CREATE INDEX IF NOT EXISTS "access_logs_user_id_idx" ON "access_logs"("user_id");
CREATE INDEX IF NOT EXISTS "otps_user_id_purpose_idx" ON "otps"("user_id", "purpose");
CREATE INDEX IF NOT EXISTS "security_event_logs_user_id_idx" ON "security_event_logs"("user_id");
CREATE INDEX IF NOT EXISTS "transactions_user_id_idx" ON "transactions"("user_id");

-- Foreign Keys (idempotent addition)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'auth_identities_user_id_fkey') THEN
        ALTER TABLE "auth_identities" ADD CONSTRAINT "auth_identities_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mfa_recovery_codes_mfa_id_fkey') THEN
        ALTER TABLE "mfa_recovery_codes" ADD CONSTRAINT "mfa_recovery_codes_mfa_id_fkey" FOREIGN KEY ("mfa_id") REFERENCES "mfa"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'auth_sessions_user_id_fkey') THEN
        ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wallet_key_references_wallet_id_fkey') THEN
        ALTER TABLE "wallet_key_references" ADD CONSTRAINT "wallet_key_references_wallet_id_fkey" FOREIGN KEY ("wallet_id") REFERENCES "wallets"("wallet_id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wallet_creation_jobs_user_id_fkey') THEN
        ALTER TABLE "wallet_creation_jobs" ADD CONSTRAINT "wallet_creation_jobs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;
