-- SARAL Protocol — Database Cleanup Migration
-- Removes unused 'transactions' table and obsolete plaintext MFA fields
-- Enforces Zero-Persistence & Minimal Relational Architecture

-- 1. Drop unused legacy table 'transactions'
DROP TABLE IF EXISTS "transactions" CASCADE;

-- 2. Drop obsolete plaintext columns from 'mfa' table
ALTER TABLE "mfa" DROP COLUMN IF EXISTS "secret";
ALTER TABLE "mfa" DROP COLUMN IF EXISTS "recovery_codes";

