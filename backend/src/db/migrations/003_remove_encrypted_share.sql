-- Migration 003: Remove encrypted_share from key_shares
-- Shares are stored EXCLUSIVELY inside Docker containers.
-- The DB only tracks metadata (container_id, container_name).

-- 1. Drop the encrypted_share column — no key material in the DB
ALTER TABLE key_shares DROP COLUMN IF EXISTS encrypted_share;

-- 2. Make container columns NOT NULL (they were nullable in migration 002)
ALTER TABLE key_shares
  ALTER COLUMN container_id   SET NOT NULL,
  ALTER COLUMN container_name SET NOT NULL;

COMMENT ON TABLE key_shares IS
  'Tracks which Docker container holds each Shamir share. '
  'No cryptographic material is stored in this table.';

