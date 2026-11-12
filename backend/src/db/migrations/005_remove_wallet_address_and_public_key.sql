-- Migration 005: Remove Wallet Address and Public Key from Persistent Storage
-- Requirement: No public key and no wallet address may be stored anywhere.
-- They are regenerated (derived) at every login from the key shares held by the nodes.

-- 1. Ensure wallet_placements has the required metadata columns from wallets
ALTER TABLE wallet_placements
  ADD COLUMN IF NOT EXISTS protocol_version VARCHAR(50) NOT NULL DEFAULT 'MPC-secp256k1-v1',
  ADD COLUMN IF NOT EXISTS threshold INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS n INTEGER NOT NULL DEFAULT 9,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- 2. Backfill metadata from wallets to wallet_placements if table wallets exists
DO $$
BEGIN
  IF EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'wallets') THEN
    UPDATE wallet_placements wp
    SET protocol_version = COALESCE(w.protocol_version, 'MPC-secp256k1-v1'),
        threshold = COALESCE(w.threshold, 5),
        n = COALESCE(w.n, 9),
        created_at = COALESCE(w.created_at, CURRENT_TIMESTAMP)
    FROM wallets w
    WHERE wp.wallet_id = w.id;
  END IF;
END $$;

-- 3. Update constraints on wallet_placements: remove wallet_id foreign key, key by user_id
ALTER TABLE wallet_placements DROP CONSTRAINT IF EXISTS wallet_placements_wallet_id_fkey;
ALTER TABLE wallet_placements DROP CONSTRAINT IF EXISTS unique_wallet_epoch;
ALTER TABLE wallet_placements DROP COLUMN IF EXISTS wallet_id;

-- Ensure user_id is UNIQUE per epoch, and add unique constraint on user_id
ALTER TABLE wallet_placements DROP CONSTRAINT IF EXISTS unique_user_epoch;
ALTER TABLE wallet_placements ADD CONSTRAINT unique_user_epoch UNIQUE (user_id, epoch);

DROP INDEX IF EXISTS idx_wallet_placements_wallet_id;
CREATE INDEX IF NOT EXISTS idx_wallet_placements_user_id ON wallet_placements(user_id);

-- 4. Drop table wallets completely (contains address and public_key)
DROP TABLE IF EXISTS wallets CASCADE;

-- 5. Scrub any historical address or public key occurrences from text log tables
UPDATE access_logs
SET reason = REGEXP_REPLACE(reason, '0x[a-fA-F0-9]{40}', '[REDACTED_ADDRESS]', 'g')
WHERE reason ~ '0x[a-fA-F0-9]{40}';

UPDATE access_logs
SET reason = REGEXP_REPLACE(reason, '0x?0[23][a-fA-F0-9]{64}', '[REDACTED_PUBKEY]', 'g')
WHERE reason ~ '0x?0[23][a-fA-F0-9]{64}';

UPDATE access_logs
SET reason = REGEXP_REPLACE(reason, '0x?04[a-fA-F0-9]{128}', '[REDACTED_PUBKEY]', 'g')
WHERE reason ~ '0x?04[a-fA-F0-9]{128}';

UPDATE security_event_logs
SET details = REGEXP_REPLACE(details, '0x[a-fA-F0-9]{40}', '[REDACTED_ADDRESS]', 'g')
WHERE details ~ '0x[a-fA-F0-9]{40}';

UPDATE security_event_logs
SET details = REGEXP_REPLACE(details, '0x?0[23][a-fA-F0-9]{64}', '[REDACTED_PUBKEY]', 'g')
WHERE details ~ '0x?0[23][a-fA-F0-9]{64}';

UPDATE security_event_logs
SET details = REGEXP_REPLACE(details, '0x?04[a-fA-F0-9]{128}', '[REDACTED_PUBKEY]', 'g')
WHERE details ~ '0x?04[a-fA-F0-9]{128}';

UPDATE recovery_records
SET reason = REGEXP_REPLACE(reason, '0x[a-fA-F0-9]{40}', '[REDACTED_ADDRESS]', 'g')
WHERE reason ~ '0x[a-fA-F0-9]{40}';

UPDATE recovery_records
SET authorized_custodians = REGEXP_REPLACE(authorized_custodians, '0x[a-fA-F0-9]{40}', '[REDACTED_ADDRESS]', 'g')
WHERE authorized_custodians ~ '0x[a-fA-F0-9]{40}';

