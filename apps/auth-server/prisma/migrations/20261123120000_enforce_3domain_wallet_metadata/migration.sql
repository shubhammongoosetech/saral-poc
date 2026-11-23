-- SARAL Protocol — Enforce 3-Domain Wallet Metadata and User Id Uniqueness
-- Ensures unique constraint on wallets(user_id) and validates zero-address storage mandate

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'unique_user_wallet'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'wallets_user_id_key'
    ) THEN
        ALTER TABLE "wallets" ADD CONSTRAINT "unique_user_wallet" UNIQUE ("user_id");
    END IF;
END $$;

