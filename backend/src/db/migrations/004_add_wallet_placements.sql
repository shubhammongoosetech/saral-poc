-- Migration 004: Add wallet_placements table for Rendezvous (HRW) Hashing & Pinned Routing
-- Patent Paragraphs [0016], [0022] & Architectural Decision D-06

CREATE TABLE IF NOT EXISTS wallet_placements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  epoch INTEGER NOT NULL DEFAULT 1,
  foundation_nodes TEXT[] NOT NULL,
  public_nodes TEXT[] NOT NULL,
  private_nodes TEXT[] NOT NULL,
  foundation_threshold INTEGER NOT NULL,
  public_threshold INTEGER NOT NULL,
  private_threshold INTEGER NOT NULL,
  manifest_hash VARCHAR(64) NOT NULL,
  pinned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT unique_wallet_epoch UNIQUE (wallet_id, epoch)
);

CREATE INDEX IF NOT EXISTS idx_wallet_placements_wallet_id ON wallet_placements(wallet_id);
CREATE INDEX IF NOT EXISTS idx_wallet_placements_user_id ON wallet_placements(user_id);

