-- Migration 002: Add Docker container metadata to key_shares
-- Each share is stored inside a dedicated Docker container.
-- These columns track which container holds which share.

ALTER TABLE key_shares
  ADD COLUMN IF NOT EXISTS container_id   VARCHAR(100),
  ADD COLUMN IF NOT EXISTS container_name VARCHAR(255);

-- Index for fast container lookup by name
CREATE INDEX IF NOT EXISTS idx_key_shares_container_name ON key_shares(container_name);

COMMENT ON COLUMN key_shares.container_id   IS 'Docker container short ID (12-char) that holds this share';
COMMENT ON COLUMN key_shares.container_name IS 'Deterministic Docker container name: saral-share-{userId8}-{category}-{index}';

