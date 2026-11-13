-- Migration 006: Remove Guarded Break-Glass Recovery, Economic Security, and Device/Guardian tables
-- Drops recovery_records table and its indices cascade.
DROP TABLE IF EXISTS recovery_records CASCADE;

