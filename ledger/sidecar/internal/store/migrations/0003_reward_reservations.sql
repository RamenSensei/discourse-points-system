-- Allow reward_events to be reserved before the ledger tx is applied.
-- A NULL tx_hash means "in flight"; completed rows still point at the tx.

ALTER TABLE reward_events
    ALTER COLUMN tx_hash DROP NOT NULL;

CREATE INDEX IF NOT EXISTS reward_events_pending_idx
    ON reward_events (paid_at)
    WHERE tx_hash IS NULL;
