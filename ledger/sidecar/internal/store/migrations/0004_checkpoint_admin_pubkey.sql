-- Record the admin public key that signed each checkpoint. Older rows are
-- backfilled by txlog when their signature verifies with the configured key.

ALTER TABLE checkpoints
    ADD COLUMN IF NOT EXISTS admin_pubkey BYTEA;
