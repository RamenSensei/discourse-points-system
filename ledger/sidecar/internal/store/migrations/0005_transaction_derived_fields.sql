-- Denormalized fields for high-volume history and recent-transaction reads.
-- The canonical payload remains the signed source of truth; these columns are
-- derived indexes so hot read paths do not repeatedly parse JSON from BYTEA.

ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS amount BIGINT,
    ADD COLUMN IF NOT EXISTS to_discourse_id BIGINT,
    ADD COLUMN IF NOT EXISTS reward_source TEXT;

UPDATE transactions
   SET amount = CASE
           WHEN tx_type IN ('transfer', 'reclaim_invalid')
           THEN (convert_from(payload, 'UTF8')::jsonb ->> 'amount')::bigint
           ELSE amount
       END,
       to_discourse_id = CASE
           WHEN tx_type = 'transfer'
           THEN (convert_from(payload, 'UTF8')::jsonb ->> 'to_discourse_id')::bigint
           ELSE to_discourse_id
       END,
       reward_source = NULLIF(convert_from(payload, 'UTF8')::jsonb -> 'meta' ->> 'reward_source', '')
 WHERE (tx_type IN ('transfer', 'reclaim_invalid') AND amount IS NULL)
    OR (tx_type = 'transfer' AND to_discourse_id IS NULL)
    OR reward_source IS NULL;

CREATE INDEX IF NOT EXISTS transactions_signer_leaf_desc_idx
    ON transactions (signer, leaf_index DESC);

CREATE INDEX IF NOT EXISTS transactions_to_discourse_leaf_desc_idx
    ON transactions (to_discourse_id, leaf_index DESC)
    WHERE to_discourse_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS transactions_leaf_desc_idx
    ON transactions (leaf_index DESC);

CREATE INDEX IF NOT EXISTS accounts_balance_desc_idx
    ON accounts (balance DESC);
