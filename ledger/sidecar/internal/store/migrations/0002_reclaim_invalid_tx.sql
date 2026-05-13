ALTER TABLE transactions DROP CONSTRAINT transactions_tx_type_check;

ALTER TABLE transactions ADD CONSTRAINT transactions_tx_type_check
    CHECK (tx_type IN
           ('genesis','transfer','rotate_key','reclaim_invalid','rotate_admin','reward_config'));
