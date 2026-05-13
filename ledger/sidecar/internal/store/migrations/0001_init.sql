-- forum-points-ledger schema 0001_init (v2: pubkey nullable, discourse_id is primary identity)
--
-- 单位:1 pt 原子,无小数;固定总量 50_000_000。
-- accounts 可以先由"管理员转账激活"创建,pubkey 为空;用户首次发起转账时通过
-- /me/register 绑定 pubkey。

CREATE TABLE accounts (
    discourse_id BIGINT PRIMARY KEY,                   -- 0 = treasury, >0 = real user
    pubkey       BYTEA UNIQUE,                         -- NULL until user activates
    username     TEXT NOT NULL DEFAULT '(pending)',
    nonce        BIGINT NOT NULL DEFAULT 0,
    balance      BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ
);

CREATE INDEX accounts_pubkey_idx ON accounts (pubkey) WHERE pubkey IS NOT NULL;

CREATE TABLE transactions (
    leaf_index   BIGINT PRIMARY KEY,
    tx_type      TEXT NOT NULL CHECK (tx_type IN
                  ('genesis','transfer','rotate_key','reclaim_invalid','rotate_admin','reward_config')),
    payload      BYTEA NOT NULL,                    -- raw canonical-JSON bytes (signature byte-equal)
    sig          BYTEA NOT NULL,
    signer       BYTEA NOT NULL,
    prev_hash    BYTEA NOT NULL,
    tx_hash      BYTEA NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX transactions_signer_idx ON transactions (signer);
CREATE INDEX transactions_created_at_idx ON transactions (created_at);

CREATE UNIQUE INDEX one_genesis ON transactions ((tx_type = 'genesis'))
    WHERE tx_type = 'genesis';

CREATE TABLE checkpoints (
    tree_size    BIGINT PRIMARY KEY,
    root_hash    BYTEA NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    admin_sig    BYTEA NOT NULL,
    ots_receipt  BYTEA,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Reward dedup table: same event must not pay twice.
CREATE TABLE reward_events (
    event_type TEXT NOT NULL,                          -- 'signup_bonus','first_post_ever','quality_post','backfill'
    event_key  TEXT NOT NULL,                          -- 'user:42', 'post:1234', 'user:42:backfill:v1'
    tx_hash    BYTEA NOT NULL REFERENCES transactions(tx_hash),
    paid_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_type, event_key)
);

-- Hot-tunable reward amounts.
CREATE TABLE reward_config (
    event_type TEXT PRIMARY KEY,
    amount     BIGINT NOT NULL CHECK (amount >= 0),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO reward_config (event_type, amount, enabled) VALUES
    ('signup_bonus',     100, true),
    ('first_post_ever',   50, true),
    ('quality_post',     500, true)
ON CONFLICT (event_type) DO NOTHING;
