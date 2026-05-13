package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/forum-points/ledger/internal/ledger"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(ctx context.Context, dsn string) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &PGStore{pool: pool}, nil
}

func (s *PGStore) Pool() *pgxpool.Pool { return s.pool }
func (s *PGStore) Close()              { s.pool.Close() }

func (s *PGStore) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if isMigrationFile(e) {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, name := range files {
		var applied bool
		err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		sql, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		pgtx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := pgtx.Exec(ctx, string(sql)); err != nil {
			pgtx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := pgtx.Exec(ctx,
			`INSERT INTO schema_migrations(name) VALUES($1)`, name,
		); err != nil {
			pgtx.Rollback(ctx)
			return err
		}
		if err := pgtx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func isMigrationFile(e fs.DirEntry) bool {
	name := e.Name()
	return !e.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".sql")
}

func (s *PGStore) Begin(ctx context.Context) (ledger.StoreTx, error) {
	pgtx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	return &pgStoreTx{pgtx: pgtx}, nil
}

type pgStoreTx struct {
	pgtx pgx.Tx
	done bool
}

func (t *pgStoreTx) Commit(ctx context.Context) error {
	t.done = true
	return t.pgtx.Commit(ctx)
}

func (t *pgStoreTx) Rollback(ctx context.Context) error {
	if t.done {
		return nil
	}
	t.done = true
	return t.pgtx.Rollback(ctx)
}

func (t *pgStoreTx) GetAccountByPubKey(ctx context.Context, pubkey []byte) (*ledger.Account, error) {
	if len(pubkey) == 0 {
		return nil, nil
	}
	var a ledger.Account
	err := t.pgtx.QueryRow(ctx,
		`SELECT discourse_id, pubkey, username, nonce, balance
		   FROM accounts WHERE pubkey = $1`, pubkey,
	).Scan(&a.DiscourseID, &a.Pubkey, &a.Username, &a.Nonce, &a.Balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (t *pgStoreTx) GetAccountByDiscourseID(ctx context.Context, did int64) (*ledger.Account, error) {
	var a ledger.Account
	err := t.pgtx.QueryRow(ctx,
		`SELECT discourse_id, pubkey, username, nonce, balance
		   FROM accounts WHERE discourse_id = $1`, did,
	).Scan(&a.DiscourseID, &a.Pubkey, &a.Username, &a.Nonce, &a.Balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (t *pgStoreTx) UpsertAccount(ctx context.Context, a *ledger.Account) error {
	// pubkey may be nil. Use parameterized upsert keyed by discourse_id.
	var pubArg interface{}
	if len(a.Pubkey) > 0 {
		pubArg = a.Pubkey
	} else {
		pubArg = nil
	}
	_, err := t.pgtx.Exec(ctx,
		`INSERT INTO accounts (discourse_id, pubkey, username, nonce, balance)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (discourse_id) DO UPDATE SET
		   pubkey   = COALESCE(EXCLUDED.pubkey, accounts.pubkey),
		   username = CASE WHEN EXCLUDED.username = '(pending)' AND accounts.username <> '(pending)'
		                   THEN accounts.username ELSE EXCLUDED.username END,
		   nonce    = EXCLUDED.nonce,
		   balance  = EXCLUDED.balance`,
		a.DiscourseID, pubArg, a.Username, a.Nonce, a.Balance,
	)
	return err
}

func (t *pgStoreTx) UpdatePubKey(ctx context.Context, oldPub, newPub []byte) error {
	tag, err := t.pgtx.Exec(ctx,
		`UPDATE accounts SET pubkey = $2 WHERE pubkey = $1`, oldPub, newPub,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ledger.ErrUnknownAccount
	}
	return nil
}

func (t *pgStoreTx) UpdateUsernameAndPubKey(ctx context.Context, did int64, pubkey []byte, username string) error {
	tag, err := t.pgtx.Exec(ctx,
		`UPDATE accounts
		    SET pubkey = $2, username = $3, activated_at = now()
		  WHERE discourse_id = $1`,
		did, pubkey, username,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ledger.ErrUnknownAccount
	}
	return nil
}

func (t *pgStoreTx) LastTx(ctx context.Context) (*ledger.Tx, error) {
	var tx ledger.Tx
	var typ string
	err := t.pgtx.QueryRow(ctx,
		`SELECT leaf_index, tx_type, payload, sig, signer, prev_hash, tx_hash
		   FROM transactions
		   ORDER BY leaf_index DESC
		   LIMIT 1`,
	).Scan(&tx.LeafIndex, &typ, &tx.Payload, &tx.Sig, &tx.Signer, &tx.PrevHash, &tx.TxHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tx.Type = ledger.TxType(typ)
	return &tx, nil
}

func (t *pgStoreTx) InsertTx(ctx context.Context, tx *ledger.Tx) error {
	_, err := t.pgtx.Exec(ctx,
		`INSERT INTO transactions
		   (leaf_index, tx_type, payload, sig, signer, prev_hash, tx_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		tx.LeafIndex, string(tx.Type), []byte(tx.Payload), tx.Sig, tx.Signer, tx.PrevHash, tx.TxHash,
	)
	return err
}

func (t *pgStoreTx) GenesisExists(ctx context.Context) (bool, error) {
	var exists bool
	err := t.pgtx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM transactions WHERE tx_type='genesis')`,
	).Scan(&exists)
	return exists, err
}

func (t *pgStoreTx) TotalBalance(ctx context.Context) (int64, error) {
	var total int64
	err := t.pgtx.QueryRow(ctx,
		`SELECT COALESCE(SUM(balance), 0) FROM accounts`,
	).Scan(&total)
	return total, err
}

// --- reward dedup + config helpers (used by webhook handler, not by ledger.Apply) ---

// RewardEventExists returns true if a reward of (event_type, event_key) has already paid.
func (s *PGStore) RewardEventExists(ctx context.Context, eventType, eventKey string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM reward_events WHERE event_type=$1 AND event_key=$2)`,
		eventType, eventKey,
	).Scan(&exists)
	return exists, err
}

// RecordRewardEvent links the given tx_hash to a (event_type, event_key) dedup row.
// Must be called AFTER Apply succeeded (so tx_hash exists in transactions).
func (s *PGStore) RecordRewardEvent(ctx context.Context, eventType, eventKey string, txHash []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO reward_events (event_type, event_key, tx_hash)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (event_type, event_key) DO NOTHING`,
		eventType, eventKey, txHash,
	)
	return err
}

func (s *PGStore) GetRewardAmount(ctx context.Context, eventType string) (int64, bool, error) {
	var amt int64
	var enabled bool
	err := s.pool.QueryRow(ctx,
		`SELECT amount, enabled FROM reward_config WHERE event_type=$1`, eventType,
	).Scan(&amt, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return amt, enabled, nil
}

// HistoryRow is the raw shape we return from UserHistory. Caller-side (api.HistoryQuerier)
// receives a more user-facing struct; we keep this internal type minimal.
type HistoryRow struct {
	LeafIndex        int64
	TxType           string
	Amount           int64
	FromDscID        int64
	ToDscID          int64
	SignerHex        string
	CounterpartyName string
	Meta             []byte
	CreatedAt        string
	TxHashHex        string
}

// UserHistory returns transactions where the user is sender (signer pubkey ==
// accounts.pubkey for this discourse_id) or receiver (payload.to_discourse_id == id).
// Uses an on-the-fly JSON parse over the BYTEA payload — fine at our scale.
func (s *PGStore) UserHistory(ctx context.Context, discourseID int64, limit int) ([]HistoryRow, error) {
	rows, err := s.pool.Query(ctx, `
WITH me AS (SELECT pubkey FROM accounts WHERE discourse_id = $1)
SELECT t.leaf_index,
       t.tx_type,
       COALESCE((convert_from(t.payload, 'UTF8')::jsonb ->> 'amount')::bigint, 0)            AS amount,
       COALESCE((convert_from(t.payload, 'UTF8')::jsonb ->> 'to_discourse_id')::bigint, -1)  AS to_did,
       encode(t.signer, 'hex')                                                                AS signer_hex,
       encode(t.tx_hash, 'hex')                                                               AS tx_hash_hex,
       (convert_from(t.payload, 'UTF8')::jsonb -> 'meta')                                     AS meta,
       to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')                AS created_at,
       COALESCE(a_from.discourse_id, -1)                                                      AS from_did,
       COALESCE(a_to.username, '')                                                            AS to_name,
       COALESCE(a_from.username, '')                                                          AS from_name
  FROM transactions t
  LEFT JOIN accounts a_from ON a_from.pubkey = t.signer
  LEFT JOIN accounts a_to   ON a_to.discourse_id = COALESCE((convert_from(t.payload, 'UTF8')::jsonb ->> 'to_discourse_id')::bigint, -1)
 WHERE t.tx_type IN ('transfer', 'rotate_key')
   AND (
        t.signer = (SELECT pubkey FROM me)
     OR COALESCE((convert_from(t.payload, 'UTF8')::jsonb ->> 'to_discourse_id')::bigint, -1) = $1
       )
 ORDER BY t.leaf_index DESC
 LIMIT $2`,
		discourseID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryRow
	for rows.Next() {
		var r HistoryRow
		var toName, fromName string
		if err := rows.Scan(
			&r.LeafIndex, &r.TxType, &r.Amount, &r.ToDscID,
			&r.SignerHex, &r.TxHashHex, &r.Meta, &r.CreatedAt,
			&r.FromDscID, &toName, &fromName,
		); err != nil {
			return nil, err
		}
		// Decide counterparty name relative to `discourseID`
		if r.FromDscID == discourseID {
			r.CounterpartyName = toName
		} else {
			r.CounterpartyName = fromName
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
