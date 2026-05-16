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

const ledgerAdvisoryLockKey int64 = 0x46504c4544474552 // "FPLEDGER"

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
	pgtx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
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

func (t *pgStoreTx) LockLedger(ctx context.Context) error {
	_, err := t.pgtx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ledgerAdvisoryLockKey)
	return err
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

func (t *pgStoreTx) GetAccountsByDiscourseIDs(ctx context.Context, dids []int64) (map[int64]*ledger.Account, error) {
	out := make(map[int64]*ledger.Account, len(dids))
	if len(dids) == 0 {
		return out, nil
	}
	rows, err := t.pgtx.Query(ctx,
		`SELECT discourse_id, pubkey, username, nonce, balance
		   FROM accounts
		  WHERE discourse_id = ANY($1)`, dids,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a ledger.Account
		if err := rows.Scan(&a.DiscourseID, &a.Pubkey, &a.Username, &a.Nonce, &a.Balance); err != nil {
			return nil, err
		}
		out[a.DiscourseID] = &a
	}
	return out, rows.Err()
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
	fields, err := ledger.DeriveTxFields(tx.Type, tx.Payload)
	if err != nil {
		return err
	}
	var amountArg, toArg any
	if fields.Amount != nil {
		amountArg = *fields.Amount
	}
	if fields.ToDiscourseID != nil {
		toArg = *fields.ToDiscourseID
	}
	_, err = t.pgtx.Exec(ctx,
		`INSERT INTO transactions
		   (leaf_index, tx_type, payload, sig, signer, prev_hash, tx_hash,
		    amount, to_discourse_id, reward_source)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''))`,
		tx.LeafIndex, string(tx.Type), []byte(tx.Payload), tx.Sig, tx.Signer, tx.PrevHash, tx.TxHash,
		amountArg, toArg, fields.RewardSource,
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

// RewardEventExists returns true if a reward of (event_type, event_key) has
// already paid or is currently reserved by another worker.
func (s *PGStore) RewardEventExists(ctx context.Context, eventType, eventKey string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM reward_events WHERE event_type=$1 AND event_key=$2)`,
		eventType, eventKey,
	).Scan(&exists)
	return exists, err
}

// TryReserveRewardEvent atomically claims a reward event before the ledger
// transfer is signed. This prevents duplicate payouts when webhooks or backfills
// race on the same event key.
func (s *PGStore) TryReserveRewardEvent(ctx context.Context, eventType, eventKey string) (bool, error) {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM reward_events
		  WHERE event_type = $1
		    AND event_key = $2
		    AND tx_hash IS NULL
		    AND paid_at < now() - interval '15 minutes'`,
		eventType, eventKey,
	)
	if err != nil {
		return false, err
	}

	var reserved bool
	err = s.pool.QueryRow(ctx,
		`INSERT INTO reward_events (event_type, event_key)
		 VALUES ($1, $2)
		 ON CONFLICT (event_type, event_key) DO NOTHING
		 RETURNING true`,
		eventType, eventKey,
	).Scan(&reserved)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return reserved, err
}

func (s *PGStore) CompleteRewardEvent(ctx context.Context, eventType, eventKey string, txHash []byte) error {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO reward_events (event_type, event_key, tx_hash)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (event_type, event_key) DO UPDATE SET
		   tx_hash = COALESCE(reward_events.tx_hash, EXCLUDED.tx_hash),
		   paid_at = CASE WHEN reward_events.tx_hash IS NULL THEN now() ELSE reward_events.paid_at END
		 WHERE reward_events.tx_hash IS NULL OR reward_events.tx_hash = EXCLUDED.tx_hash`,
		eventType, eventKey, txHash,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("reward event already completed with a different tx_hash")
	}
	return nil
}

func (s *PGStore) ReleaseRewardEvent(ctx context.Context, eventType, eventKey string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM reward_events
		  WHERE event_type = $1
		    AND event_key = $2
		    AND tx_hash IS NULL`,
		eventType, eventKey,
	)
	return err
}

// RecordRewardEvent links the given tx_hash to a (event_type, event_key) dedup row.
// Must be called AFTER Apply succeeded (so tx_hash exists in transactions).
func (s *PGStore) RecordRewardEvent(ctx context.Context, eventType, eventKey string, txHash []byte) error {
	return s.CompleteRewardEvent(ctx, eventType, eventKey, txHash)
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
// accounts.pubkey for this discourse_id) or receiver (to_discourse_id == id).
// Hot fields are denormalized from the signed payload by migration 0005.
func (s *PGStore) UserHistory(ctx context.Context, discourseID int64, limit int) ([]HistoryRow, error) {
	rows, err := s.pool.Query(ctx, `
WITH me AS (SELECT pubkey FROM accounts WHERE discourse_id = $1)
SELECT t.leaf_index,
       t.tx_type,
       COALESCE(t.amount, 0)                                                                 AS amount,
       COALESCE(t.to_discourse_id, -1)                                                       AS to_did,
       encode(t.signer, 'hex')                                                                AS signer_hex,
       encode(t.tx_hash, 'hex')                                                               AS tx_hash_hex,
       (convert_from(t.payload, 'UTF8')::jsonb -> 'meta')                                     AS meta,
       to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')                AS created_at,
       COALESCE(a_from.discourse_id, -1)                                                      AS from_did,
       COALESCE(a_to.username, '')                                                            AS to_name,
       COALESCE(a_from.username, '')                                                          AS from_name
  FROM transactions t
  LEFT JOIN accounts a_from ON a_from.pubkey = t.signer
  LEFT JOIN accounts a_to   ON a_to.discourse_id = t.to_discourse_id
 WHERE t.tx_type IN ('transfer', 'rotate_key')
   AND (
        t.signer = (SELECT pubkey FROM me)
     OR t.to_discourse_id = $1
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
