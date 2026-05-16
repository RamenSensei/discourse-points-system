// Package txlog wires the on-disk transaction table to the RFC 6962 Merkle
// tree and the admin-signed Tree Head.
//
//	leaf_bytes[i] = transactions.tx_hash[i]    (32 bytes, already collision-resistant)
//	leaf_hash[i]  = SHA-256(0x00 || leaf_bytes[i])
//
// The verifier fetches the full tx (payload/sig/signer/prev_hash) from
// GET /log/leaves and re-derives leaf_bytes by recomputing the tx hash, then
// re-derives leaf_hash, and verifies inclusion against the signed STH.
package txlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/forum-points/ledger/internal/merkle"
)

// LeafRecord is what /log/leaves emits per entry. All byte fields are hex.
type LeafRecord struct {
	LeafIndex int64  `json:"leaf_index"`
	TxType    string `json:"tx_type"`
	Payload   string `json:"payload_b64"`
	Sig       string `json:"sig_hex"`
	Signer    string `json:"signer_hex"`
	PrevHash  string `json:"prev_hash_hex"`
	TxHash    string `json:"tx_hash_hex"`
	CreatedAt string `json:"created_at"`
}

// STH = Signed Tree Head.
type STH struct {
	TreeSize    int64  `json:"tree_size"`
	RootHash    string `json:"root_hash_hex"`
	TimestampMS int64  `json:"timestamp_ms"`
	AdminSig    string `json:"admin_sig_hex"`
	AdminPubKey string `json:"admin_pubkey_hex"`
}

// Service implements the txlog endpoints. Pool is the pgx pool for fetching
// leaves; AdminPrivKey signs STHs.
type Service struct {
	Pool         *pgxpool.Pool
	AdminPrivKey ed25519.PrivateKey
	AdminPubKey  ed25519.PublicKey
	mu           sync.Mutex
	snapshot     *merkleSnapshot
}

type merkleSnapshot struct {
	TreeSize   int64
	TxHashes   [][]byte
	LeafHashes [][]byte
	RootHash   []byte
}

// AllTxHashes returns all tx_hash bytes in leaf_index order.
func (s *Service) AllTxHashes(ctx context.Context) ([][]byte, error) {
	snap, err := s.merkleSnapshot(ctx, -1)
	if err != nil {
		return nil, err
	}
	return snap.TxHashes, nil
}

// RangeLeaves returns full leaf records for [from, to). Use -1 for "no limit".
func (s *Service) RangeLeaves(ctx context.Context, from, to int64) ([]LeafRecord, error) {
	query := `SELECT leaf_index, tx_type,
	                 encode(payload, 'base64'),
	                 encode(sig, 'hex'),
	                 encode(signer, 'hex'),
	                 encode(prev_hash, 'hex'),
	                 encode(tx_hash, 'hex'),
	                 to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	            FROM transactions
	            WHERE leaf_index >= $1
	            AND ($2 < 0 OR leaf_index < $2)
	            ORDER BY leaf_index ASC
	            LIMIT 10000`
	rows, err := s.Pool.Query(ctx, query, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LeafRecord
	for rows.Next() {
		var r LeafRecord
		if err := rows.Scan(&r.LeafIndex, &r.TxType, &r.Payload, &r.Sig, &r.Signer, &r.PrevHash, &r.TxHash, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CurrentSTH computes the root of the current tree and signs it.
func (s *Service) CurrentSTH(ctx context.Context) (*STH, error) {
	snap, err := s.merkleSnapshot(ctx, -1)
	if err != nil {
		return nil, err
	}
	return s.persistCheckpoint(ctx, snap.TreeSize, snap.RootHash)
}

func (s *Service) CurrentTreeSize(ctx context.Context) (int64, error) {
	var size int64
	err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(leaf_index) + 1, 0) FROM transactions`,
	).Scan(&size)
	return size, err
}

func (s *Service) LeafHashes(ctx context.Context, treeSize int64) ([][]byte, error) {
	snap, err := s.merkleSnapshot(ctx, treeSize)
	if err != nil {
		return nil, err
	}
	return snap.LeafHashes, nil
}

func (s *Service) merkleSnapshot(ctx context.Context, treeSize int64) (*merkleSnapshot, error) {
	target := treeSize
	if target < 0 {
		var err error
		target, err = s.CurrentTreeSize(ctx)
		if err != nil {
			return nil, err
		}
	}
	if target < 0 {
		return nil, fmt.Errorf("bad tree size %d", target)
	}

	s.mu.Lock()
	cached := s.snapshot
	if cached != nil && target <= cached.TreeSize {
		out := &merkleSnapshot{
			TreeSize:   target,
			TxHashes:   cached.TxHashes[:target],
			LeafHashes: cached.LeafHashes[:target],
			RootHash:   merkle.RootFromLeafHashes(cached.LeafHashes[:target]),
		}
		s.mu.Unlock()
		return out, nil
	}

	start := int64(0)
	var txHashes [][]byte
	var leafHashes [][]byte
	if cached != nil {
		start = cached.TreeSize
		txHashes = append(txHashes, cached.TxHashes...)
		leafHashes = append(leafHashes, cached.LeafHashes...)
	}
	s.mu.Unlock()

	if start < target {
		rows, err := s.Pool.Query(ctx,
			`SELECT leaf_index, tx_hash
			   FROM transactions
			  WHERE leaf_index >= $1 AND leaf_index < $2
			  ORDER BY leaf_index ASC`,
			start, target,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		next := start
		for rows.Next() {
			var idx int64
			var h []byte
			if err := rows.Scan(&idx, &h); err != nil {
				return nil, err
			}
			if idx != next {
				return nil, fmt.Errorf("transaction log gap at leaf_index=%d, got %d", next, idx)
			}
			txHashes = append(txHashes, h)
			leafHashes = append(leafHashes, merkle.LeafHash(h))
			next++
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if next != target {
			return nil, fmt.Errorf("transaction log ended at %d, want tree_size=%d", next, target)
		}
	}

	snap := &merkleSnapshot{
		TreeSize:   target,
		TxHashes:   txHashes,
		LeafHashes: leafHashes,
		RootHash:   merkle.RootFromLeafHashes(leafHashes),
	}
	s.mu.Lock()
	if s.snapshot == nil || snap.TreeSize >= s.snapshot.TreeSize {
		s.snapshot = snap
	}
	s.mu.Unlock()
	return snap, nil
}

func (s *Service) persistCheckpoint(ctx context.Context, treeSize int64, root []byte) (*STH, error) {
	ts := time.Now().UnixMilli()
	sig := ed25519.Sign(s.AdminPrivKey, signedSTHBytes(treeSize, root, ts))

	var storedRoot, storedSig, storedPub []byte
	var storedTS int64
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO checkpoints (tree_size, root_hash, timestamp_ms, admin_sig, admin_pubkey)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (tree_size) DO NOTHING
		 RETURNING root_hash, timestamp_ms, admin_sig, admin_pubkey`,
		treeSize, root, ts, sig, []byte(s.AdminPubKey),
	).Scan(&storedRoot, &storedTS, &storedSig, &storedPub)
	if err != nil {
		if err != pgx.ErrNoRows {
			return nil, fmt.Errorf("persist checkpoint: %w", err)
		}
		err = s.Pool.QueryRow(ctx,
			`SELECT root_hash, timestamp_ms, admin_sig, admin_pubkey
			   FROM checkpoints
			  WHERE tree_size = $1`,
			treeSize,
		).Scan(&storedRoot, &storedTS, &storedSig, &storedPub)
		if err != nil {
			return nil, fmt.Errorf("load checkpoint: %w", err)
		}
	}

	if !bytes.Equal(storedRoot, root) {
		return nil, fmt.Errorf("checkpoint tree_size=%d has root %s, current root is %s", treeSize, hex(storedRoot), hex(root))
	}
	storedPub, err = s.checkpointPubKey(ctx, treeSize, storedRoot, storedTS, storedSig, storedPub)
	if err != nil {
		return nil, err
	}

	return &STH{
		TreeSize:    treeSize,
		RootHash:    hex(storedRoot),
		TimestampMS: storedTS,
		AdminSig:    hex(storedSig),
		AdminPubKey: hex(storedPub),
	}, nil
}

// CheckpointSummary is a public-facing row from the checkpoints table.
// Receipt bytes are not exposed (large + only meaningful with OTS tooling);
// the boolean indicates whether an OTS receipt has been stored.
type CheckpointSummary struct {
	TreeSize      int64  `json:"tree_size"`
	RootHash      string `json:"root_hash_hex"`
	TimestampMS   int64  `json:"timestamp_ms"`
	AdminSig      string `json:"admin_sig_hex"`
	AdminPubKey   string `json:"admin_pubkey_hex"`
	HasOTSReceipt bool   `json:"has_ots_receipt"`
}

// Checkpoints returns the most recent `limit` STH checkpoints in descending
// tree_size order. Public — any third party can browse to monitor the log.
func (s *Service) Checkpoints(ctx context.Context, limit int) ([]CheckpointSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT tree_size, root_hash, timestamp_ms, admin_sig, admin_pubkey, ots_receipt IS NOT NULL
		   FROM checkpoints
		  ORDER BY tree_size DESC
		  LIMIT $1`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckpointSummary
	for rows.Next() {
		var size int64
		var root, sig, pub []byte
		var ts int64
		var hasOTS bool
		if err := rows.Scan(&size, &root, &ts, &sig, &pub, &hasOTS); err != nil {
			return nil, err
		}
		if len(pub) == 0 {
			pub, err = s.checkpointPubKey(ctx, size, root, ts, sig, pub)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, CheckpointSummary{
			TreeSize:      size,
			RootHash:      hex(root),
			TimestampMS:   ts,
			AdminSig:      hex(sig),
			AdminPubKey:   hex(pub),
			HasOTSReceipt: hasOTS,
		})
	}
	return out, rows.Err()
}

func (s *Service) checkpointPubKey(ctx context.Context, treeSize int64, root []byte, tsMS int64, sig, storedPub []byte) ([]byte, error) {
	if len(storedPub) > 0 {
		return storedPub, nil
	}
	currentPub := []byte(s.AdminPubKey)
	if !ed25519.Verify(s.AdminPubKey, signedSTHBytes(treeSize, root, tsMS), sig) {
		return nil, fmt.Errorf("checkpoint tree_size=%d has no stored admin_pubkey and does not verify with current admin key", treeSize)
	}
	_, err := s.Pool.Exec(ctx,
		`UPDATE checkpoints
		    SET admin_pubkey = $2
		  WHERE tree_size = $1
		    AND admin_pubkey IS NULL`,
		treeSize, currentPub,
	)
	if err != nil {
		return nil, fmt.Errorf("backfill checkpoint admin pubkey: %w", err)
	}
	return currentPub, nil
}

// SignedSTHBytes is exported so the verify CLI can replay the signed message.
func SignedSTHBytes(treeSize int64, rootHash []byte, tsMS int64) []byte {
	return signedSTHBytes(treeSize, rootHash, tsMS)
}

func signedSTHBytes(treeSize int64, rootHash []byte, tsMS int64) []byte {
	return []byte(fmt.Sprintf("fp.sth.v1|%d|%s|%d", treeSize, hex(rootHash), tsMS))
}

func hex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}
