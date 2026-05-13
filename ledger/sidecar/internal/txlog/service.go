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
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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
}

// AllTxHashes returns all tx_hash bytes in leaf_index order.
func (s *Service) AllTxHashes(ctx context.Context) ([][]byte, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT tx_hash FROM transactions ORDER BY leaf_index ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
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
	hashes, err := s.AllTxHashes(ctx)
	if err != nil {
		return nil, err
	}
	leafHashes := make([][]byte, len(hashes))
	for i, h := range hashes {
		leafHashes[i] = merkle.LeafHash(h)
	}
	root := merkle.RootFromLeafHashes(leafHashes)
	ts := time.Now().UnixMilli()

	// Sign canonical bytes "fp.sth.v1|<tree_size>|<root_hex>|<ts_ms>"
	msg := signedSTHBytes(int64(len(hashes)), root, ts)
	sig := ed25519.Sign(s.AdminPrivKey, msg)

	// Also persist this STH to checkpoints (idempotent on tree_size).
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO checkpoints (tree_size, root_hash, timestamp_ms, admin_sig)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tree_size) DO NOTHING`,
		int64(len(hashes)), root, ts, sig,
	)
	if err != nil && !isUniqueViolation(err) {
		return nil, fmt.Errorf("persist checkpoint: %w", err)
	}

	return &STH{
		TreeSize:    int64(len(hashes)),
		RootHash:    hex(root),
		TimestampMS: ts,
		AdminSig:    hex(sig),
		AdminPubKey: hex([]byte(s.AdminPubKey)),
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
	HasOTSReceipt bool   `json:"has_ots_receipt"`
}

// Checkpoints returns the most recent `limit` STH checkpoints in descending
// tree_size order. Public — any third party can browse to monitor the log.
func (s *Service) Checkpoints(ctx context.Context, limit int) ([]CheckpointSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT tree_size, root_hash, timestamp_ms, admin_sig, ots_receipt IS NOT NULL
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
		var root, sig []byte
		var ts int64
		var hasOTS bool
		if err := rows.Scan(&size, &root, &ts, &sig, &hasOTS); err != nil {
			return nil, err
		}
		out = append(out, CheckpointSummary{
			TreeSize:      size,
			RootHash:      hex(root),
			TimestampMS:   ts,
			AdminSig:      hex(sig),
			HasOTSReceipt: hasOTS,
		})
	}
	return out, rows.Err()
}

// SignedSTHBytes is exported so the verify CLI can replay the signed message.
func SignedSTHBytes(treeSize int64, rootHash []byte, tsMS int64) []byte {
	return signedSTHBytes(treeSize, rootHash, tsMS)
}

func signedSTHBytes(treeSize int64, rootHash []byte, tsMS int64) []byte {
	return []byte(fmt.Sprintf("fp.sth.v1|%d|%s|%d", treeSize, hex(rootHash), tsMS))
}

func isUniqueViolation(err error) bool {
	var pgErr *pgErrorLite
	if !errorAs(err, &pgErr) {
		return false
	}
	return false
}

// minimal placeholders so we don't import pgconn directly here
type pgErrorLite struct{}

func errorAs(err error, _ **pgErrorLite) bool { return false }

func hex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}

// silence unused import warnings during gradual fills
var _ = pgx.ErrNoRows
var _ = json.Marshal
