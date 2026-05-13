// Package ots provides OpenTimestamps anchoring.
//
// We POST the SHA-256 digest of our STH canonical bytes to a public OTS
// calendar server; the server returns a "pending" timestamp receipt that
// proves a Bitcoin commitment will eventually exist for this digest.
//
// We don't bundle a full OTS upgrade flow here — the receipt is stored as-is
// and can be upgraded later via the OTS CLI or the calendar's /timestamp endpoint.
package ots

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultCalendar = "https://a.pool.opentimestamps.org/digest"
	contentType     = "application/vnd.opentimestamps.v1"
)

// Submit submits a 32-byte digest to the OTS calendar and returns the receipt bytes.
func Submit(ctx context.Context, calendarURL string, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, errors.New("digest must be 32 bytes")
	}
	if calendarURL == "" {
		calendarURL = defaultCalendar
	}
	req, err := http.NewRequestWithContext(ctx, "POST", calendarURL, bytes.NewReader(digest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", contentType)
	req.Header.Set("User-Agent", "forum-points-ledger-ots/1")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("ots calendar HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// AnchorChecks stores the OTS receipt for an existing STH row in `checkpoints`.
// The checkpoint must already exist (created by txlog.CurrentSTH).
func AnchorCheckpoint(ctx context.Context, db *pgxpool.Pool, treeSize int64, receipt []byte) error {
	tag, err := db.Exec(ctx,
		`UPDATE checkpoints SET ots_receipt = $1 WHERE tree_size = $2`,
		receipt, treeSize,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no checkpoint at tree_size=%d", treeSize)
	}
	return nil
}

// DigestSTH returns SHA-256 over the canonical STH message bytes — the same
// bytes that the admin signs. This is what gets anchored.
func DigestSTH(canonicalSTHBytes []byte) []byte {
	h := sha256.New()
	h.Write(canonicalSTHBytes)
	return h.Sum(nil)
}
