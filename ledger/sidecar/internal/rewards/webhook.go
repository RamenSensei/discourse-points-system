// Package rewards handles incoming Discourse webhooks and turns them into
// admin-signed ledger transactions to seed/reward forum accounts.
package rewards

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/forum-points/ledger/internal/ledger"
)

const (
	EventSignupBonus   = "signup_bonus"
	EventFirstPostEver = "first_post_ever"
	EventQualityPost   = "quality_post"
	EventBackfill      = "backfill"
)

type Service struct {
	Store         ledger.Store
	Rewards       Rewards
	AdminPrivKey  ed25519.PrivateKey
	AdminPubKey   ed25519.PublicKey
	WebhookSecret []byte
}

// Rewards is the interface for looking up reward amounts and recording dedup events.
type Rewards interface {
	GetRewardAmount(ctx context.Context, eventType string) (amount int64, enabled bool, err error)
	RewardEventExists(ctx context.Context, eventType, eventKey string) (bool, error)
	RecordRewardEvent(ctx context.Context, eventType, eventKey string, txHash []byte) error
}

// Webhook is the http.Handler that receives Discourse-formatted webhook events.
//
// Discourse sets:
//
//	X-Discourse-Event-Signature: sha256=<hex>
//	X-Discourse-Event-Type:      <category, e.g. "user", "post", "topic">
//	X-Discourse-Event:           <name,     e.g. "user_created", "user_activated">
//	Content-Type:                application/json
func (s *Service) Webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.verifySig(r, body) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-Discourse-Event-Type")
	eventName := r.Header.Get("X-Discourse-Event")
	log.Printf("rewards: webhook %s/%s (%d bytes)", eventType, eventName, len(body))

	switch eventType {
	case "user":
		s.handleUserEvent(r.Context(), eventName, body, w)
	case "post":
		s.handlePostEvent(r.Context(), eventName, body, w)
	default:
		// Unhandled event — record receipt but no action
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ignored"}`))
	}
}

func (s *Service) verifySig(r *http.Request, body []byte) bool {
	header := r.Header.Get("X-Discourse-Event-Signature")
	if header == "" {
		return false
	}
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, s.WebhookSecret)
	h.Write(body)
	return hmac.Equal(want, h.Sum(nil))
}

// --- user events ---

type userPayload struct {
	User struct {
		ID         int64  `json:"id"`
		Username   string `json:"username"`
		Active     bool   `json:"active"`
		Approved   bool   `json:"approved"`
		TrustLevel int    `json:"trust_level"`
	} `json:"user"`
}

func (s *Service) handleUserEvent(ctx context.Context, eventName string, body []byte, w http.ResponseWriter) {
	var p userPayload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad user payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.User.ID <= 0 {
		http.Error(w, "missing user.id", http.StatusBadRequest)
		return
	}

	// Pay signup bonus on user_created or user_activated (whichever fires first).
	// dedup_key = "user:<id>" so the second event is a no-op.
	switch eventName {
	case "user_created", "user_activated":
		if p.User.Active {
			s.payOnce(ctx, EventSignupBonus, fmt.Sprintf("user:%d", p.User.ID),
				p.User.ID, p.User.Username, w)
			return
		}
	}
	writeOK(w, "user event recorded, no reward triggered")
}

// --- post events ---

type postPayload struct {
	Post struct {
		ID         int64  `json:"id"`
		UserID     int64  `json:"user_id"`
		Username   string `json:"username"`
		PostNumber int    `json:"post_number"`
	} `json:"post"`
}

func (s *Service) handlePostEvent(ctx context.Context, eventName string, body []byte, w http.ResponseWriter) {
	var p postPayload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad post payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Lifetime first-post bonus: same user only triggers once across all posts.
	if eventName == "post_created" {
		if p.Post.UserID <= 0 {
			writeOK(w, "skip non-user post author")
			return
		}
		s.payOnce(ctx, EventFirstPostEver, fmt.Sprintf("user:%d", p.Post.UserID),
			p.Post.UserID, p.Post.Username, w)
		return
	}
	writeOK(w, "post event recorded, no reward triggered")
}

// payOnce: looks up reward_config, dedups via reward_events, signs an admin
// transfer to discourse_id, applies it, and records the event.
func (s *Service) payOnce(ctx context.Context, eventType, eventKey string, toDscID int64, toUsername string, w http.ResponseWriter) {
	if toDscID <= ledger.TreasuryDscID {
		writeOK(w, "skip non-user discourse_id")
		return
	}
	amount, enabled, err := s.Rewards.GetRewardAmount(ctx, eventType)
	if err != nil {
		http.Error(w, "reward_config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !enabled || amount <= 0 {
		writeOK(w, "reward disabled or amount=0")
		return
	}
	if toDscID == ledger.TreasuryDscID {
		writeOK(w, "skip self-pay to treasury")
		return
	}
	already, err := s.Rewards.RewardEventExists(ctx, eventType, eventKey)
	if err != nil {
		http.Error(w, "dedup check: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if already {
		writeOK(w, "already paid (dedup)")
		return
	}

	tx, err := s.signAndApplyTransfer(ctx, toDscID, toUsername, amount, eventType)
	if err != nil {
		http.Error(w, "apply: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.Rewards.RecordRewardEvent(ctx, eventType, eventKey, tx.TxHash); err != nil {
		// Reward paid but dedup row failed — log loudly, allow webhook to succeed.
		log.Printf("rewards: WARN payOnce dedup-record failed (tx already applied): %v", err)
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "paid",
		"event":      eventType,
		"to":         toDscID,
		"amount":     amount,
		"tx_hash":    hex.EncodeToString(tx.TxHash),
		"leaf_index": tx.LeafIndex,
	})
}

// SignAndApplyTransfer is exported so the backfill CLI can call it.
func (s *Service) SignAndApplyTransfer(ctx context.Context, toDscID int64, toUsername string, amount int64, source string) (*ledger.Tx, error) {
	return s.signAndApplyTransfer(ctx, toDscID, toUsername, amount, source)
}

func (s *Service) signAndApplyTransfer(ctx context.Context, toDscID int64, toUsername string, amount int64, source string) (*ledger.Tx, error) {
	if toDscID <= ledger.TreasuryDscID {
		return nil, ledger.ErrBadDiscourseID
	}
	// Look up the admin's current nonce
	stx, err := s.Store.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	admin, err := stx.GetAccountByPubKey(ctx, s.AdminPubKey)
	stx.Rollback(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin lookup: %w", err)
	}
	if admin == nil {
		return nil, errors.New("admin/treasury account not found; run ledger-admin init first")
	}
	if admin.Balance < amount {
		return nil, fmt.Errorf("treasury underfunded: balance=%d need=%d", admin.Balance, amount)
	}
	nonce := admin.Nonce + 1

	meta := map[string]any{
		"reward_source":       source,
		"tip_target_username": toUsername,
	}
	payload := ledger.TransferPayload{
		From:          s.AdminPubKey,
		ToDiscourseID: toDscID,
		Amount:        amount,
		Nonce:         nonce,
		Meta:          meta,
	}
	payloadBytes, err := ledger.CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(s.AdminPrivKey, payloadBytes)
	tx := &ledger.Tx{
		Type:    ledger.TxTransfer,
		Payload: payloadBytes,
		Sig:     sig,
		Signer:  s.AdminPubKey,
	}
	if err := ledger.Apply(ctx, s.Store, tx); err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	return tx, nil
}

func writeOK(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","detail":"` + msg + `"}`))
}
