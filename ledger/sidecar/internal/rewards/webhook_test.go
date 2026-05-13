package rewards

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/forum-points/ledger/internal/ledger"
)

// memRewards is an in-memory implementation of the Rewards interface for tests.
type memRewards struct {
	mu      sync.Mutex
	amounts map[string]int64
	enabled map[string]bool
	events  map[string]struct{}
}

func newMemRewards() *memRewards {
	return &memRewards{
		amounts: map[string]int64{"signup_bonus": 100, "first_post_ever": 50},
		enabled: map[string]bool{"signup_bonus": true, "first_post_ever": true},
		events:  map[string]struct{}{},
	}
}

func (r *memRewards) GetRewardAmount(ctx context.Context, eventType string) (int64, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.amounts[eventType]
	if !ok {
		return 0, false, nil
	}
	return a, r.enabled[eventType], nil
}

func (r *memRewards) RewardEventExists(ctx context.Context, eventType, eventKey string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.events[eventType+"/"+eventKey]
	return ok, nil
}

func (r *memRewards) RecordRewardEvent(ctx context.Context, eventType, eventKey string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[eventType+"/"+eventKey] = struct{}{}
	return nil
}

func setupService(t *testing.T) (*Service, *ledger.MemStore, ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	ms := ledger.NewMemStore()
	adminPub, adminPriv, _ := ed25519.GenerateKey(rand.Reader)
	// Genesis
	pay, _ := ledger.CanonicalJSON(ledger.GenesisPayload{To: adminPub, Amount: ledger.SupplyCap})
	sig := ed25519.Sign(adminPriv, pay)
	if err := ledger.Apply(context.Background(), ms, &ledger.Tx{
		Type: ledger.TxGenesis, Payload: pay, Sig: sig, Signer: adminPub,
	}); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	secret := []byte("wb-secret-for-test")
	return &Service{
		Store:         ms,
		Rewards:       newMemRewards(),
		AdminPrivKey:  adminPriv,
		AdminPubKey:   adminPub,
		WebhookSecret: secret,
	}, ms, adminPub, adminPriv, secret
}

func makeReq(t *testing.T, eventType, eventName string, body []byte, secret []byte) *http.Request {
	t.Helper()
	h := hmac.New(sha256.New, secret)
	h.Write(body)
	sig := "sha256=" + hex.EncodeToString(h.Sum(nil))
	req := httptest.NewRequest("POST", "/hooks/discourse", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Discourse-Event-Type", eventType)
	req.Header.Set("X-Discourse-Event", eventName)
	req.Header.Set("X-Discourse-Event-Signature", sig)
	return req
}

func TestSignupBonusPaidOnce(t *testing.T) {
	svc, ms, _, _, secret := setupService(t)

	body := []byte(`{"user":{"id":42,"username":"alice","active":true,"trust_level":1}}`)
	rec := httptest.NewRecorder()
	svc.Webhook(rec, makeReq(t, "user", "user_activated", body, secret))
	if rec.Code != 200 {
		t.Fatalf("first webhook: %d %s", rec.Code, rec.Body.String())
	}

	stx, _ := ms.Begin(context.Background())
	defer stx.Rollback(context.Background())
	alice, _ := stx.GetAccountByDiscourseID(context.Background(), 42)
	if alice == nil || alice.Balance != 100 {
		t.Fatalf("alice = %+v", alice)
	}

	// Re-fire same event → dedup, no double pay
	rec2 := httptest.NewRecorder()
	svc.Webhook(rec2, makeReq(t, "user", "user_activated", body, secret))
	if rec2.Code != 200 {
		t.Fatalf("second webhook: %d %s", rec2.Code, rec2.Body.String())
	}
	stx2, _ := ms.Begin(context.Background())
	defer stx2.Rollback(context.Background())
	alice2, _ := stx2.GetAccountByDiscourseID(context.Background(), 42)
	if alice2.Balance != 100 {
		t.Fatalf("dedup failed: alice balance = %d", alice2.Balance)
	}
}

func TestFirstPostBonusOnePerUser(t *testing.T) {
	svc, ms, _, _, secret := setupService(t)

	// alice posts first time → +50
	body1 := []byte(`{"post":{"id":1,"user_id":42,"username":"alice","post_number":1}}`)
	rec := httptest.NewRecorder()
	svc.Webhook(rec, makeReq(t, "post", "post_created", body1, secret))
	if rec.Code != 200 {
		t.Fatalf("first post: %d %s", rec.Code, rec.Body.String())
	}

	// alice posts second time → no bonus (dedup on user:42)
	body2 := []byte(`{"post":{"id":2,"user_id":42,"username":"alice","post_number":2}}`)
	rec2 := httptest.NewRecorder()
	svc.Webhook(rec2, makeReq(t, "post", "post_created", body2, secret))

	stx, _ := ms.Begin(context.Background())
	defer stx.Rollback(context.Background())
	alice, _ := stx.GetAccountByDiscourseID(context.Background(), 42)
	if alice == nil || alice.Balance != 50 {
		t.Fatalf("alice balance after two posts = %d, want 50", alice.Balance)
	}
}

func TestPostBySystemUserDoesNotPay(t *testing.T) {
	svc, ms, _, _, secret := setupService(t)

	body := []byte(`{"post":{"id":1,"user_id":-1,"username":"system","post_number":1}}`)
	rec := httptest.NewRecorder()
	svc.Webhook(rec, makeReq(t, "post", "post_created", body, secret))
	if rec.Code != 200 {
		t.Fatalf("system post: %d %s", rec.Code, rec.Body.String())
	}

	stx, _ := ms.Begin(context.Background())
	defer stx.Rollback(context.Background())
	system, _ := stx.GetAccountByDiscourseID(context.Background(), -1)
	if system != nil {
		t.Fatalf("system account should not be created: %+v", system)
	}
}

func TestSignAndApplyTransferRejectsNonUserID(t *testing.T) {
	svc, _, _, _, _ := setupService(t)
	if _, err := svc.SignAndApplyTransfer(context.Background(), -1, "system", 50, "test"); !errors.Is(err, ledger.ErrBadDiscourseID) {
		t.Fatalf("err = %v, want ErrBadDiscourseID", err)
	}
}

func TestBadHmacRejected(t *testing.T) {
	svc, _, _, _, _ := setupService(t)
	body := []byte(`{"user":{"id":42}}`)
	req := makeReq(t, "user", "user_activated", body, []byte("wrong-secret"))
	rec := httptest.NewRecorder()
	svc.Webhook(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}
