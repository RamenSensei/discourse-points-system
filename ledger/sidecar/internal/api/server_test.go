package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/forum-points/ledger/internal/ledger"
)

const devHeaderAuthToken = "test-dev-header-auth-token-at-least-32-bytes"

// memHistory satisfies HistoryQuerier from the MemStore for tests.
type memHistory struct{ ms *ledger.MemStore }

func (h *memHistory) UserHistory(ctx context.Context, dscID int64, limit int) ([]HistoryEntry, error) {
	// MemStore doesn't expose tx iteration; this minimal stub returns empty.
	// For richer history tests we rely on integration tests with PG. Here we
	// just confirm the endpoint plumbing.
	return []HistoryEntry{}, nil
}

type harness struct {
	t        *testing.T
	srv      *httptest.Server
	store    *ledger.MemStore
	adminPub ed25519.PublicKey
	admin    ed25519.PrivateKey
	client   *http.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ms := ledger.NewMemStore()
	adminPub, adminPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Apply genesis
	g := signTx(t, adminPriv, ledger.TxGenesis, ledger.GenesisPayload{
		To: adminPub, TreasuryUser: "TREASURY", Amount: ledger.SupplyCap,
	})
	if err := ledger.Apply(context.Background(), ms, g); err != nil {
		t.Fatalf("genesis: %v", err)
	}

	srv := &Server{Store: ms, History: &memHistory{ms: ms}, DevHeaderAuthToken: devHeaderAuthToken}
	hSrv := httptest.NewServer(srv.Routes())
	t.Cleanup(hSrv.Close)
	return &harness{
		t:        t,
		srv:      hSrv,
		store:    ms,
		adminPub: adminPub,
		admin:    adminPriv,
		client:   hSrv.Client(),
	}
}

func (h *harness) GET(path string, headers map[string]string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("GET", h.srv.URL+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

func (h *harness) POST(path string, body any, headers map[string]string) (int, map[string]any) {
	h.t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req, _ := http.NewRequest("POST", h.srv.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(respBody, &out)
	return resp.StatusCode, out
}

// adminTransferTo: admin transfers `amount` to a discourse_id (auto-creating receiver).
// Returns the tx that was applied so caller can chain nonces.
func (h *harness) adminTransferTo(toDscID int64, amount int64, nonce int64, meta map[string]any) {
	h.t.Helper()
	tx := signTx(h.t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
		From:          h.adminPub,
		ToDiscourseID: toDscID,
		Amount:        amount,
		Nonce:         nonce,
		Meta:          meta,
	})
	if err := ledger.Apply(context.Background(), h.store, tx); err != nil {
		h.t.Fatalf("admin transfer: %v", err)
	}
}

func devAuth(id int64, name string) map[string]string {
	return map[string]string{
		"X-Discourse-User-Id":  fmt.Sprintf("%d", id),
		"X-Discourse-Username": name,
		"X-Wallet-Dev-Auth":    devHeaderAuthToken,
	}
}

// ============================================================================
// /health
// ============================================================================

func TestHealth(t *testing.T) {
	h := newHarness(t)
	code, body := h.GET("/api/v1/health", nil)
	if code != 200 || body["status"] != "ok" {
		t.Fatalf("health: %d %v", code, body)
	}
}

// ============================================================================
// /balance/:id
// ============================================================================

func TestBalance_TreasuryHasSupply(t *testing.T) {
	h := newHarness(t)
	code, body := h.GET("/api/v1/balance/0", nil)
	if code != 200 {
		t.Fatalf("status: %d", code)
	}
	if body["balance"] != float64(ledger.SupplyCap) {
		t.Fatalf("treasury balance = %v, want %d", body["balance"], ledger.SupplyCap)
	}
	if body["activated"] != true || body["registered"] != true {
		t.Fatalf("treasury should be activated: %v", body)
	}
}

func TestBalance_UnknownUser_ReturnsZero(t *testing.T) {
	h := newHarness(t)
	code, body := h.GET("/api/v1/balance/9999", nil)
	if code != 200 {
		t.Fatalf("status: %d", code)
	}
	if body["balance"] != float64(0) {
		t.Fatalf("balance = %v, want 0", body["balance"])
	}
	if body["registered"] != false || body["activated"] != false {
		t.Fatalf("unknown user should be inactive: %v", body)
	}
}

func TestBalance_AutoCreatedReceiver_NotActivated(t *testing.T) {
	h := newHarness(t)
	h.adminTransferTo(42, 100, 1, map[string]any{"tip_target_username": "alice"})
	code, body := h.GET("/api/v1/balance/42", nil)
	if code != 200 {
		t.Fatalf("status: %d", code)
	}
	if body["balance"] != float64(100) || body["registered"] != false || body["activated"] != false {
		t.Fatalf("pre-activation balance = %v", body)
	}
	if body["username"] != "alice" {
		t.Fatalf("username = %v, want alice", body["username"])
	}
}

func TestBalance_BadID_400(t *testing.T) {
	h := newHarness(t)
	code, _ := h.GET("/api/v1/balance/not-a-number", nil)
	if code != 400 {
		t.Fatalf("status: %d, want 400", code)
	}
}

func TestBalance_NegativeID_400(t *testing.T) {
	h := newHarness(t)
	code, _ := h.GET("/api/v1/balance/-1", nil)
	if code != 400 {
		t.Fatalf("status: %d, want 400", code)
	}
}

// ============================================================================
// /me + /me/register
// ============================================================================

func TestMe_Unauthenticated_401(t *testing.T) {
	h := newHarness(t)
	code, _ := h.GET("/api/v1/me", nil)
	if code != 401 {
		t.Fatalf("status: %d, want 401", code)
	}
}

func TestMe_HeaderAuthRequiresDevToken_401(t *testing.T) {
	h := newHarness(t)
	code, _ := h.GET("/api/v1/me", map[string]string{
		"X-Discourse-User-Id":  "42",
		"X-Discourse-Username": "alice",
	})
	if code != 401 {
		t.Fatalf("status: %d, want 401", code)
	}
}

func TestMe_HeaderAuth_NewUser_NoAccount(t *testing.T) {
	h := newHarness(t)
	code, body := h.GET("/api/v1/me", devAuth(42, "alice"))
	if code != 200 {
		t.Fatalf("status: %d", code)
	}
	if body["registered"] != false || body["balance"] != float64(0) {
		t.Fatalf("new user: %v", body)
	}
}

func TestRegister_FirstTime_201(t *testing.T) {
	h := newHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	code, body := h.POST("/api/v1/me/register",
		map[string]string{"pubkey_hex": hex.EncodeToString(pub)},
		devAuth(42, "alice"))
	if code != 201 {
		t.Fatalf("status: %d body=%v", code, body)
	}
	if body["activated"] != true || body["registered"] != true {
		t.Fatalf("first-time register: %v", body)
	}
}

func TestRegister_ActivatesPreFunded_200(t *testing.T) {
	h := newHarness(t)
	h.adminTransferTo(42, 100, 1, nil)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	code, body := h.POST("/api/v1/me/register",
		map[string]string{"pubkey_hex": hex.EncodeToString(pub)},
		devAuth(42, "alice"))
	if code != 200 {
		t.Fatalf("status: %d body=%v", code, body)
	}
	if body["activated"] != true {
		t.Fatalf("activation: %v", body)
	}
}

func TestRegister_Idempotent_200(t *testing.T) {
	h := newHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := map[string]string{"pubkey_hex": hex.EncodeToString(pub)}
	h.POST("/api/v1/me/register", body, devAuth(42, "alice"))
	code, _ := h.POST("/api/v1/me/register", body, devAuth(42, "alice"))
	if code != 200 {
		t.Fatalf("idempotent register: %d", code)
	}
}

func TestRegister_DifferentPubkey_409(t *testing.T) {
	h := newHarness(t)
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	h.POST("/api/v1/me/register",
		map[string]string{"pubkey_hex": hex.EncodeToString(pub1)},
		devAuth(42, "alice"))
	code, _ := h.POST("/api/v1/me/register",
		map[string]string{"pubkey_hex": hex.EncodeToString(pub2)},
		devAuth(42, "alice"))
	if code != 409 {
		t.Fatalf("expected 409 conflict, got %d", code)
	}
}

func TestRegister_BadPubkey_400(t *testing.T) {
	h := newHarness(t)
	code, _ := h.POST("/api/v1/me/register",
		map[string]string{"pubkey_hex": "tooshort"},
		devAuth(42, "alice"))
	if code != 400 {
		t.Fatalf("status: %d", code)
	}
}

// Note: /me/register treasury-id guard (`if id == TreasuryDscID`) is defense-in-depth
// but unreachable through header auth (which rejects id<=0) and unreachable through
// DiscourseConnect (Discourse never issues external_id 0). No test — dead code by design.

// ============================================================================
// /tx — happy + many sad paths
// ============================================================================

func TestSubmitTx_AdminTransferHappyPath(t *testing.T) {
	h := newHarness(t)
	tx := signTx(t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
		From: h.adminPub, ToDiscourseID: 42, Amount: 100, Nonce: 1,
	})
	code, body := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 201 {
		t.Fatalf("status: %d body=%v", code, body)
	}
	if body["tx_hash"] == nil {
		t.Fatalf("no tx_hash in response: %v", body)
	}
	// receiver should now show 100
	_, bal := h.GET("/api/v1/balance/42", nil)
	if bal["balance"] != float64(100) {
		t.Fatalf("alice balance after tip: %v", bal)
	}
}

func TestSubmitTx_BadSignature_400(t *testing.T) {
	h := newHarness(t)
	tx := signTx(t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
		From: h.adminPub, ToDiscourseID: 42, Amount: 100, Nonce: 1,
	})
	tx.Sig[0] ^= 0xff
	code, body := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 400 {
		t.Fatalf("status: %d body=%v", code, body)
	}
}

func TestSubmitTx_SignerMismatch_400(t *testing.T) {
	h := newHarness(t)
	_, mallorPriv, _ := ed25519.GenerateKey(rand.Reader)
	// mallory signs but claims to be admin
	tx := signTx(t, mallorPriv, ledger.TxTransfer, ledger.TransferPayload{
		From: h.adminPub, ToDiscourseID: 42, Amount: 100, Nonce: 1,
	})
	code, body := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 400 {
		t.Fatalf("status: %d body=%v", code, body)
	}
	if !strings.Contains(stringOf(body["error"]), "signer") {
		t.Logf("error message: %v", body["error"])
	}
}

func TestSubmitTx_BadNonce_422(t *testing.T) {
	h := newHarness(t)
	tx := signTx(t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
		From: h.adminPub, ToDiscourseID: 42, Amount: 100, Nonce: 99, // expected 1
	})
	code, _ := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 422 {
		t.Fatalf("status: %d, want 422 for bad nonce", code)
	}
}

func TestSubmitTx_InsufficientFunds_422(t *testing.T) {
	h := newHarness(t)
	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	// Pre-activate alice with 0 balance
	stx, _ := h.store.Begin(context.Background())
	_ = stx.UpsertAccount(context.Background(), &ledger.Account{
		DiscourseID: 42, Pubkey: alicePub, Username: "alice",
	})
	_ = stx.Commit(context.Background())
	tx := signTx(t, alicePriv, ledger.TxTransfer, ledger.TransferPayload{
		From: alicePub, ToDiscourseID: 43, Amount: 1, Nonce: 1,
	})
	code, _ := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 422 {
		t.Fatalf("status: %d, want 422 for insufficient funds", code)
	}
}

func TestSubmitTx_SelfTransfer_400(t *testing.T) {
	h := newHarness(t)
	tx := signTx(t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
		From: h.adminPub, ToDiscourseID: 0, Amount: 1, Nonce: 1, // treasury to self
	})
	code, _ := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 400 {
		t.Fatalf("status: %d, want 400 for self-transfer", code)
	}
}

func TestSubmitTx_BadReceiverID_400(t *testing.T) {
	h := newHarness(t)
	tx := signTx(t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
		From: h.adminPub, ToDiscourseID: -1, Amount: 1, Nonce: 1,
	})
	code, body := h.POST("/api/v1/tx", buildSubmit(tx), nil)
	if code != 400 {
		t.Fatalf("status: %d body=%v, want 400 for bad receiver id", code, body)
	}
}

func TestSubmitTx_BadBase64_400(t *testing.T) {
	h := newHarness(t)
	body := map[string]string{
		"tx_type":     "transfer",
		"payload_b64": "@@@not base64@@@",
		"sig_b64":     "AAAA",
		"signer_hex":  hex.EncodeToString(h.adminPub),
	}
	code, _ := h.POST("/api/v1/tx", body, nil)
	if code != 400 {
		t.Fatalf("status: %d", code)
	}
}

func TestSubmitTx_UnknownTxType_400(t *testing.T) {
	h := newHarness(t)
	pay := []byte("{}")
	sig := ed25519.Sign(h.admin, pay)
	body := map[string]string{
		"tx_type":     "mystery_type",
		"payload_b64": base64.StdEncoding.EncodeToString(pay),
		"sig_b64":     base64.StdEncoding.EncodeToString(sig),
		"signer_hex":  hex.EncodeToString(h.adminPub),
	}
	code, _ := h.POST("/api/v1/tx", body, nil)
	if code != 400 {
		t.Fatalf("status: %d", code)
	}
}

func TestSubmitTx_DuplicateNonce_422(t *testing.T) {
	h := newHarness(t)
	mk := func(nonce int64) any {
		return buildSubmit(signTx(t, h.admin, ledger.TxTransfer, ledger.TransferPayload{
			From: h.adminPub, ToDiscourseID: 42, Amount: 1, Nonce: nonce,
		}))
	}
	if c, _ := h.POST("/api/v1/tx", mk(1), nil); c != 201 {
		t.Fatalf("first nonce=1: %d", c)
	}
	// replay
	if c, _ := h.POST("/api/v1/tx", mk(1), nil); c != 422 {
		t.Fatalf("replay nonce=1: %d, want 422", c)
	}
}

// ============================================================================
// /treasury
// ============================================================================

func TestTreasury(t *testing.T) {
	h := newHarness(t)
	code, body := h.GET("/api/v1/treasury", nil)
	if code != 200 {
		t.Fatalf("status: %d", code)
	}
	if body["supply_ok"] != true {
		t.Fatalf("supply_ok: %v", body["supply_ok"])
	}
	if body["supply_circulating"] != float64(ledger.SupplyCap) {
		t.Fatalf("circulating = %v", body["supply_circulating"])
	}
}

// ============================================================================
// /history
// ============================================================================

func TestHistory_NoHistoryEnabled_OK(t *testing.T) {
	// We wired memHistory, so the endpoint should work and return empty.
	h := newHarness(t)
	code, body := h.GET("/api/v1/history/42", nil)
	if code != 200 {
		t.Fatalf("status: %d", code)
	}
	if body["discourse_id"] != float64(42) {
		t.Fatalf("body: %v", body)
	}
}

func TestHistory_NegativeID_400(t *testing.T) {
	h := newHarness(t)
	code, _ := h.GET("/api/v1/history/-1", nil)
	if code != 400 {
		t.Fatalf("status: %d, want 400", code)
	}
}

func TestHistory_NilQuerier_501(t *testing.T) {
	ms := ledger.NewMemStore()
	srv := &Server{Store: ms} // no History
	hSrv := httptest.NewServer(srv.Routes())
	defer hSrv.Close()
	resp, _ := hSrv.Client().Get(hSrv.URL + "/api/v1/history/42")
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: %d, want 501", resp.StatusCode)
	}
}

// ============================================================================
// helpers
// ============================================================================

func signTx(t *testing.T, priv ed25519.PrivateKey, typ ledger.TxType, payload any) *ledger.Tx {
	t.Helper()
	pay, err := ledger.CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := ed25519.Sign(priv, pay)
	return &ledger.Tx{
		Type:    typ,
		Payload: pay,
		Sig:     sig,
		Signer:  priv.Public().(ed25519.PublicKey),
	}
}

func buildSubmit(tx *ledger.Tx) map[string]string {
	return map[string]string{
		"tx_type":     string(tx.Type),
		"payload_b64": base64.StdEncoding.EncodeToString(tx.Payload),
		"sig_b64":     base64.StdEncoding.EncodeToString(tx.Sig),
		"signer_hex":  hex.EncodeToString(tx.Signer),
	}
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestMain(m *testing.M) {
	// Ensure no inherited admin auth env leaks into individual tests.
	_ = os.Unsetenv("WALLET_ALLOW_HEADER_AUTH")
	os.Exit(m.Run())
}
