package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// adminHarness wires a Service with no DB pool and a fixed admin key.
// Tests touching dashboard/accounts/recent-txs are skipped (need real PG).
type adminHarness struct {
	t      *testing.T
	srv    *httptest.Server
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	secret []byte
}

func newAdminHarness(t *testing.T) *adminHarness {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	svc := &Service{
		AdminPubKey:   pub,
		SessionSecret: secret,
		SecureCookies: false,
	}
	r := chi.NewRouter()
	svc.Mount(r)
	hSrv := httptest.NewServer(r)
	t.Cleanup(hSrv.Close)
	return &adminHarness{
		t:      t,
		srv:    hSrv,
		pub:    pub,
		priv:   priv,
		secret: secret,
	}
}

func (h *adminHarness) doRaw(method, path string, body any, cookies map[string]string) (*http.Response, []byte) {
	h.t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	if sess := cookies[cookieName]; sess != "" && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		req.Header.Set("X-FP-CSRF", csrfToken(h.secret, sess))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (h *adminHarness) decodeJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode json: %v body=%s", err, body)
	}
	return m
}

// Helper: do full challenge → sign → login round, return the session cookie value.
func (h *adminHarness) loginAs(priv ed25519.PrivateKey, pub ed25519.PublicKey) (string, *http.Response) {
	h.t.Helper()
	resp, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	if resp.StatusCode != 200 {
		h.t.Fatalf("challenge: %d body=%s", resp.StatusCode, body)
	}
	ch := h.decodeJSON(h.t, body)
	nonceBytes, _ := hex.DecodeString(ch["nonce_hex"].(string))
	sig := ed25519.Sign(priv, nonceBytes)
	resp, body = h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      ch["token"].(string),
		"sig_hex":    hex.EncodeToString(sig),
		"pubkey_hex": hex.EncodeToString(pub),
	}, nil)
	if resp.StatusCode != 200 {
		return "", resp
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c.Value, resp
		}
	}
	return "", resp
}

// ============================================================================
// login challenge
// ============================================================================

func TestLoginChallenge_ReturnsTokenAndNonce(t *testing.T) {
	h := newAdminHarness(t)
	resp, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	m := h.decodeJSON(t, body)
	if m["nonce_hex"] == "" || m["token"] == "" {
		t.Fatalf("missing fields: %v", m)
	}
	// nonce should be 32 bytes = 64 hex chars
	if len(m["nonce_hex"].(string)) != 64 {
		t.Fatalf("nonce_hex len = %d", len(m["nonce_hex"].(string)))
	}
}

func TestLoginChallenge_DifferentNoncesEachCall(t *testing.T) {
	h := newAdminHarness(t)
	_, body1 := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	_, body2 := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	m1, m2 := h.decodeJSON(t, body1), h.decodeJSON(t, body2)
	if m1["nonce_hex"] == m2["nonce_hex"] {
		t.Fatalf("nonces should differ across calls")
	}
}

// ============================================================================
// login (happy + sad paths)
// ============================================================================

func TestLogin_HappyPath(t *testing.T) {
	h := newAdminHarness(t)
	sess, resp := h.loginAs(h.priv, h.pub)
	if resp.StatusCode != 200 {
		t.Fatalf("login status: %d", resp.StatusCode)
	}
	if sess == "" {
		t.Fatalf("no session cookie returned; cookies: %v", resp.Cookies())
	}
}

func TestLogin_WrongPubkey_403(t *testing.T) {
	h := newAdminHarness(t)
	// Get a challenge for the admin
	_, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	ch := h.decodeJSON(t, body)
	// Sign with imposter key
	impPub, impPriv, _ := ed25519.GenerateKey(rand.Reader)
	nonceBytes, _ := hex.DecodeString(ch["nonce_hex"].(string))
	sig := ed25519.Sign(impPriv, nonceBytes)
	resp, _ := h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      ch["token"].(string),
		"sig_hex":    hex.EncodeToString(sig),
		"pubkey_hex": hex.EncodeToString(impPub),
	}, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

func TestLogin_TamperedToken_401(t *testing.T) {
	h := newAdminHarness(t)
	_, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	ch := h.decodeJSON(t, body)
	// Flip a hex digit in the token's MAC
	tok := ch["token"].(string)
	tampered := tok[:len(tok)-2] + "00"
	if tampered == tok {
		tampered = tok[:len(tok)-2] + "ff"
	}
	nonceBytes, _ := hex.DecodeString(ch["nonce_hex"].(string))
	sig := ed25519.Sign(h.priv, nonceBytes)
	resp, _ := h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      tampered,
		"sig_hex":    hex.EncodeToString(sig),
		"pubkey_hex": hex.EncodeToString(h.pub),
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

func TestLogin_BadSignature_401(t *testing.T) {
	h := newAdminHarness(t)
	_, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	ch := h.decodeJSON(t, body)
	// Sign WRONG bytes — should fail verification
	wrongMsg := []byte("not the nonce")
	sig := ed25519.Sign(h.priv, wrongMsg)
	resp, _ := h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      ch["token"].(string),
		"sig_hex":    hex.EncodeToString(sig),
		"pubkey_hex": hex.EncodeToString(h.pub),
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

func TestLogin_BadPubkeyHex_400(t *testing.T) {
	h := newAdminHarness(t)
	_, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	ch := h.decodeJSON(t, body)
	resp, _ := h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      ch["token"].(string),
		"sig_hex":    "00",
		"pubkey_hex": "notvalidhex",
	}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
}

func TestLogin_BadSigHex_400(t *testing.T) {
	h := newAdminHarness(t)
	_, body := h.doRaw("GET", "/admin/api/login-challenge", nil, nil)
	ch := h.decodeJSON(t, body)
	resp, _ := h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      ch["token"].(string),
		"sig_hex":    "notvalidhex",
		"pubkey_hex": hex.EncodeToString(h.pub),
	}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
}

func TestLogin_MalformedJSON_400(t *testing.T) {
	h := newAdminHarness(t)
	req, _ := http.NewRequest("POST", h.srv.URL+"/admin/api/login", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLogin_BadTokenFormat_400(t *testing.T) {
	h := newAdminHarness(t)
	resp, _ := h.doRaw("POST", "/admin/api/login", map[string]string{
		"token":      "no-dot-no-format",
		"sig_hex":    "00",
		"pubkey_hex": hex.EncodeToString(h.pub),
	}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("status: %d, want 400", resp.StatusCode)
	}
}

// ============================================================================
// session expiry / cookie validation
// ============================================================================

func TestSession_ExpiredCookie_Rejected(t *testing.T) {
	h := newAdminHarness(t)
	// Mint an already-expired session manually
	tok := sessionToken{ExpUnix: time.Now().Add(-1 * time.Hour).Unix()}
	expired := signSession(tok, h.secret)
	resp, _ := h.doRaw("GET", "/admin/api/whoami", nil, map[string]string{cookieName: expired})
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

func TestSession_TamperedCookie_Rejected(t *testing.T) {
	h := newAdminHarness(t)
	tok := sessionToken{ExpUnix: time.Now().Add(1 * time.Hour).Unix()}
	good := signSession(tok, h.secret)
	tampered := good[:len(good)-2] + "ff"
	resp, _ := h.doRaw("GET", "/admin/api/whoami", nil, map[string]string{cookieName: tampered})
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

func TestSession_WrongSecret_Rejected(t *testing.T) {
	h := newAdminHarness(t)
	wrongSecret := make([]byte, 32)
	_, _ = rand.Read(wrongSecret)
	tok := sessionToken{ExpUnix: time.Now().Add(1 * time.Hour).Unix()}
	foreign := signSession(tok, wrongSecret)
	resp, _ := h.doRaw("GET", "/admin/api/whoami", nil, map[string]string{cookieName: foreign})
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

// ============================================================================
// whoami / logout / protected endpoints
// ============================================================================

func TestWhoami_Unauthenticated_401(t *testing.T) {
	h := newAdminHarness(t)
	resp, _ := h.doRaw("GET", "/admin/api/whoami", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d, want 401", resp.StatusCode)
	}
}

func TestWhoami_Authenticated_ReturnsPubkey(t *testing.T) {
	h := newAdminHarness(t)
	sess, _ := h.loginAs(h.priv, h.pub)
	resp, body := h.doRaw("GET", "/admin/api/whoami", nil, map[string]string{cookieName: sess})
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	m := h.decodeJSON(t, body)
	if m["admin_pubkey_hex"] != hex.EncodeToString(h.pub) {
		t.Fatalf("pubkey mismatch: got %v, want %s", m["admin_pubkey_hex"], hex.EncodeToString(h.pub))
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	h := newAdminHarness(t)
	sess, _ := h.loginAs(h.priv, h.pub)
	// logout
	resp, _ := h.doRaw("POST", "/admin/api/logout", nil, map[string]string{cookieName: sess})
	if resp.StatusCode != 204 {
		t.Fatalf("logout status: %d", resp.StatusCode)
	}
	// confirm MaxAge<0 in response
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("logout should set MaxAge<0 on cookie: %v", resp.Cookies())
	}
}

func TestProtectedEndpoint_NoCookie_401(t *testing.T) {
	h := newAdminHarness(t)
	for _, path := range []string{
		"/admin/api/dashboard",
		"/admin/api/reward-config",
		"/admin/api/recent-txs",
		"/admin/api/accounts",
	} {
		resp, _ := h.doRaw("GET", path, nil, nil)
		if resp.StatusCode != 401 {
			t.Fatalf("GET %s: status %d, want 401", path, resp.StatusCode)
		}
	}
	// also POST endpoints
	resp, _ := h.doRaw("POST", "/admin/api/reward-config", map[string]any{"event_type": "x", "amount": 1, "enabled": true}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("POST reward-config: status %d, want 401", resp.StatusCode)
	}
	resp, _ = h.doRaw("POST", "/admin/api/anchor-sth", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("POST anchor-sth: status %d, want 401", resp.StatusCode)
	}
}

func TestProtectedPost_MissingCSRF_403(t *testing.T) {
	h := newAdminHarness(t)
	sess, _ := h.loginAs(h.priv, h.pub)
	req, _ := http.NewRequest("POST", h.srv.URL+"/admin/api/anchor-sth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sess})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST anchor-sth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

func TestProtectedPost_CrossOrigin_403(t *testing.T) {
	h := newAdminHarness(t)
	sess, _ := h.loginAs(h.priv, h.pub)
	req, _ := http.NewRequest("POST", h.srv.URL+"/admin/api/anchor-sth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sess})
	req.Header.Set("X-FP-CSRF", csrfToken(h.secret, sess))
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST anchor-sth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d, want 403", resp.StatusCode)
	}
}

// ============================================================================
// static / index
// ============================================================================

func TestIndex_ServesHTML(t *testing.T) {
	h := newAdminHarness(t)
	resp, body := h.doRaw("GET", "/admin/", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !bytes.Contains([]byte(ct), []byte("text/html")) {
		t.Fatalf("content-type: %s", ct)
	}
	if !bytes.Contains(body, []byte("<html")) && !bytes.Contains(body, []byte("<!doctype")) && !bytes.Contains(body, []byte("<!DOCTYPE")) {
		t.Fatalf("body doesn't look like HTML: %s", body[:min(200, len(body))])
	}
}

func TestAdminBareRedirect(t *testing.T) {
	h := newAdminHarness(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", h.srv.URL+"/admin", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("status: %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/wallet/admin/" {
		t.Fatalf("redirect to %s, want /wallet/admin/", loc)
	}
}

func TestStaticAssets_AppJSReachable(t *testing.T) {
	h := newAdminHarness(t)
	for _, path := range []string{"/admin/static/app.js", "/admin/static/style.css", "/admin/static/index.html"} {
		resp, body := h.doRaw("GET", path, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: status %d, body=%s", path, resp.StatusCode, body[:min(120, len(body))])
		}
		if len(body) == 0 {
			t.Fatalf("GET %s: empty body", path)
		}
	}
}

func TestStaticAssets_DotfilesNotServed(t *testing.T) {
	h := newAdminHarness(t)
	resp, _ := h.doRaw("GET", "/admin/static/._app.js", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d, want 404", resp.StatusCode)
	}
}

// ============================================================================
// anchor-sth without TxLog returns 503
// ============================================================================

func TestAnchorSTH_NilTxLog_503(t *testing.T) {
	h := newAdminHarness(t)
	sess, _ := h.loginAs(h.priv, h.pub)
	resp, _ := h.doRaw("POST", "/admin/api/anchor-sth", nil, map[string]string{cookieName: sess})
	if resp.StatusCode != 503 {
		t.Fatalf("status: %d, want 503 (no TxLog wired)", resp.StatusCode)
	}
}

func TestCalendarAllowed(t *testing.T) {
	svc := &Service{
		OTSCalendarURL:       "https://calendar.example/digest/",
		OTSCalendarAllowlist: []string{"https://backup.example/digest"},
	}
	if !svc.calendarAllowed("https://calendar.example/digest") {
		t.Fatalf("configured calendar should be allowed")
	}
	if !svc.calendarAllowed("https://backup.example/digest/") {
		t.Fatalf("allowlisted calendar should be allowed")
	}
	if svc.calendarAllowed("https://metadata.google.internal/") {
		t.Fatalf("unexpected calendar should be rejected")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
