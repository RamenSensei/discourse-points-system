package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSessionRoundtrip(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	tok := SessionToken{DiscourseID: 42, Username: "alice", ExpUnix: time.Now().Add(time.Hour).Unix()}
	signed := SignSession(tok, secret)
	got, err := VerifySession(signed, secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.DiscourseID != 42 || got.Username != "alice" {
		t.Fatalf("got %+v", got)
	}
}

func TestSessionExpired(t *testing.T) {
	secret := make([]byte, 32)
	tok := SessionToken{DiscourseID: 1, Username: "x", ExpUnix: time.Now().Add(-time.Hour).Unix()}
	signed := SignSession(tok, secret)
	if _, err := VerifySession(signed, secret); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestSessionTampered(t *testing.T) {
	secret := make([]byte, 32)
	tok := SessionToken{DiscourseID: 1, Username: "x", ExpUnix: time.Now().Add(time.Hour).Unix()}
	signed := SignSession(tok, secret)
	parts := []byte(signed)
	parts[0] ^= 0x01
	if _, err := VerifySession(string(parts), secret); err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestLoginRedirectsToDiscourse(t *testing.T) {
	d := &DiscourseConnect{
		Secret:      []byte("test-secret"),
		ForumBase:   "https://forum.test",
		CallbackURL: "https://forum.test/wallet/auth/discourse/callback",
	}
	req := httptest.NewRequest("GET", "/auth/discourse/login?return=/topic/5", nil)
	rec := httptest.NewRecorder()
	d.Login(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://forum.test/session/sso_provider?") {
		t.Fatalf("Location = %q", loc)
	}
	// Should set state cookie
	if rec.Result().Cookies()[0].Name != stateCookieName {
		t.Fatalf("expected state cookie, got %+v", rec.Result().Cookies())
	}
}

func TestLoginRejectsExternalReturnURL(t *testing.T) {
	d := &DiscourseConnect{
		Secret:      []byte("test-secret"),
		ForumBase:   "https://forum.test",
		CallbackURL: "https://forum.test/wallet/auth/discourse/callback",
	}
	req := httptest.NewRequest("GET", "/auth/discourse/login?return=https://evil.test/phish", nil)
	rec := httptest.NewRecorder()
	d.Login(rec, req)
	state, err := parseStateCookie(rec.Result().Cookies()[0].Value, d.Secret)
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if state.Return != "https://forum.test" {
		t.Fatalf("return = %q, want forum base", state.Return)
	}
}

func TestCallbackHappyPath(t *testing.T) {
	d := &DiscourseConnect{
		Secret:      []byte("test-secret"),
		ForumBase:   "https://forum.test",
		CallbackURL: "https://forum.test/wallet/auth/discourse/callback",
	}

	// 1. Login to get state cookie + know what nonce was issued.
	loginReq := httptest.NewRequest("GET", "/auth/discourse/login", nil)
	loginRec := httptest.NewRecorder()
	d.Login(loginRec, loginReq)
	stateCookie := loginRec.Result().Cookies()[0]
	state, err := parseStateCookie(stateCookie.Value, d.Secret)
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}

	// 2. Synthesize a "Discourse callback" with matching nonce
	values := url.Values{}
	values.Set("nonce", state.Nonce)
	values.Set("external_id", "42")
	values.Set("username", "alice")
	encoded := encodeBase64Std(values.Encode())
	sigHex := hexMAC(d.Secret, []byte(encoded))

	cbURL := "/auth/discourse/callback?sso=" + url.QueryEscape(encoded) + "&sig=" + sigHex
	cbReq := httptest.NewRequest("GET", cbURL, nil)
	cbReq.AddCookie(stateCookie)
	cbRec := httptest.NewRecorder()
	d.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", cbRec.Code, cbRec.Body.String())
	}
	// session cookie should be set
	found := false
	for _, c := range cbRec.Result().Cookies() {
		if c.Name == SessionCookieName {
			found = true
			tok, err := VerifySession(c.Value, d.Secret)
			if err != nil {
				t.Fatalf("session verify: %v", err)
			}
			if tok.DiscourseID != 42 || tok.Username != "alice" {
				t.Fatalf("session token = %+v", tok)
			}
		}
	}
	if !found {
		t.Fatalf("session cookie not set; cookies: %+v", cbRec.Result().Cookies())
	}
}

func TestCallbackRejectsBadSig(t *testing.T) {
	d := &DiscourseConnect{Secret: []byte("test-secret"), ForumBase: "https://forum.test"}
	req := httptest.NewRequest("GET", "/auth/discourse/callback?sso=aGVsbG8%3D&sig=00", nil)
	rec := httptest.NewRecorder()
	d.Callback(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// helpers
func encodeBase64Std(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	_ = enc // unused
	return base64StdEncode([]byte(s))
}
