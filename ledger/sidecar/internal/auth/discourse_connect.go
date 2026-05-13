// Package auth wires Discourse SSO into the sidecar.
//
// Flow: GET /auth/discourse/login → redirect → Discourse → GET /auth/discourse/callback → set session cookie → 302
//
// Session cookie format (`fp_session`):
//
//	base64url(JSON{discourse_id, username, exp_unix}) "." hex(HMAC-SHA256(SESSION_SECRET, payload))
//
// State cookie (`fp_oauth_state`) carries the SSO nonce so we don't need any server-side session store.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type DiscourseConnect struct {
	// Provider shared secret (Discourse Admin → discourse_connect_provider_secrets)
	Secret []byte
	// Forum HTTPS base URL, e.g. "https://forum.example.com"
	ForumBase string
	// Our public callback URL, e.g. "https://forum.example.com/wallet/auth/discourse/callback"
	CallbackURL string
	// SecureCookies = true in production (HTTPS)
	SecureCookies bool
}

const (
	stateCookieName   = "fp_oauth_state"
	stateCookieMaxAge = 600 // 10 min
	SessionCookieName = "fp_session"
	sessionTTL        = 24 * time.Hour
)

// Login redirects the user to Discourse's session/sso_provider endpoint with a signed payload.
func (d *DiscourseConnect) Login(w http.ResponseWriter, r *http.Request) {
	nonce := randomHex(16)
	returnURL := safeReturnURL(r.URL.Query().Get("return"), d.ForumBase)

	// Stash nonce + returnURL in a short-lived signed state cookie.
	state := stateCookieValue{Nonce: nonce, Return: returnURL, Exp: time.Now().Unix() + stateCookieMaxAge}
	stateB, _ := json.Marshal(state)
	stateMAC := mac(d.Secret, stateB)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(stateB) + "." + hex.EncodeToString(stateMAC),
		Path:     "/wallet/",
		MaxAge:   stateCookieMaxAge,
		HttpOnly: true,
		Secure:   d.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	// Build SSO payload: nonce=...&return_sso_url=...
	payload := url.Values{}
	payload.Set("nonce", nonce)
	payload.Set("return_sso_url", d.CallbackURL)
	encoded := base64.StdEncoding.EncodeToString([]byte(payload.Encode()))
	sig := hex.EncodeToString(mac(d.Secret, []byte(encoded)))

	q := url.Values{}
	q.Set("sso", encoded)
	q.Set("sig", sig)
	http.Redirect(w, r, d.ForumBase+"/session/sso_provider?"+q.Encode(), http.StatusFound)
}

// Callback consumes Discourse's response, verifies sig + nonce, and sets the fp_session cookie.
func (d *DiscourseConnect) Callback(w http.ResponseWriter, r *http.Request) {
	sso := r.URL.Query().Get("sso")
	sig := r.URL.Query().Get("sig")
	if sso == "" || sig == "" {
		http.Error(w, "missing sso or sig", http.StatusBadRequest)
		return
	}
	gotSig, err := hex.DecodeString(sig)
	if err != nil {
		http.Error(w, "bad sig hex", http.StatusBadRequest)
		return
	}
	wantSig := mac(d.Secret, []byte(sso))
	if !hmac.Equal(gotSig, wantSig) {
		http.Error(w, "sso signature mismatch", http.StatusUnauthorized)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(sso)
	if err != nil {
		http.Error(w, "bad sso b64", http.StatusBadRequest)
		return
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		http.Error(w, "bad sso payload", http.StatusBadRequest)
		return
	}

	// Verify nonce from state cookie matches the one in the payload
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "missing state cookie (start over with /auth/discourse/login)", http.StatusUnauthorized)
		return
	}
	state, err := parseStateCookie(stateCookie.Value, d.Secret)
	if err != nil {
		http.Error(w, "bad state cookie: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if state.Nonce != values.Get("nonce") {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	dscIDStr := values.Get("external_id")
	dscID, err := strconv.ParseInt(dscIDStr, 10, 64)
	if err != nil || dscID <= 0 {
		http.Error(w, "bad external_id", http.StatusBadRequest)
		return
	}
	username := values.Get("username")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}

	// Mint session cookie
	tok := SessionToken{
		DiscourseID: dscID,
		Username:    username,
		ExpUnix:     time.Now().Add(sessionTTL).Unix(),
	}
	cookieVal := SignSession(tok, d.Secret)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    cookieVal,
		Path:     "/wallet/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   d.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/wallet/", MaxAge: -1})

	redirectTo := state.Return
	if redirectTo == "" {
		redirectTo = d.ForumBase
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func safeReturnURL(raw, forumBase string) string {
	if raw == "" {
		return forumBase
	}
	u, err := url.Parse(raw)
	if err != nil {
		return forumBase
	}
	if !u.IsAbs() {
		if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
			return raw
		}
		return forumBase
	}
	base, err := url.Parse(forumBase)
	if err != nil {
		return forumBase
	}
	if strings.EqualFold(u.Scheme, base.Scheme) && strings.EqualFold(u.Host, base.Host) {
		return raw
	}
	return forumBase
}

// Logout clears the session cookie.
func (d *DiscourseConnect) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: "", Path: "/wallet/", MaxAge: -1,
		HttpOnly: true, Secure: d.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// SessionToken is the payload of a fp_session cookie.
type SessionToken struct {
	DiscourseID int64  `json:"discourse_id"`
	Username    string `json:"username"`
	ExpUnix     int64  `json:"exp_unix"`
}

func SignSession(t SessionToken, secret []byte) string {
	b, _ := json.Marshal(t)
	enc := base64.RawURLEncoding.EncodeToString(b)
	sig := mac(secret, []byte(enc))
	return enc + "." + hex.EncodeToString(sig)
}

func VerifySession(s string, secret []byte) (*SessionToken, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("bad session format")
	}
	gotSig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad sig hex: %w", err)
	}
	wantSig := mac(secret, []byte(parts[0]))
	if !hmac.Equal(gotSig, wantSig) {
		return nil, errors.New("session signature mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("bad b64: %w", err)
	}
	var tok SessionToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, err
	}
	if time.Now().Unix() > tok.ExpUnix {
		return nil, errors.New("session expired")
	}
	return &tok, nil
}

type stateCookieValue struct {
	Nonce  string `json:"nonce"`
	Return string `json:"return"`
	Exp    int64  `json:"exp"`
}

func parseStateCookie(v string, secret []byte) (*stateCookieValue, error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("bad state format")
	}
	gotSig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	wantSig := mac(secret, raw)
	if !hmac.Equal(gotSig, wantSig) {
		return nil, errors.New("state signature mismatch")
	}
	var s stateCookieValue
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if time.Now().Unix() > s.Exp {
		return nil, errors.New("state expired")
	}
	return &s, nil
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
