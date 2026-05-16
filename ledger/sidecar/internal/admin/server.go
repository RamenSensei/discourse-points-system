// Package admin provides the admin Web UI: challenge-response auth + dashboard
// + reward-config editor + manual audit triggers.
package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/forum-points/ledger/internal/ledger"
	"github.com/forum-points/ledger/internal/ots"
	"github.com/forum-points/ledger/internal/txlog"
)

//go:embed static/*
var staticFS embed.FS

const (
	loginTTL       = 5 * time.Minute
	sessionTTL     = 1 * time.Hour
	cookieName     = "fp_admin_session"
	stateCookieMax = 600
)

type Service struct {
	AdminPubKey          ed25519.PublicKey
	SessionSecret        []byte
	Pool                 *pgxpool.Pool
	TxLog                *txlog.Service // optional, for STH info
	SecureCookies        bool
	OTSCalendarURL       string
	OTSCalendarAllowlist []string
	SubmitOTS            func(ctx context.Context, calendarURL string, digest []byte) ([]byte, error)
}

// Mount installs /admin/* routes on the given router.
func (s *Service) Mount(r chi.Router) {
	r.Mount("/admin/static/", http.StripPrefix("/admin/static/", staticHandler()))
	r.Get("/admin/", s.indexHandler)
	r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/wallet/admin/", http.StatusFound)
	})

	r.Get("/admin/api/login-challenge", s.loginChallenge)
	r.Post("/admin/api/login", s.login)
	r.Post("/admin/api/logout", s.logout)
	r.Get("/admin/api/whoami", s.whoami)

	// Protected endpoints
	r.Group(func(r chi.Router) {
		r.Use(s.requireAdmin)
		r.Get("/admin/api/dashboard", s.dashboard)
		r.Get("/admin/api/reward-config", s.getRewardConfig)
		r.Post("/admin/api/reward-config", s.updateRewardConfig)
		r.Get("/admin/api/recent-txs", s.recentTxs)
		r.Get("/admin/api/accounts", s.accounts)
		r.Get("/admin/api/anchor-sth", s.anchorDigest)
		r.Post("/admin/api/anchor-sth", s.anchorSTH)
	})
}

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || strings.HasPrefix(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, sub, name)
	})
}

func (s *Service) indexHandler(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "missing index", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// --- auth ---

type challengeToken struct {
	Nonce string `json:"n"`
	Exp   int64  `json:"e"`
}

func (s *Service) loginChallenge(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	tok := challengeToken{Nonce: hex.EncodeToString(nonce), Exp: time.Now().Add(loginTTL).Unix()}
	j, _ := json.Marshal(tok)
	enc := base64.RawURLEncoding.EncodeToString(j)
	sig := mac(s.SessionSecret, []byte(enc))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"nonce_hex": tok.Nonce,
		"token":     enc + "." + hex.EncodeToString(sig),
	})
}

type loginReq struct {
	Token     string `json:"token"`
	SigHex    string `json:"sig_hex"`
	PubKeyHex string `json:"pubkey_hex"`
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	parts := strings.SplitN(req.Token, ".", 2)
	if len(parts) != 2 {
		writeErr(w, http.StatusBadRequest, errors.New("bad token"))
		return
	}
	gotSig, _ := hex.DecodeString(parts[1])
	wantSig := mac(s.SessionSecret, []byte(parts[0]))
	if !hmac.Equal(gotSig, wantSig) {
		writeErr(w, http.StatusUnauthorized, errors.New("token signature mismatch"))
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var tok challengeToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if time.Now().Unix() > tok.Exp {
		writeErr(w, http.StatusUnauthorized, errors.New("challenge expired; reload page"))
		return
	}

	pubBytes, err := hex.DecodeString(req.PubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, errors.New("bad pubkey_hex"))
		return
	}
	if !hmac.Equal(pubBytes, []byte(s.AdminPubKey)) {
		writeErr(w, http.StatusForbidden, errors.New("not the admin pubkey"))
		return
	}
	sig, err := hex.DecodeString(req.SigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		writeErr(w, http.StatusBadRequest, errors.New("bad sig_hex"))
		return
	}
	nonceBytes, _ := hex.DecodeString(tok.Nonce)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), nonceBytes, sig) {
		writeErr(w, http.StatusUnauthorized, errors.New("signature does not verify"))
		return
	}

	// Mint session cookie
	sess := sessionToken{ExpUnix: time.Now().Add(sessionTTL).Unix()}
	cookieVal := signSession(sess, s.SessionSecret)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieVal,
		Path:     "/wallet/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"admin":      req.PubKeyHex,
		"expires_at": sess.ExpUnix,
		"csrf_token": csrfToken(s.SessionSecret, cookieVal),
	})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/wallet/", MaxAge: -1,
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) whoami(w http.ResponseWriter, r *http.Request) {
	c, err := s.adminSessionCookie(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"admin_pubkey_hex": hex.EncodeToString(s.AdminPubKey),
		"csrf_token":       csrfToken(s.SessionSecret, c.Value),
	})
}

type sessionToken struct {
	ExpUnix int64 `json:"e"`
}

func signSession(t sessionToken, secret []byte) string {
	b, _ := json.Marshal(t)
	enc := base64.RawURLEncoding.EncodeToString(b)
	sig := mac(secret, []byte(enc))
	return enc + "." + hex.EncodeToString(sig)
}

func verifySession(s string, secret []byte) (*sessionToken, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("bad cookie format")
	}
	gotSig, _ := hex.DecodeString(parts[1])
	wantSig := mac(secret, []byte(parts[0]))
	if !hmac.Equal(gotSig, wantSig) {
		return nil, errors.New("signature mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var t sessionToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	if time.Now().Unix() > t.ExpUnix {
		return nil, errors.New("expired")
	}
	return &t, nil
}

func csrfToken(secret []byte, sessionValue string) string {
	return hex.EncodeToString(mac(secret, []byte("csrf|"+sessionValue)))
}

func validCSRF(secret []byte, sessionValue, got string) bool {
	want := csrfToken(secret, sessionValue)
	return hmac.Equal([]byte(got), []byte(want))
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func sameOriginWrite(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Service) isAuthed(r *http.Request) bool {
	_, err := s.adminSessionCookie(r)
	return err == nil
}

func (s *Service) adminSessionCookie(r *http.Request) (*http.Cookie, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, err
	}
	if _, err := verifySession(c.Value, s.SessionSecret); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Service) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := s.adminSessionCookie(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, errors.New("admin auth required"))
			return
		}
		if isUnsafeMethod(r.Method) {
			if !sameOriginWrite(r) {
				writeErr(w, http.StatusForbidden, errors.New("cross-origin admin write rejected"))
				return
			}
			if !validCSRF(s.SessionSecret, c.Value, r.Header.Get("X-FP-CSRF")) {
				writeErr(w, http.StatusForbidden, errors.New("missing or invalid csrf token"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- dashboard data ---

func (s *Service) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{}

	var supplyCirc int64
	_ = s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(balance), 0) FROM accounts`).Scan(&supplyCirc)
	var treasury int64
	_ = s.Pool.QueryRow(ctx, `SELECT balance FROM accounts WHERE discourse_id = 0`).Scan(&treasury)
	var txCount, acctCount, activatedCount int64
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM transactions`).Scan(&txCount)
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM accounts`).Scan(&acctCount)
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM accounts WHERE pubkey IS NOT NULL`).Scan(&activatedCount)

	out["supply_circulating"] = supplyCirc
	out["supply_cap"] = ledger.SupplyCap
	out["treasury_balance"] = treasury
	out["tx_count"] = txCount
	out["account_count"] = acctCount
	out["activated_count"] = activatedCount

	// STH
	if s.TxLog != nil {
		sth, err := s.TxLog.CurrentSTH(ctx)
		if err == nil {
			out["sth"] = sth
		}
	}

	// Checkpoint with OTS
	var lastSize int64
	var hasReceipt bool
	_ = s.Pool.QueryRow(ctx,
		`SELECT tree_size, ots_receipt IS NOT NULL FROM checkpoints ORDER BY tree_size DESC LIMIT 1`,
	).Scan(&lastSize, &hasReceipt)
	out["last_checkpoint_size"] = lastSize
	out["last_checkpoint_has_ots"] = hasReceipt

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Service) getRewardConfig(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(),
		`SELECT event_type, amount, enabled, updated_at FROM reward_config ORDER BY event_type`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var eventType string
		var amount int64
		var enabled bool
		var updatedAt time.Time
		if err := rows.Scan(&eventType, &amount, &enabled, &updatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, map[string]any{
			"event_type": eventType,
			"amount":     amount,
			"enabled":    enabled,
			"updated_at": updatedAt.UTC().Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type updateRewardReq struct {
	EventType string `json:"event_type"`
	Amount    int64  `json:"amount"`
	Enabled   bool   `json:"enabled"`
}

func (s *Service) updateRewardConfig(w http.ResponseWriter, r *http.Request) {
	var req updateRewardReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Amount < 0 {
		writeErr(w, http.StatusBadRequest, errors.New("amount must be ≥ 0"))
		return
	}
	if req.EventType == "" {
		writeErr(w, http.StatusBadRequest, errors.New("event_type required"))
		return
	}
	tag, err := s.Pool.Exec(r.Context(),
		`UPDATE reward_config SET amount=$2, enabled=$3, updated_at=now() WHERE event_type=$1`,
		req.EventType, req.Amount, req.Enabled,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if tag.RowsAffected() == 0 {
		// Insert if not present
		_, err = s.Pool.Exec(r.Context(),
			`INSERT INTO reward_config (event_type, amount, enabled) VALUES ($1, $2, $3)
			 ON CONFLICT (event_type) DO UPDATE SET amount=$2, enabled=$3, updated_at=now()`,
			req.EventType, req.Amount, req.Enabled,
		)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Service) recentTxs(w http.ResponseWriter, r *http.Request) {
	limit := 25
	rows, err := s.Pool.Query(r.Context(), `
		SELECT t.leaf_index, t.tx_type,
		       COALESCE(t.amount, 0)                                                               AS amount,
		       COALESCE(t.to_discourse_id, -1)                                                     AS to_did,
		       COALESCE(t.reward_source, '')                                                       AS reward_source,
		       to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')               AS created_at,
		       encode(t.tx_hash, 'hex')                                                              AS tx_hash_hex,
		       COALESCE(a_from.discourse_id, -1)                                                     AS from_did,
		       COALESCE(a_to.username, '')                                                           AS to_name,
		       COALESCE(a_from.username, '')                                                         AS from_name
		  FROM transactions t
		  LEFT JOIN accounts a_from ON a_from.pubkey = t.signer
		  LEFT JOIN accounts a_to   ON a_to.discourse_id = t.to_discourse_id
		 ORDER BY t.leaf_index DESC
		 LIMIT $1`, limit,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var leafIdx int64
		var txType string
		var amount int64
		var toDID int64
		var rewardSrc, createdAt, txHash, toName, fromName string
		var fromDID int64
		if err := rows.Scan(&leafIdx, &txType, &amount, &toDID, &rewardSrc, &createdAt, &txHash, &fromDID, &toName, &fromName); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, map[string]any{
			"leaf_index":    leafIdx,
			"tx_type":       txType,
			"amount":        amount,
			"from_did":      fromDID,
			"from_name":     fromName,
			"to_did":        toDID,
			"to_name":       toName,
			"reward_source": rewardSrc,
			"created_at":    createdAt,
			"tx_hash_hex":   txHash,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"count": len(out), "entries": out})
}

func (s *Service) accounts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), `
		SELECT discourse_id, COALESCE(encode(pubkey, 'hex'), ''), username, balance, nonce,
		       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(COALESCE(activated_at, 'epoch'::timestamptz) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS activated_at
		  FROM accounts
		 ORDER BY balance DESC
		 LIMIT 200`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var did int64
		var pubHex, username, createdAt, activatedAt string
		var balance, nonce int64
		if err := rows.Scan(&did, &pubHex, &username, &balance, &nonce, &createdAt, &activatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, map[string]any{
			"discourse_id": did,
			"pubkey_hex":   pubHex,
			"username":     username,
			"balance":      balance,
			"nonce":        nonce,
			"activated":    pubHex != "",
			"created_at":   createdAt,
			"activated_at": activatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"count": len(out), "accounts": out})
}

type anchorReq struct {
	CalendarURL string `json:"calendar_url"`
	Force       bool   `json:"force"`
}

type anchorMaterial struct {
	STH       *txlog.STH
	Digest    []byte
	Canonical []byte
}

func (s *Service) currentAnchorMaterial(ctx context.Context) (*anchorMaterial, error) {
	if s.TxLog == nil {
		return nil, errors.New("STH service not configured")
	}
	sth, err := s.TxLog.CurrentSTH(ctx)
	if err != nil {
		return nil, err
	}
	rootBytes, _ := hex.DecodeString(sth.RootHash)
	canonical := txlog.SignedSTHBytes(sth.TreeSize, rootBytes, sth.TimestampMS)
	return &anchorMaterial{
		STH:       sth,
		Digest:    ots.DigestSTH(canonical),
		Canonical: canonical,
	}, nil
}

func (s *Service) anchorDigest(w http.ResponseWriter, r *http.Request) {
	if s.TxLog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("STH service not configured"))
		return
	}
	mat, err := s.currentAnchorMaterial(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sth":              mat.STH,
		"canonical_msg":    hex.EncodeToString(mat.Canonical),
		"digest_to_anchor": hex.EncodeToString(mat.Digest),
	})
}

func (s *Service) anchorSTH(w http.ResponseWriter, r *http.Request) {
	if s.TxLog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("STH service not configured"))
		return
	}
	if s.Pool == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("database pool not configured"))
		return
	}

	var req anchorReq
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}

	mat, err := s.currentAnchorMaterial(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if mat.STH.TreeSize == 0 {
		writeErr(w, http.StatusConflict, errors.New("tree is empty; nothing to anchor"))
		return
	}

	var existingReceipt []byte
	_ = s.Pool.QueryRow(r.Context(),
		`SELECT ots_receipt FROM checkpoints WHERE tree_size = $1`,
		mat.STH.TreeSize,
	).Scan(&existingReceipt)
	if len(existingReceipt) > 0 && !req.Force {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":               true,
			"already_anchored": true,
			"sth":              mat.STH,
			"digest_to_anchor": hex.EncodeToString(mat.Digest),
			"receipt_len":      len(existingReceipt),
			"receipt_b64":      base64.StdEncoding.EncodeToString(existingReceipt),
		})
		return
	}

	calendar := req.CalendarURL
	if calendar == "" {
		calendar = s.OTSCalendarURL
	}
	if calendar == "" {
		calendar = ots.DefaultCalendar
	}
	if !s.calendarAllowed(calendar) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("calendar_url is not allowed: %s", calendar))
		return
	}
	submit := s.SubmitOTS
	if submit == nil {
		submit = ots.Submit
	}

	receipt, err := submit(r.Context(), calendar, mat.Digest)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if err := ots.AnchorCheckpoint(r.Context(), s.Pool, mat.STH.TreeSize, receipt); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"already_anchored": false,
		"sth":              mat.STH,
		"calendar":         calendar,
		"digest_to_anchor": hex.EncodeToString(mat.Digest),
		"receipt_len":      len(receipt),
		"receipt_b64":      base64.StdEncoding.EncodeToString(receipt),
	})
}

// --- helpers ---

func (s *Service) calendarAllowed(calendar string) bool {
	if calendar == "" {
		return false
	}
	allowed := []string{ots.DefaultCalendar}
	if s.OTSCalendarURL != "" {
		allowed = append(allowed, s.OTSCalendarURL)
	}
	allowed = append(allowed, s.OTSCalendarAllowlist...)
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimRight(candidate, "/"), strings.TrimRight(calendar, "/")) {
			return true
		}
	}
	return false
}

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// silence unused imports
var _ = context.Background
var _ = fmt.Sprintf
