package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/forum-points/ledger/internal/auth"
	"github.com/forum-points/ledger/internal/explorer"
	"github.com/forum-points/ledger/internal/ledger"
	"github.com/forum-points/ledger/internal/rewards"
)

type Server struct {
	Store   ledger.Store
	DC      *auth.DiscourseConnect // optional; nil disables SSO routes
	Rewards *rewards.Service       // optional; nil disables webhook route
	TxLog   *TxLogService          // optional; nil disables /log/* routes
	History HistoryQuerier         // optional; nil disables /history/:id
	Admin   AdminMounter           // optional; nil disables /admin/*
	// DevHeaderAuthToken enables X-Discourse-* header auth only when callers
	// also present this bearer token in X-Wallet-Dev-Auth. Leave empty in prod.
	DevHeaderAuthToken string
	r                  *chi.Mux
}

// AdminMounter is implemented by *admin.Service. Kept as interface so the api
// package doesn't import admin (admin already imports things from api would be cyclic).
type AdminMounter interface {
	Mount(r chi.Router)
}

// HistoryQuerier abstracts the (PG-only) JSON-on-BYTEA query needed for /history.
type HistoryQuerier interface {
	UserHistory(ctx context.Context, discourseID int64, limit int) ([]HistoryEntry, error)
}

type HistoryEntry struct {
	LeafIndex        int64          `json:"leaf_index"`
	TxType           string         `json:"tx_type"`
	Kind             string         `json:"kind"` // "sent" | "received" | "rotate_key"
	Amount           int64          `json:"amount"`
	FromDiscourseID  int64          `json:"from_discourse_id"`
	ToDiscourseID    int64          `json:"to_discourse_id"`
	CounterpartyName string         `json:"counterparty_name"`
	Meta             map[string]any `json:"meta,omitempty"`
	CreatedAt        string         `json:"created_at"`
	TxHashHex        string         `json:"tx_hash_hex"`
}

func (s *Server) Routes() *chi.Mux {
	s.r = chi.NewRouter()
	s.r.Use(jsonContentType)
	s.r.Get("/api/v1/health", s.health)
	s.r.Get("/api/v1/me", s.me)
	s.r.Post("/api/v1/me/register", s.register)
	s.r.Get("/api/v1/balance/{discourse_id}", s.balance)
	s.r.Get("/api/v1/history/{discourse_id}", s.history)
	s.r.Post("/api/v1/tx", s.submitTx)
	s.r.Get("/api/v1/treasury", s.treasury)
	if s.DC != nil {
		s.r.Get("/auth/discourse/login", s.DC.Login)
		s.r.Get("/auth/discourse/callback", s.DC.Callback)
		s.r.Post("/auth/discourse/logout", s.DC.Logout)
	}
	if s.Rewards != nil {
		s.r.Post("/api/v1/hooks/discourse", s.Rewards.Webhook)
	}
	s.installTxLogRoutes()
	(&explorer.Service{}).Mount(s.r)
	if s.Admin != nil {
		s.Admin.Mount(s.r)
	}
	return s.r
}

func jsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only mark API responses as JSON. Static asset handlers (admin/, explorer/)
		// and HTML SPA shells set their own Content-Type; forcing JSON here would
		// cause browsers to refuse the linked stylesheet under strict MIME rules.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// resolveCurrentUser tries the session cookie first (issued by DiscourseConnect
// SP), then falls back to explicitly token-gated dev-only headers.
func (s *Server) resolveCurrentUser(r *http.Request) (int64, string, error) {
	if s.DC != nil {
		if c, err := r.Cookie(auth.SessionCookieName); err == nil {
			tok, err := auth.VerifySession(c.Value, s.DC.Secret)
			if err == nil {
				return tok.DiscourseID, tok.Username, nil
			}
		}
	}
	if s.DevHeaderAuthToken != "" && constantTimeStringEqual(r.Header.Get("X-Wallet-Dev-Auth"), s.DevHeaderAuthToken) {
		return resolveHeaderUser(r)
	}
	return 0, "", errors.New("not authenticated (no fp_session cookie); visit /wallet/auth/discourse/login")
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func resolveHeaderUser(r *http.Request) (int64, string, error) {
	idStr := r.Header.Get("X-Discourse-User-Id")
	name := r.Header.Get("X-Discourse-Username")
	if idStr == "" || name == "" {
		return 0, "", errors.New("missing X-Discourse-User-Id or X-Discourse-Username (dev auth)")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, "", errors.New("bad X-Discourse-User-Id")
	}
	if id <= 0 {
		return 0, "", errors.New("X-Discourse-User-Id must be positive")
	}
	return id, name, nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, name, err := s.resolveCurrentUser(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	stx, err := s.Store.Begin(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer stx.Rollback(r.Context())
	a, err := stx.GetAccountByDiscourseID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if a == nil {
		// No account at all yet — registration possible, balance is 0.
		writeJSON(w, http.StatusOK, map[string]any{
			"discourse_id": id,
			"username":     name,
			"registered":   false,
			"activated":    false,
			"balance":      0,
			"nonce":        0,
		})
		return
	}
	// Account exists. activated = has pubkey set; balance may be > 0 even if not activated.
	activated := len(a.Pubkey) > 0
	out := accountResponse(a, true)
	out["registered"] = activated // "registered" means "has wallet pubkey", same as activated
	out["activated"] = activated
	writeJSON(w, http.StatusOK, out)
}

type registerReq struct {
	PubKeyHex string `json:"pubkey_hex"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	id, name, err := s.resolveCurrentUser(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	pub, err := hex.DecodeString(req.PubKeyHex)
	if err != nil || len(pub) != ledger.PubKeyLen {
		writeErr(w, http.StatusBadRequest, errors.New("pubkey_hex must be 64-char hex (32 bytes)"))
		return
	}
	if id == ledger.TreasuryDscID {
		writeErr(w, http.StatusBadRequest, errors.New("cannot register treasury account via this endpoint"))
		return
	}
	stx, err := s.Store.Begin(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer stx.Rollback(r.Context())
	existing, err := stx.GetAccountByDiscourseID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	switch {
	case existing == nil:
		// No prior account — create fresh with this pubkey.
		a := &ledger.Account{Pubkey: pub, DiscourseID: id, Username: name}
		if err := stx.UpsertAccount(r.Context(), a); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if err := stx.Commit(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		out := accountResponse(a, true)
		out["activated"] = true
		writeJSON(w, http.StatusCreated, out)

	case len(existing.Pubkey) == 0:
		// Pre-funded account waiting for activation. Attach pubkey + real username.
		if err := stx.UpdateUsernameAndPubKey(r.Context(), id, pub, name); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if err := stx.Commit(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		existing.Pubkey = pub
		existing.Username = name
		out := accountResponse(existing, true)
		out["activated"] = true
		writeJSON(w, http.StatusOK, out)

	case bytesEqual(existing.Pubkey, pub):
		// Idempotent — same pubkey already on file.
		writeJSON(w, http.StatusOK, accountResponse(existing, true))

	default:
		writeErr(w, http.StatusConflict, errors.New("account already has a different pubkey; use rotate_key to change"))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) balance(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "discourse_id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id < ledger.TreasuryDscID {
		writeErr(w, http.StatusBadRequest, errors.New("bad discourse_id"))
		return
	}
	stx, err := s.Store.Begin(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer stx.Rollback(r.Context())
	a, err := stx.GetAccountByDiscourseID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if a == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"discourse_id": id,
			"balance":      0,
			"registered":   false,
			"activated":    false,
		})
		return
	}
	activated := len(a.Pubkey) > 0
	out := accountResponse(a, false)
	out["registered"] = activated
	out["activated"] = activated
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	if s.History == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("history not enabled"))
		return
	}
	idStr := chi.URLParam(r, "discourse_id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id < ledger.TreasuryDscID {
		writeErr(w, http.StatusBadRequest, errors.New("bad discourse_id"))
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, e := strconv.Atoi(l); e == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	entries, err := s.History.UserHistory(r.Context(), id, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"discourse_id": id,
		"count":        len(entries),
		"entries":      entries,
	})
}

func (s *Server) treasury(w http.ResponseWriter, r *http.Request) {
	stx, err := s.Store.Begin(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer stx.Rollback(r.Context())
	t, err := stx.GetAccountByDiscourseID(r.Context(), ledger.TreasuryDscID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	total, err := stx.TotalBalance(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var balance int64
	registered := false
	if t != nil {
		balance = t.Balance
		registered = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"treasury_balance":    balance,
		"treasury_registered": registered,
		"supply_circulating":  total,
		"supply_cap":          ledger.SupplyCap,
		"supply_ok":           total == ledger.SupplyCap,
	})
}

type submitReq struct {
	TxType     string `json:"tx_type"`
	PayloadB64 string `json:"payload_b64"`
	SigB64     string `json:"sig_b64"`
	SignerHex  string `json:"signer_hex"`
}

func (s *Server) submitTx(w http.ResponseWriter, r *http.Request) {
	var req submitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("payload_b64 not base64"))
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.SigB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("sig_b64 not base64"))
		return
	}
	signer, err := hex.DecodeString(req.SignerHex)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("signer_hex not hex"))
		return
	}

	tx := &ledger.Tx{
		Type:    ledger.TxType(req.TxType),
		Payload: payload,
		Sig:     sig,
		Signer:  signer,
	}
	if err := ledger.Apply(r.Context(), s.Store, tx); err != nil {
		// Map known errors to HTTP statuses
		switch {
		case errors.Is(err, ledger.ErrBadSig),
			errors.Is(err, ledger.ErrBadPubKey),
			errors.Is(err, ledger.ErrSignerMismatch),
			errors.Is(err, ledger.ErrSelfTransfer),
			errors.Is(err, ledger.ErrBadAmount),
			errors.Is(err, ledger.ErrBadDiscourseID),
			errors.Is(err, ledger.ErrUnknownTxType):
			writeErr(w, http.StatusBadRequest, err)
		case errors.Is(err, ledger.ErrInsufficientFunds),
			errors.Is(err, ledger.ErrBadNonce):
			writeErr(w, http.StatusUnprocessableEntity, err)
		case errors.Is(err, ledger.ErrGenesisExists):
			writeErr(w, http.StatusConflict, err)
		case errors.Is(err, ledger.ErrUnknownAccount):
			writeErr(w, http.StatusNotFound, err)
		default:
			writeErr(w, http.StatusInternalServerError, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"leaf_index": tx.LeafIndex,
		"tx_hash":    hex.EncodeToString(tx.TxHash),
	})
}

func accountResponse(a *ledger.Account, includeNonce bool) map[string]any {
	out := map[string]any{
		"discourse_id": a.DiscourseID,
		"username":     a.Username,
		"balance":      a.Balance,
	}
	if len(a.Pubkey) > 0 {
		out["pubkey_hex"] = hex.EncodeToString(a.Pubkey)
	} else {
		out["pubkey_hex"] = ""
	}
	out["registered"] = len(a.Pubkey) > 0
	if includeNonce {
		out["nonce"] = a.Nonce
	}
	return out
}
