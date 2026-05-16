package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/forum-points/ledger/internal/admin"
	"github.com/forum-points/ledger/internal/api"
	"github.com/forum-points/ledger/internal/auth"
	"github.com/forum-points/ledger/internal/rewards"
	"github.com/forum-points/ledger/internal/store"
	"github.com/forum-points/ledger/internal/txlog"
)

// pgHistoryAdapter wraps PGStore.UserHistory to satisfy api.HistoryQuerier
// (translates the raw row shape into user-facing entries).
type pgHistoryAdapter struct{ pg *store.PGStore }

func (a *pgHistoryAdapter) UserHistory(ctx context.Context, dscID int64, limit int) ([]api.HistoryEntry, error) {
	rows, err := a.pg.UserHistory(ctx, dscID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]api.HistoryEntry, 0, len(rows))
	for _, r := range rows {
		kind := "other"
		switch {
		case r.TxType == "rotate_key":
			kind = "rotate_key"
		case r.FromDscID == dscID:
			kind = "sent"
		case r.ToDscID == dscID:
			kind = "received"
		}
		var meta map[string]any
		if len(r.Meta) > 0 {
			_ = json.Unmarshal(r.Meta, &meta)
		}
		out = append(out, api.HistoryEntry{
			LeafIndex:        r.LeafIndex,
			TxType:           r.TxType,
			Kind:             kind,
			Amount:           r.Amount,
			FromDiscourseID:  r.FromDscID,
			ToDiscourseID:    r.ToDscID,
			CounterpartyName: r.CounterpartyName,
			Meta:             meta,
			CreatedAt:        r.CreatedAt,
			TxHashHex:        r.TxHashHex,
		})
	}
	return out, nil
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18080"
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pg, err := store.NewPGStore(ctx, dsn)
	if err != nil {
		log.Fatalf("connect pg: %v", err)
	}
	defer pg.Close()

	if err := pg.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("migrations OK")

	srv := &api.Server{
		Store:              pg,
		History:            &pgHistoryAdapter{pg: pg},
		RateLimitPerMinute: envInt("WALLET_RATE_LIMIT_PER_MINUTE"),
		RateLimitBurst:     envInt("WALLET_RATE_LIMIT_BURST"),
	}
	if os.Getenv("WALLET_ALLOW_HEADER_AUTH") == "1" {
		tok := os.Getenv("WALLET_DEV_HEADER_AUTH_TOKEN")
		if len(tok) < 32 {
			log.Fatal("WALLET_ALLOW_HEADER_AUTH=1 requires WALLET_DEV_HEADER_AUTH_TOKEN with at least 32 bytes; never enable this in production")
		}
		srv.DevHeaderAuthToken = tok
		log.Println("DEV header auth enabled; requests must include X-Wallet-Dev-Auth")
	}

	if secret := os.Getenv("DISCOURSE_CONNECT_SECRET"); secret != "" {
		forumBase := os.Getenv("FORUM_BASE_URL")
		if forumBase == "" {
			log.Fatal("FORUM_BASE_URL must be set when DISCOURSE_CONNECT_SECRET is set")
		}
		callback := os.Getenv("WALLET_CALLBACK_URL")
		if callback == "" {
			callback = forumBase + "/wallet/auth/discourse/callback"
		}
		srv.DC = &auth.DiscourseConnect{
			Secret:        []byte(secret),
			ForumBase:     forumBase,
			CallbackURL:   callback,
			SecureCookies: os.Getenv("WALLET_INSECURE_COOKIES") != "1",
		}
		log.Printf("DiscourseConnect SP enabled: forum=%s callback=%s", forumBase, callback)
	} else {
		log.Println("DiscourseConnect SP disabled (set DISCOURSE_CONNECT_SECRET to enable)")
	}

	if wbSecret := os.Getenv("DISCOURSE_WEBHOOK_SECRET"); wbSecret != "" {
		priv, ok, err := privateKeyFromEnv("REWARD_PRIV_KEY_HEX", "ADMIN_PRIV_KEY_HEX")
		if err != nil {
			log.Fatal(err)
		}
		if !ok {
			log.Fatal("REWARD_PRIV_KEY_HEX required when DISCOURSE_WEBHOOK_SECRET is set (legacy fallback: ADMIN_PRIV_KEY_HEX)")
		}
		pub := priv.Public().(ed25519.PublicKey)
		srv.Rewards = &rewards.Service{
			Store:         pg,
			Rewards:       pg, // PGStore implements rewards.Rewards
			AdminPrivKey:  priv,
			AdminPubKey:   pub,
			WebhookSecret: []byte(wbSecret),
		}
		log.Printf("Discourse webhook handler enabled; admin pubkey=%s", hex.EncodeToString(pub))
	} else {
		log.Println("Discourse webhook handler disabled (set DISCOURSE_WEBHOOK_SECRET to enable)")
	}

	// Tx log + STH service is enabled when a STH signing key is present.
	// ADMIN_PRIV_KEY_HEX remains as a legacy fallback for single-key installs.
	if priv, ok, err := privateKeyFromEnv("STH_PRIV_KEY_HEX", "ADMIN_PRIV_KEY_HEX"); err != nil {
		log.Fatal(err)
	} else if ok {
		pub := priv.Public().(ed25519.PublicKey)
		srv.TxLog = &txlog.Service{
			Pool:         pg.Pool(),
			AdminPrivKey: priv,
			AdminPubKey:  pub,
		}
		log.Println("Tx log + STH endpoints enabled (/log/sth, /log/leaves, /log/inclusion, /log/consistency)")
	}

	// Admin Web UI — enabled whenever ADMIN_PUBKEY_HEX is configured.
	if pubHex := os.Getenv("ADMIN_PUBKEY_HEX"); pubHex != "" {
		pub, err := hex.DecodeString(pubHex)
		if err == nil && len(pub) == ed25519.PublicKeySize {
			sessSecret := []byte(os.Getenv("ADMIN_SESSION_SECRET"))
			if len(sessSecret) < 32 {
				sessSecret = make([]byte, 32)
				if _, err := cryptorand.Read(sessSecret); err != nil {
					log.Fatalf("rand for admin session secret: %v", err)
				}
				log.Println("ADMIN_SESSION_SECRET not set; using ephemeral (admin sessions lost on restart)")
			}
			srv.Admin = &admin.Service{
				AdminPubKey:          ed25519.PublicKey(pub),
				SessionSecret:        sessSecret,
				Pool:                 pg.Pool(),
				TxLog:                srv.TxLog,
				SecureCookies:        os.Getenv("WALLET_INSECURE_COOKIES") != "1",
				OTSCalendarURL:       os.Getenv("OTS_CALENDAR_URL"),
				OTSCalendarAllowlist: splitCSVEnv("OTS_CALENDAR_ALLOWLIST"),
			}
			log.Println("Admin Web UI enabled at /wallet/admin/ (challenge-sign login with admin Ed25519 key)")
		}
	}

	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      srv.Routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func privateKeyFromEnv(primary, fallback string) (ed25519.PrivateKey, bool, error) {
	value := os.Getenv(primary)
	name := primary
	if value == "" && fallback != "" {
		value = os.Getenv(fallback)
		name = fallback
	}
	if value == "" {
		return nil, false, nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, false, errors.New(name + " must be a 128-char hex Ed25519 private key")
	}
	return ed25519.PrivateKey(raw), true, nil
}

func envInt(name string) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		log.Fatalf("%s must be a non-negative integer", name)
	}
	return n
}

func splitCSVEnv(name string) []string {
	raw := os.Getenv(name)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
