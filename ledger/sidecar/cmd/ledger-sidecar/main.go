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

	srv := &api.Server{Store: pg, History: &pgHistoryAdapter{pg: pg}}
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
		privHex := os.Getenv("ADMIN_PRIV_KEY_HEX")
		if privHex == "" {
			log.Fatal("ADMIN_PRIV_KEY_HEX required when DISCOURSE_WEBHOOK_SECRET is set (sidecar must sign reward txs)")
		}
		priv, err := hex.DecodeString(privHex)
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			log.Fatal("ADMIN_PRIV_KEY_HEX must be a 128-char hex Ed25519 private key")
		}
		pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
		srv.Rewards = &rewards.Service{
			Store:         pg,
			Rewards:       pg, // PGStore implements rewards.Rewards
			AdminPrivKey:  ed25519.PrivateKey(priv),
			AdminPubKey:   pub,
			WebhookSecret: []byte(wbSecret),
		}
		log.Printf("Discourse webhook handler enabled; admin pubkey=%s", hex.EncodeToString(pub))
	} else {
		log.Println("Discourse webhook handler disabled (set DISCOURSE_WEBHOOK_SECRET to enable)")
	}

	// Tx log + STH service is enabled whenever ADMIN_PRIV_KEY_HEX is present
	// (it's a read-only audit surface — STH signing reuses the admin key).
	if privHex := os.Getenv("ADMIN_PRIV_KEY_HEX"); privHex != "" {
		priv, err := hex.DecodeString(privHex)
		if err == nil && len(priv) == ed25519.PrivateKeySize {
			pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
			srv.TxLog = &txlog.Service{
				Pool:         pg.Pool(),
				AdminPrivKey: ed25519.PrivateKey(priv),
				AdminPubKey:  pub,
			}
			log.Println("Tx log + STH endpoints enabled (/log/sth, /log/leaves, /log/inclusion, /log/consistency)")
		}
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
				AdminPubKey:   ed25519.PublicKey(pub),
				SessionSecret: sessSecret,
				Pool:          pg.Pool(),
				TxLog:         srv.TxLog,
				SecureCookies: os.Getenv("WALLET_INSECURE_COOKIES") != "1",
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
