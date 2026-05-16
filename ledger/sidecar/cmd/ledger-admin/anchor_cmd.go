package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/forum-points/ledger/internal/discoursebot"
	"github.com/forum-points/ledger/internal/ots"
	"github.com/forum-points/ledger/internal/store"
	"github.com/forum-points/ledger/internal/txlog"
)

func cmdAnchorSTH(args []string) {
	fs := flag.NewFlagSet("anchor-sth", flag.ExitOnError)
	defaultCalendar := os.Getenv("OTS_CALENDAR_URL")
	if defaultCalendar == "" {
		defaultCalendar = ots.DefaultCalendar
	}
	calendar := fs.String("calendar", defaultCalendar, "OpenTimestamps calendar URL")
	_ = fs.Parse(args)

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	privHex := os.Getenv("STH_PRIV_KEY_HEX")
	if privHex == "" {
		privHex = os.Getenv("ADMIN_PRIV_KEY_HEX")
	}
	if privHex == "" {
		log.Fatal("STH_PRIV_KEY_HEX is required (legacy fallback: ADMIN_PRIV_KEY_HEX)")
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("STH_PRIV_KEY_HEX must be 128-char hex Ed25519 private key")
	}

	ctx := context.Background()
	pg, err := store.NewPGStore(ctx, dsn)
	if err != nil {
		log.Fatalf("connect pg: %v", err)
	}
	defer pg.Close()
	if err := pg.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	svc := &txlog.Service{
		Pool:         pg.Pool(),
		AdminPrivKey: ed25519.PrivateKey(priv),
		AdminPubKey:  ed25519.PrivateKey(priv).Public().(ed25519.PublicKey),
	}

	sth, err := svc.CurrentSTH(ctx)
	if err != nil {
		log.Fatalf("current STH: %v", err)
	}
	if sth.TreeSize == 0 {
		log.Fatal("tree is empty; nothing to anchor")
	}

	rootHash, _ := hex.DecodeString(sth.RootHash)
	canonical := txlog.SignedSTHBytes(sth.TreeSize, rootHash, sth.TimestampMS)
	digest := ots.DigestSTH(canonical)

	fmt.Printf("anchoring STH:\n")
	fmt.Printf("  tree_size:  %d\n", sth.TreeSize)
	fmt.Printf("  root_hash:  %s\n", sth.RootHash)
	fmt.Printf("  digest:     %s\n", hex.EncodeToString(digest))
	fmt.Printf("  calendar:   %s\n", *calendar)
	fmt.Println()

	receipt, err := ots.Submit(ctx, *calendar, digest)
	if err != nil {
		log.Fatalf("ots submit: %v", err)
	}
	fmt.Printf("got receipt: %d bytes\n", len(receipt))
	fmt.Printf("  receipt_hex (first 80B): %s…\n", hex.EncodeToString(receipt[:min(80, len(receipt))]))

	if err := ots.AnchorCheckpoint(ctx, pg.Pool(), sth.TreeSize, receipt); err != nil {
		log.Fatalf("store receipt: %v", err)
	}
	fmt.Println("receipt stored in checkpoints table ✓")
}

func cmdPublishSTH(args []string) {
	fs := flag.NewFlagSet("publish-sth", flag.ExitOnError)
	apiBase := fs.String("discourse-api", "", "Discourse base URL")
	apiKey := fs.String("api-key", "", "Discourse Admin API key")
	apiUser := fs.String("api-username", "system", "Discourse Admin API username")
	topicID := fs.Int("topic-id", 0, "existing topic ID to reply to (0 = create new topic)")
	title := fs.String("title", "", "title for the new topic (when --topic-id=0)")
	categoryID := fs.Int("category", 0, "category for new topic (0 = default)")
	pinNew := fs.Bool("pin", true, "pin the topic on creation")
	_ = fs.Parse(args)

	dsn := os.Getenv("DATABASE_URL")
	privHex := os.Getenv("STH_PRIV_KEY_HEX")
	if privHex == "" {
		privHex = os.Getenv("ADMIN_PRIV_KEY_HEX")
	}
	if dsn == "" || privHex == "" {
		log.Fatal("DATABASE_URL and STH_PRIV_KEY_HEX are required (legacy fallback: ADMIN_PRIV_KEY_HEX)")
	}
	if *apiBase == "" || *apiKey == "" {
		log.Fatal("--discourse-api and --api-key are required")
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("STH_PRIV_KEY_HEX malformed")
	}

	ctx := context.Background()
	pg, err := store.NewPGStore(ctx, dsn)
	if err != nil {
		log.Fatalf("connect pg: %v", err)
	}
	defer pg.Close()
	if err := pg.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	svc := &txlog.Service{
		Pool:         pg.Pool(),
		AdminPrivKey: ed25519.PrivateKey(priv),
		AdminPubKey:  ed25519.PrivateKey(priv).Public().(ed25519.PublicKey),
	}

	sth, err := svc.CurrentSTH(ctx)
	if err != nil {
		log.Fatalf("current STH: %v", err)
	}

	// Try to fetch the stored receipt (if anchored)
	var receipt []byte
	row := pg.Pool().QueryRow(ctx, `SELECT ots_receipt FROM checkpoints WHERE tree_size = $1`, sth.TreeSize)
	_ = row.Scan(&receipt)

	body := formatSTHPost(sth, receipt)
	c := discoursebot.New(*apiBase, *apiKey, *apiUser)
	if *topicID == 0 {
		t := *title
		if t == "" {
			t = fmt.Sprintf("Forum Points — Daily STH %s", time.Now().UTC().Format("2006-01-02"))
		}
		resp, err := c.CreateTopic(ctx, t, body, *categoryID)
		if err != nil {
			log.Fatalf("create topic: %v", err)
		}
		fmt.Printf("created topic id=%d slug=%s post_id=%d\n", resp.TopicID, resp.TopicSlug, resp.ID)
		if *pinNew && resp.TopicID > 0 {
			if err := c.PinTopic(ctx, resp.TopicID, ""); err != nil {
				fmt.Printf("(pin failed, non-fatal: %v)\n", err)
			} else {
				fmt.Println("pinned ✓")
			}
		}
	} else {
		resp, err := c.ReplyToTopic(ctx, *topicID, body)
		if err != nil {
			log.Fatalf("reply: %v", err)
		}
		fmt.Printf("replied to topic %d as post_id=%d\n", *topicID, resp.ID)
	}
}

func formatSTHPost(sth *txlog.STH, receipt []byte) string {
	hasReceipt := len(receipt) > 0
	receiptBlock := "_(no OTS receipt yet — run `ledger-admin anchor-sth` first)_"
	if hasReceipt {
		receiptBlock = "**OTS receipt** (Bitcoin-anchored, pending confirmation):\n\n```\n" +
			base64.StdEncoding.EncodeToString(receipt) + "\n```"
	}
	return fmt.Sprintf(`# Forum Points — Signed Tree Head

Public, tamper-evident state of the `+"`forum-points-ledger`"+` Merkle log at this checkpoint.

| field | value |
|---|---|
| tree_size | %d |
| root_hash | `+"`%s`"+` |
| timestamp_ms | %d (%s UTC) |
| admin_pubkey | `+"`%s`"+` |

**Signature** (Ed25519 over canonical STH bytes):
`+"```\n%s\n```"+`

%s

---

**How to verify this checkpoint independently**
`+"```bash"+`
# Build the verifier from source:
git clone <repo>; cd ledger/sidecar
go build ./cmd/ledger-verify

# Run a full audit against the public API:
./ledger-verify -target https://forum.example.com/wallet -samples 100
`+"```"+`

The verifier independently checks:
- every transaction's Ed25519 signature
- the prev-hash chain (no rewrites in history)
- the Merkle root matches this STH
- random inclusion proofs
- a consistency proof from a prior STH

_Generated automatically; do not edit._`,
		sth.TreeSize, sth.RootHash, sth.TimestampMS,
		time.UnixMilli(sth.TimestampMS).UTC().Format(time.RFC3339),
		sth.AdminPubKey, sth.AdminSig, receiptBlock,
	)
}

// Silence unused import in older builds:
var _ = http.MethodGet
