package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/forum-points/ledger/internal/ledger"
	"github.com/forum-points/ledger/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "init":
		cmdInit(os.Args[2:])
	case "smoke-test":
		cmdSmokeTest(os.Args[2:])
	case "distribute":
		cmdDistribute(os.Args[2:])
	case "reclaim-invalid":
		cmdReclaimInvalid(os.Args[2:])
	case "anchor-sth":
		cmdAnchorSTH(os.Args[2:])
	case "publish-sth":
		cmdPublishSTH(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ledger-admin <keygen|init|smoke-test|distribute|reclaim-invalid|anchor-sth|publish-sth> [flags]")
	fmt.Fprintln(os.Stderr, "  keygen           generate Ed25519 keypair, print hex")
	fmt.Fprintln(os.Stderr, "  init             write genesis tx (50_000_000 pts → treasury)")
	fmt.Fprintln(os.Stderr, "  smoke-test       end-to-end POST /tx exercise against a running sidecar")
	fmt.Fprintln(os.Stderr, "  distribute       backfill signup_bonus + first_post_ever to existing users")
	fmt.Fprintln(os.Stderr, "  reclaim-invalid  append an admin-signed correction from a negative/system account")
	fmt.Fprintln(os.Stderr, "  anchor-sth       submit current STH digest to OpenTimestamps; store receipt")
	fmt.Fprintln(os.Stderr, "  publish-sth      post current STH (with receipt if any) to a Discourse topic")
}

func cmdKeygen(_ []string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pubkey_hex:  %s\n", hex.EncodeToString(pub))
	fmt.Printf("privkey_hex: %s\n", hex.EncodeToString(priv))
	fmt.Println()
	fmt.Println("export ADMIN_PUBKEY_HEX=" + hex.EncodeToString(pub))
	fmt.Println("export ADMIN_PRIV_KEY_HEX=" + hex.EncodeToString(priv) + "   # KEEP SECRET")
}

func cmdInit(args []string) {
	memo := ""
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.StringVar(&memo, "memo", "", "optional memo for genesis tx")
	fs.Parse(args)

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	privHex := os.Getenv("ADMIN_PRIV_KEY_HEX")
	if privHex == "" {
		log.Fatal("ADMIN_PRIV_KEY_HEX is required")
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("ADMIN_PRIV_KEY_HEX must be a 128-char hex Ed25519 private key")
	}
	treasuryUser := os.Getenv("TREASURY_USERNAME")
	if treasuryUser == "" {
		treasuryUser = "TREASURY"
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

	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	payload := ledger.GenesisPayload{
		To:           pub,
		TreasuryUser: treasuryUser,
		Amount:       ledger.SupplyCap,
		Memo:         memo,
	}
	payloadBytes, err := ledger.CanonicalJSON(payload)
	if err != nil {
		log.Fatal(err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), payloadBytes)

	tx := &ledger.Tx{
		Type:    ledger.TxGenesis,
		Payload: payloadBytes,
		Sig:     sig,
		Signer:  pub,
	}

	if err := ledger.Apply(ctx, pg, tx); err != nil {
		log.Fatalf("apply genesis: %v", err)
	}
	fmt.Println("genesis applied:")
	fmt.Printf("  treasury pubkey: %s\n", hex.EncodeToString(pub))
	fmt.Printf("  supply cap:      %d pts\n", ledger.SupplyCap)
	fmt.Printf("  tx_hash:         %s\n", hex.EncodeToString(tx.TxHash))
}
