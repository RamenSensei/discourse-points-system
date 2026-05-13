package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/forum-points/ledger/internal/ledger"
	"github.com/forum-points/ledger/internal/store"
)

func cmdReclaimInvalid(args []string) {
	fs := flag.NewFlagSet("reclaim-invalid", flag.ExitOnError)
	fromID := fs.Int64("from", 0, "negative discourse_id to reclaim from")
	amount := fs.Int64("amount", 0, "amount to reclaim; 0 means full account balance")
	memo := fs.String("memo", "", "audit memo")
	_ = fs.Parse(args)

	if *fromID >= ledger.TreasuryDscID {
		log.Fatal("--from must be a negative discourse_id")
	}

	dsn := os.Getenv("DATABASE_URL")
	privHex := os.Getenv("ADMIN_PRIV_KEY_HEX")
	if dsn == "" || privHex == "" {
		log.Fatal("DATABASE_URL and ADMIN_PRIV_KEY_HEX are required")
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("ADMIN_PRIV_KEY_HEX must be 128-char hex Ed25519 private key")
	}
	adminPriv := ed25519.PrivateKey(priv)
	adminPub := adminPriv.Public().(ed25519.PublicKey)

	ctx := context.Background()
	pg, err := store.NewPGStore(ctx, dsn)
	if err != nil {
		log.Fatalf("connect pg: %v", err)
	}
	defer pg.Close()
	if err := pg.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	stx, err := pg.Begin(ctx)
	if err != nil {
		log.Fatalf("begin: %v", err)
	}
	admin, err := stx.GetAccountByPubKey(ctx, adminPub)
	if err != nil {
		_ = stx.Rollback(ctx)
		log.Fatalf("admin lookup: %v", err)
	}
	from, err := stx.GetAccountByDiscourseID(ctx, *fromID)
	if err != nil {
		_ = stx.Rollback(ctx)
		log.Fatalf("invalid account lookup: %v", err)
	}
	_ = stx.Rollback(ctx)
	if admin == nil || admin.DiscourseID != ledger.TreasuryDscID {
		log.Fatal("admin/treasury account not found")
	}
	if from == nil {
		log.Fatalf("account %d not found", *fromID)
	}
	if len(from.Pubkey) > 0 {
		log.Fatalf("account %d is activated; refusing reclaim", *fromID)
	}
	reclaimAmount := *amount
	if reclaimAmount == 0 {
		reclaimAmount = from.Balance
	}
	if reclaimAmount <= 0 {
		log.Fatalf("nothing to reclaim: amount=%d balance=%d", reclaimAmount, from.Balance)
	}

	payload := ledger.ReclaimInvalidPayload{
		Admin:           adminPub,
		FromDiscourseID: *fromID,
		Amount:          reclaimAmount,
		Nonce:           admin.Nonce + 1,
		Memo:            *memo,
	}
	payloadBytes, err := ledger.CanonicalJSON(payload)
	if err != nil {
		log.Fatal(err)
	}
	tx := &ledger.Tx{
		Type:    ledger.TxReclaimInvalid,
		Payload: payloadBytes,
		Sig:     ed25519.Sign(adminPriv, payloadBytes),
		Signer:  adminPub,
	}
	if err := ledger.Apply(ctx, pg, tx); err != nil {
		log.Fatalf("apply reclaim_invalid: %v", err)
	}
	fmt.Printf("reclaimed %d pts from discourse_id=%d into treasury\n", reclaimAmount, *fromID)
	fmt.Printf("  leaf_index: %d\n", tx.LeafIndex)
	fmt.Printf("  tx_hash:    %s\n", hex.EncodeToString(tx.TxHash))
}
