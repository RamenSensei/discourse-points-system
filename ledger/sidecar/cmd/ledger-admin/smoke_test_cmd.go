package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/forum-points/ledger/internal/ledger"
)

func cmdSmokeTest(args []string) {
	fs := flag.NewFlagSet("smoke-test", flag.ExitOnError)
	target := fs.String("target", "http://127.0.0.1:18080", "base URL of running sidecar")
	fs.Parse(args)

	privHex := os.Getenv("ADMIN_PRIV_KEY_HEX")
	if privHex == "" {
		log.Fatal("ADMIN_PRIV_KEY_HEX is required (so the test can move funds from treasury)")
	}
	adminPriv, err := hex.DecodeString(privHex)
	if err != nil || len(adminPriv) != ed25519.PrivateKeySize {
		log.Fatal("ADMIN_PRIV_KEY_HEX must be a 128-char hex Ed25519 private key")
	}
	adminPub := ed25519.PrivateKey(adminPriv).Public().(ed25519.PublicKey)

	if err := getOK(*target + "/api/v1/health"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("health: OK")

	// Generate two user keypairs to play alice & bob
	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)

	// 1. Admin transfers 1000 → alice (id=42) — alice has no prior account, the
	//    apply layer must auto-create her with NULL pubkey.
	treasury := mustGetAccount(*target, 0)
	transfer(*target, ed25519.PrivateKey(adminPriv), adminPub, 42, 1000, treasury.Nonce+1, map[string]any{
		"tip_target_username": "alice",
		"reward_source":       "smoke_test_seed",
	})
	fmt.Printf("admin → alice (auto-created) 1000 pts (nonce=%d)\n", treasury.Nonce+1)

	// 2. Alice activates by registering her pubkey
	register(*target, 42, "alice", alicePub)
	fmt.Println("alice activated her pubkey via /me/register")

	// 3. Alice tips bob (id=43) — bob has no prior account, auto-created on receive
	aliceAcc := mustGetAccount(*target, 42)
	if aliceAcc.Balance != 1000 {
		log.Fatalf("alice balance after seed = %d, want 1000", aliceAcc.Balance)
	}
	transfer(*target, alicePriv, alicePub, 43, 250, aliceAcc.Nonce+1, map[string]any{
		"tip_target_post_id":  1234,
		"tip_target_user_id":  43,
		"tip_target_username": "bob",
	})
	fmt.Println("alice → bob (auto-created) 250 pts")

	// 4. Verify balances
	expectBalance(*target, 42, 750, "alice")
	expectBalance(*target, 43, 250, "bob")
	expectBalance(*target, 0, ledger.SupplyCap-1000, "treasury")

	t := mustGetTreasury(*target)
	if !t.SupplyOK || t.SupplyCirculating != ledger.SupplyCap {
		log.Fatalf("supply violated: %+v", t)
	}
	fmt.Printf("supply OK: circulating=%d cap=%d\n", t.SupplyCirculating, t.SupplyCap)

	fmt.Println("\nALL SMOKE TESTS PASS")
}

type meResponse struct {
	DiscourseID int64  `json:"discourse_id"`
	Username    string `json:"username"`
	PubKeyHex   string `json:"pubkey_hex"`
	Balance     int64  `json:"balance"`
	Nonce       int64  `json:"nonce"`
	Registered  bool   `json:"registered"`
	Activated   bool   `json:"activated"`
}

type treasuryResponse struct {
	SupplyCap          int64 `json:"supply_cap"`
	SupplyCirculating  int64 `json:"supply_circulating"`
	SupplyOK           bool  `json:"supply_ok"`
	TreasuryBalance    int64 `json:"treasury_balance"`
	TreasuryRegistered bool  `json:"treasury_registered"`
}

func register(base string, dscID int64, name string, pub ed25519.PublicKey) {
	body, _ := json.Marshal(map[string]string{"pubkey_hex": hex.EncodeToString(pub)})
	req, _ := http.NewRequest("POST", base+"/api/v1/me/register", bytes.NewReader(body))
	req.Header.Set("X-Discourse-User-Id", fmt.Sprintf("%d", dscID))
	req.Header.Set("X-Discourse-Username", name)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("register %s: %d %s", name, resp.StatusCode, string(b))
	}
}

func mustGetAccount(base string, dscID int64) *meResponse {
	url := fmt.Sprintf("%s/api/v1/balance/%d", base, dscID)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("balance %d: %d %s", dscID, resp.StatusCode, string(b))
	}
	var out meResponse
	json.NewDecoder(resp.Body).Decode(&out)
	return &out
}

func mustGetTreasury(base string) *treasuryResponse {
	resp, err := http.Get(base + "/api/v1/treasury")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var out treasuryResponse
	json.NewDecoder(resp.Body).Decode(&out)
	return &out
}

func transfer(base string, priv ed25519.PrivateKey, from []byte, toDscID int64, amount, nonce int64, meta map[string]any) {
	p := ledger.TransferPayload{
		From: from, ToDiscourseID: toDscID, Amount: amount, Nonce: nonce, Meta: meta,
	}
	payload, err := ledger.CanonicalJSON(p)
	if err != nil {
		log.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	body, _ := json.Marshal(map[string]string{
		"tx_type":     string(ledger.TxTransfer),
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
		"sig_b64":     base64.StdEncoding.EncodeToString(sig),
		"signer_hex":  hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	})
	resp, err := http.Post(base+"/api/v1/tx", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("transfer %d→%d: %d %s", amount, toDscID, resp.StatusCode, string(b))
	}
}

func expectBalance(base string, dscID, want int64, who string) {
	a := mustGetAccount(base, dscID)
	if a.Balance != want {
		log.Fatalf("%s (discourse_id=%d) balance=%d want=%d", who, dscID, a.Balance, want)
	}
	fmt.Printf("  %-10s balance = %d ✓\n", who, a.Balance)
}

func getOK(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return nil
}
