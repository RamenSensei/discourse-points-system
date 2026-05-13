package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func signTx(t *testing.T, priv ed25519.PrivateKey, typ TxType, payload any) *Tx {
	t.Helper()
	pay, err := CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := ed25519.Sign(priv, pay)
	return &Tx{
		Type:    typ,
		Payload: pay,
		Sig:     sig,
		Signer:  priv.Public().(ed25519.PublicKey),
	}
}

// preActivate inserts an account with a known pubkey so a user can sign.
func preActivate(t *testing.T, ms *MemStore, pub ed25519.PublicKey, dscID int64, name string) {
	t.Helper()
	stx, _ := ms.Begin(context.Background())
	_ = stx.UpsertAccount(context.Background(), &Account{
		DiscourseID: dscID,
		Pubkey:      pub,
		Username:    name,
	})
	_ = stx.Commit(context.Background())
}

func TestGenesisHappyPath(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	g := signTx(t, adminPriv, TxGenesis, GenesisPayload{
		To: adminPub, TreasuryUser: "TREASURY", Amount: SupplyCap, Memo: "genesis",
	})
	if err := Apply(context.Background(), ms, g); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	total, _ := ms.totalForTest()
	if total != SupplyCap {
		t.Fatalf("supply = %d", total)
	}
}

func TestTransferAutoCreatesReceiver(t *testing.T) {
	// Admin transfers to a discourse_id with no prior account; we expect
	// auto-creation with NULL pubkey and the right balance.
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{
		To: adminPub, Amount: SupplyCap,
	}))

	tx := signTx(t, adminPriv, TxTransfer, TransferPayload{
		From: adminPub, ToDiscourseID: 42, Amount: 100, Nonce: 1,
	})
	if err := Apply(context.Background(), ms, tx); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	stx, _ := ms.Begin(context.Background())
	defer stx.Rollback(context.Background())
	a, _ := stx.GetAccountByDiscourseID(context.Background(), 42)
	if a == nil || a.Balance != 100 || a.Pubkey != nil {
		t.Fatalf("auto-created account wrong: %+v", a)
	}
}

func TestUserSpendAfterActivation(t *testing.T) {
	// After admin pre-funds 42 and user 42 activates by registering pubkey,
	// user 42 must be able to sign and spend.
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	alicePub, alicePriv := mustKeypair(t)

	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{
		To: adminPub, Amount: SupplyCap,
	}))

	// admin transfers 100 to alice (auto-creates her account with NULL pubkey)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxTransfer, TransferPayload{
		From: adminPub, ToDiscourseID: 42, Amount: 100, Nonce: 1,
	}))

	// alice activates: registers her pubkey for discourse_id 42
	stx, _ := ms.Begin(context.Background())
	_ = stx.UpdateUsernameAndPubKey(context.Background(), 42, alicePub, "alice")
	_ = stx.Commit(context.Background())

	// alice transfers 10 to bob (discourse_id 43, auto-create)
	tx := signTx(t, alicePriv, TxTransfer, TransferPayload{
		From: alicePub, ToDiscourseID: 43, Amount: 10, Nonce: 1,
	})
	if err := Apply(context.Background(), ms, tx); err != nil {
		t.Fatalf("alice transfer: %v", err)
	}

	stx, _ = ms.Begin(context.Background())
	defer stx.Rollback(context.Background())
	alice, _ := stx.GetAccountByDiscourseID(context.Background(), 42)
	bob, _ := stx.GetAccountByDiscourseID(context.Background(), 43)
	if alice.Balance != 90 || bob.Balance != 10 {
		t.Fatalf("balances wrong: alice=%d bob=%d", alice.Balance, bob.Balance)
	}
}

func TestTransferRejectsBadNonce(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))

	bad := signTx(t, adminPriv, TxTransfer, TransferPayload{
		From: adminPub, ToDiscourseID: 42, Amount: 10, Nonce: 99,
	})
	if !errors.Is(Apply(context.Background(), ms, bad), ErrBadNonce) {
		t.Fatal("want ErrBadNonce")
	}
}

func TestTransferRejectsInsufficientFunds(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	alicePub, alicePriv := mustKeypair(t)

	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))
	preActivate(t, ms, alicePub, 42, "alice")

	bad := signTx(t, alicePriv, TxTransfer, TransferPayload{
		From: alicePub, ToDiscourseID: 43, Amount: 1, Nonce: 1,
	})
	if !errors.Is(Apply(context.Background(), ms, bad), ErrInsufficientFunds) {
		t.Fatal("want ErrInsufficientFunds")
	}
}

func TestSignerMismatchRejected(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_, mallorPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))

	bad := signTx(t, mallorPriv, TxTransfer, TransferPayload{
		From: adminPub, ToDiscourseID: 42, Amount: 10, Nonce: 1,
	})
	if !errors.Is(Apply(context.Background(), ms, bad), ErrSignerMismatch) {
		t.Fatal("want ErrSignerMismatch")
	}
}

func TestBadSignatureRejected(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))

	tx := signTx(t, adminPriv, TxTransfer, TransferPayload{
		From: adminPub, ToDiscourseID: 42, Amount: 1, Nonce: 1,
	})
	tx.Sig[0] ^= 0xff
	if !errors.Is(Apply(context.Background(), ms, tx), ErrBadSig) {
		t.Fatal("want ErrBadSig")
	}
}

func TestTransferRejectsBadReceiverID(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))

	for _, id := range []int64{0, -1} {
		tx := signTx(t, adminPriv, TxTransfer, TransferPayload{
			From: adminPub, ToDiscourseID: id, Amount: 1, Nonce: 1,
		})
		if !errors.Is(Apply(context.Background(), ms, tx), ErrBadDiscourseID) {
			t.Fatalf("to_discourse_id=%d: want ErrBadDiscourseID", id)
		}
	}
}

func TestRotateKey(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	oldPub, oldPriv := mustKeypair(t)
	newPub, newPriv := mustKeypair(t)

	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))
	preActivate(t, ms, oldPub, 42, "alice")
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxTransfer, TransferPayload{
		From: adminPub, ToDiscourseID: 42, Amount: 50, Nonce: 1,
	}))

	rot := signTx(t, oldPriv, TxRotateKey, RotateKeyPayload{
		OldPubKey: oldPub, NewPubKey: newPub, Nonce: 1,
	})
	if err := Apply(context.Background(), ms, rot); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// new key can spend
	_ = Apply(context.Background(), ms, signTx(t, newPriv, TxTransfer, TransferPayload{
		From: newPub, ToDiscourseID: 43, Amount: 10, Nonce: 2,
	}))
}

func TestReclaimInvalidAccount(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))

	stx, _ := ms.Begin(context.Background())
	treasury, _ := stx.GetAccountByDiscourseID(context.Background(), TreasuryDscID)
	treasury.Balance -= 50
	_ = stx.UpsertAccount(context.Background(), treasury)
	_ = stx.UpsertAccount(context.Background(), &Account{DiscourseID: -1, Username: "system", Balance: 50})
	_ = stx.Commit(context.Background())

	tx := signTx(t, adminPriv, TxReclaimInvalid, ReclaimInvalidPayload{
		Admin: adminPub, FromDiscourseID: -1, Amount: 50, Nonce: 1, Memo: "undo system reward",
	})
	if err := Apply(context.Background(), ms, tx); err != nil {
		t.Fatalf("reclaim_invalid: %v", err)
	}

	stx, _ = ms.Begin(context.Background())
	defer stx.Rollback(context.Background())
	treasury, _ = stx.GetAccountByDiscourseID(context.Background(), TreasuryDscID)
	system, _ := stx.GetAccountByDiscourseID(context.Background(), -1)
	if treasury.Balance != SupplyCap || treasury.Nonce != 1 {
		t.Fatalf("treasury after reclaim = %+v", treasury)
	}
	if system == nil || system.Balance != 0 {
		t.Fatalf("system after reclaim = %+v", system)
	}
}

func TestReclaimInvalidRejectsPositiveAccount(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))
	tx := signTx(t, adminPriv, TxReclaimInvalid, ReclaimInvalidPayload{
		Admin: adminPub, FromDiscourseID: 42, Amount: 1, Nonce: 1,
	})
	if !errors.Is(Apply(context.Background(), ms, tx), ErrBadDiscourseID) {
		t.Fatal("want ErrBadDiscourseID")
	}
}

func TestSupplyConservation(t *testing.T) {
	ms := NewMemStore()
	adminPub, adminPriv := mustKeypair(t)
	_ = Apply(context.Background(), ms, signTx(t, adminPriv, TxGenesis, GenesisPayload{To: adminPub, Amount: SupplyCap}))

	type usr struct {
		pub   ed25519.PublicKey
		priv  ed25519.PrivateKey
		dscID int64
		nonce int64
	}
	users := make([]*usr, 3)
	for i := range users {
		pub, priv := mustKeypair(t)
		u := &usr{pub: pub, priv: priv, dscID: int64(100 + i)}
		preActivate(t, ms, pub, u.dscID, "u")
		users[i] = u
	}

	// admin seeds each user with 1000
	for i, u := range users {
		err := Apply(context.Background(), ms, signTx(t, adminPriv, TxTransfer, TransferPayload{
			From: adminPub, ToDiscourseID: u.dscID, Amount: 1000, Nonce: int64(i + 1),
		}))
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for n := 0; n < 100; n++ {
		from := users[int(seed[n%len(seed)])%3]
		toIdx := (int(seed[n%len(seed)]) + 1) % 3
		if from == users[toIdx] {
			continue
		}
		from.nonce++
		amt := int64(1 + n%10)
		err := Apply(context.Background(), ms, signTx(t, from.priv, TxTransfer, TransferPayload{
			From: from.pub, ToDiscourseID: users[toIdx].dscID, Amount: amt, Nonce: from.nonce,
		}))
		if err != nil {
			from.nonce--
		}
	}

	total, _ := ms.totalForTest()
	if total != SupplyCap {
		t.Fatalf("supply violated: %d", total)
	}
}

func (m *MemStore) totalForTest() (int64, error) {
	stx, _ := m.Begin(context.Background())
	defer stx.Rollback(context.Background())
	return stx.TotalBalance(context.Background())
}
