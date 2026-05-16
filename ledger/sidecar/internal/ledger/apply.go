package ledger

import (
	"context"
	"encoding/json"
	"fmt"
)

// Store is the persistence interface required by Apply.
type Store interface {
	Begin(ctx context.Context) (StoreTx, error)
}

type StoreTx interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	LockLedger(ctx context.Context) error

	// Accounts — pubkey is optional; for unactivated accounts pubkey==nil.
	GetAccountByPubKey(ctx context.Context, pubkey []byte) (*Account, error)
	GetAccountByDiscourseID(ctx context.Context, discourseID int64) (*Account, error)
	GetAccountsByDiscourseIDs(ctx context.Context, discourseIDs []int64) (map[int64]*Account, error)
	UpsertAccount(ctx context.Context, a *Account) error
	UpdatePubKey(ctx context.Context, oldPub, newPub []byte) error
	UpdateUsernameAndPubKey(ctx context.Context, discourseID int64, pubkey []byte, username string) error

	// Transactions
	LastTx(ctx context.Context) (*Tx, error)
	InsertTx(ctx context.Context, tx *Tx) error
	GenesisExists(ctx context.Context) (bool, error)
	TotalBalance(ctx context.Context) (int64, error)
}

type Account struct {
	DiscourseID int64
	Pubkey      []byte // may be nil for pre-activated accounts
	Username    string
	Nonce       int64
	Balance     int64
}

// Apply validates, sig-checks, and persists a Tx. Ledger writes are globally
// ordered by StoreTx.LockLedger so prev_hash and leaf_index remain a single
// append-only sequence under concurrent submitters.
func Apply(ctx context.Context, s Store, tx *Tx) error {
	if !VerifySig(tx.Signer, tx.Payload, tx.Sig) {
		return ErrBadSig
	}

	stx, err := s.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = stx.Rollback(ctx) }()

	if err := stx.LockLedger(ctx); err != nil {
		return fmt.Errorf("ledger lock: %w", err)
	}

	last, err := stx.LastTx(ctx)
	if err != nil {
		return fmt.Errorf("last tx lookup: %w", err)
	}

	var prevHash []byte
	if last == nil {
		if tx.Type != TxGenesis {
			return fmt.Errorf("first tx must be genesis, got %s", tx.Type)
		}
		tx.LeafIndex = 0
		prevHash = ZeroHash()
	} else {
		if tx.Type == TxGenesis {
			return ErrGenesisExists
		}
		tx.LeafIndex = last.LeafIndex + 1
		prevHash = last.TxHash
	}
	tx.PrevHash = prevHash

	rebuilt, err := Build(tx.Type, tx.Payload, tx.Signer, tx.Sig, prevHash)
	if err != nil {
		return err
	}
	tx.TxHash = rebuilt.TxHash

	switch tx.Type {
	case TxGenesis:
		if err := applyGenesis(ctx, stx, tx); err != nil {
			return err
		}
	case TxTransfer:
		if err := applyTransfer(ctx, stx, tx); err != nil {
			return err
		}
	case TxRotateKey:
		if err := applyRotateKey(ctx, stx, tx); err != nil {
			return err
		}
	case TxReclaimInvalid:
		if err := applyReclaimInvalid(ctx, stx, tx); err != nil {
			return err
		}
	default:
		return ErrUnknownTxType
	}

	if err := stx.InsertTx(ctx, tx); err != nil {
		return fmt.Errorf("insert tx: %w", err)
	}

	if requiresFullSupplyCheck(tx.Type) {
		total, err := stx.TotalBalance(ctx)
		if err != nil {
			return fmt.Errorf("total balance: %w", err)
		}
		if total != SupplyCap {
			return fmt.Errorf("%w: sum(balance)=%d cap=%d", ErrSupplyViolated, total, SupplyCap)
		}
	}

	return stx.Commit(ctx)
}

func requiresFullSupplyCheck(t TxType) bool {
	return t == TxGenesis || t == TxReclaimInvalid
}

func applyGenesis(ctx context.Context, stx StoreTx, tx *Tx) error {
	exists, err := stx.GenesisExists(ctx)
	if err != nil {
		return err
	}
	if exists {
		return ErrGenesisExists
	}
	var p GenesisPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("genesis payload: %w", err)
	}
	if len(p.To) != PubKeyLen {
		return ErrBadPubKey
	}
	if p.Amount != SupplyCap {
		return fmt.Errorf("genesis amount=%d, must equal cap=%d", p.Amount, SupplyCap)
	}
	if !equalBytes(tx.Signer, p.To) {
		return fmt.Errorf("genesis signer must equal treasury pubkey")
	}
	username := p.TreasuryUser
	if username == "" {
		username = "TREASURY"
	}
	return stx.UpsertAccount(ctx, &Account{
		DiscourseID: TreasuryDscID,
		Pubkey:      p.To,
		Username:    username,
		Nonce:       0,
		Balance:     SupplyCap,
	})
}

func applyTransfer(ctx context.Context, stx StoreTx, tx *Tx) error {
	var p TransferPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("transfer payload: %w", err)
	}
	if p.Amount <= 0 {
		return ErrBadAmount
	}
	if p.ToDiscourseID <= TreasuryDscID {
		return ErrBadDiscourseID
	}
	if !equalBytes(p.From, tx.Signer) {
		return ErrSignerMismatch
	}
	if len(p.From) != PubKeyLen {
		return ErrBadPubKey
	}

	from, err := stx.GetAccountByPubKey(ctx, p.From)
	if err != nil {
		return fmt.Errorf("from account: %w", err)
	}
	if from == nil {
		return ErrUnknownAccount
	}
	if from.DiscourseID == p.ToDiscourseID {
		return ErrSelfTransfer
	}
	if p.Nonce != from.Nonce+1 {
		return fmt.Errorf("%w: expected %d got %d", ErrBadNonce, from.Nonce+1, p.Nonce)
	}
	if from.Balance < p.Amount {
		return ErrInsufficientFunds
	}

	to, err := stx.GetAccountByDiscourseID(ctx, p.ToDiscourseID)
	if err != nil {
		return fmt.Errorf("to account: %w", err)
	}
	if to == nil {
		// Auto-create a pending (unactivated) account; pubkey stays nil until /me/register.
		username := "(pending)"
		if u, ok := p.Meta["tip_target_username"].(string); ok && u != "" {
			username = u
		}
		to = &Account{
			DiscourseID: p.ToDiscourseID,
			Pubkey:      nil,
			Username:    username,
		}
	}

	from.Balance -= p.Amount
	from.Nonce = p.Nonce
	to.Balance += p.Amount

	if err := stx.UpsertAccount(ctx, from); err != nil {
		return fmt.Errorf("update from: %w", err)
	}
	if err := stx.UpsertAccount(ctx, to); err != nil {
		return fmt.Errorf("update to: %w", err)
	}
	return nil
}

func applyRotateKey(ctx context.Context, stx StoreTx, tx *Tx) error {
	var p RotateKeyPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("rotate_key payload: %w", err)
	}
	if len(p.OldPubKey) != PubKeyLen || len(p.NewPubKey) != PubKeyLen {
		return ErrBadPubKey
	}
	if !equalBytes(tx.Signer, p.OldPubKey) {
		return ErrSignerMismatch
	}
	old, err := stx.GetAccountByPubKey(ctx, p.OldPubKey)
	if err != nil {
		return fmt.Errorf("old account: %w", err)
	}
	if old == nil {
		return ErrUnknownAccount
	}
	if p.Nonce != old.Nonce+1 {
		return fmt.Errorf("%w: expected %d got %d", ErrBadNonce, old.Nonce+1, p.Nonce)
	}
	old.Nonce = p.Nonce
	if err := stx.UpsertAccount(ctx, old); err != nil {
		return fmt.Errorf("nonce bump: %w", err)
	}
	return stx.UpdatePubKey(ctx, p.OldPubKey, p.NewPubKey)
}

func applyReclaimInvalid(ctx context.Context, stx StoreTx, tx *Tx) error {
	var p ReclaimInvalidPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("reclaim_invalid payload: %w", err)
	}
	if p.Amount <= 0 {
		return ErrBadAmount
	}
	if p.FromDiscourseID >= TreasuryDscID {
		return ErrBadDiscourseID
	}
	if len(p.Admin) != PubKeyLen {
		return ErrBadPubKey
	}
	if !equalBytes(tx.Signer, p.Admin) {
		return ErrSignerMismatch
	}
	admin, err := stx.GetAccountByPubKey(ctx, p.Admin)
	if err != nil {
		return fmt.Errorf("admin account: %w", err)
	}
	if admin == nil || admin.DiscourseID != TreasuryDscID {
		return ErrUnknownAccount
	}
	if p.Nonce != admin.Nonce+1 {
		return fmt.Errorf("%w: expected %d got %d", ErrBadNonce, admin.Nonce+1, p.Nonce)
	}
	from, err := stx.GetAccountByDiscourseID(ctx, p.FromDiscourseID)
	if err != nil {
		return fmt.Errorf("invalid account: %w", err)
	}
	if from == nil {
		return ErrUnknownAccount
	}
	if len(from.Pubkey) > 0 {
		return ErrBadDiscourseID
	}
	if from.Balance < p.Amount {
		return ErrInsufficientFunds
	}

	from.Balance -= p.Amount
	admin.Balance += p.Amount
	admin.Nonce = p.Nonce

	if err := stx.UpsertAccount(ctx, from); err != nil {
		return fmt.Errorf("update invalid account: %w", err)
	}
	if err := stx.UpsertAccount(ctx, admin); err != nil {
		return fmt.Errorf("update treasury: %w", err)
	}
	return nil
}

func equalBytes(a, b []byte) bool {
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
