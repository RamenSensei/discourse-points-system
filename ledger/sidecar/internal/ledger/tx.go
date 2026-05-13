package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	SupplyCap     int64 = 50_000_000
	TreasuryDscID int64 = 0
	PubKeyLen           = ed25519.PublicKeySize
	SigLen              = ed25519.SignatureSize
	HashLen             = sha256.Size
)

type TxType string

const (
	TxGenesis        TxType = "genesis"
	TxTransfer       TxType = "transfer"
	TxRotateKey      TxType = "rotate_key"
	TxReclaimInvalid TxType = "reclaim_invalid"
	TxRotateAdmin    TxType = "rotate_admin"
	TxRewardConfig   TxType = "reward_config"
)

type Tx struct {
	LeafIndex int64           `json:"leaf_index"`
	Type      TxType          `json:"tx_type"`
	Payload   json.RawMessage `json:"payload"`
	Sig       []byte          `json:"sig"`
	Signer    []byte          `json:"signer"`
	PrevHash  []byte          `json:"prev_hash"`
	TxHash    []byte          `json:"tx_hash"`
}

type GenesisPayload struct {
	To           []byte `json:"to"`
	TreasuryUser string `json:"treasury_user"`
	Amount       int64  `json:"amount"`
	Memo         string `json:"memo"`
}

// TransferPayload sends `amount` pts from the signer (whose pubkey is `From`)
// to whoever holds the Discourse account `ToDiscourseID`. The recipient may not
// have a pubkey yet — in that case the apply layer creates a pending account.
type TransferPayload struct {
	From          []byte         `json:"from"`            // 32B pubkey of signer
	ToDiscourseID int64          `json:"to_discourse_id"` // recipient identity
	Amount        int64          `json:"amount"`
	Nonce         int64          `json:"nonce"`
	Meta          map[string]any `json:"meta,omitempty"`
}

type RotateKeyPayload struct {
	OldPubKey []byte `json:"old_pubkey"`
	NewPubKey []byte `json:"new_pubkey"`
	Nonce     int64  `json:"nonce"`
}

type ReclaimInvalidPayload struct {
	Admin           []byte `json:"admin"`
	FromDiscourseID int64  `json:"from_discourse_id"`
	Amount          int64  `json:"amount"`
	Nonce           int64  `json:"nonce"`
	Memo            string `json:"memo,omitempty"`
}

type RewardConfigPayload struct {
	EventType string `json:"event_type"`
	Amount    int64  `json:"amount"`
	Enabled   bool   `json:"enabled"`
	Nonce     int64  `json:"nonce"`
}

var (
	ErrBadSig            = errors.New("invalid signature")
	ErrBadPubKey         = errors.New("bad pubkey length")
	ErrBadHash           = errors.New("bad hash length")
	ErrUnknownAccount    = errors.New("unknown account")
	ErrInsufficientFunds = errors.New("insufficient balance")
	ErrBadNonce          = errors.New("bad nonce")
	ErrBadAmount         = errors.New("amount must be positive")
	ErrBadDiscourseID    = errors.New("discourse_id must be a real user id (> 0)")
	ErrGenesisExists     = errors.New("genesis already applied")
	ErrSupplyViolated    = errors.New("supply invariant violated")
	ErrUnknownTxType     = errors.New("unknown tx_type")
	ErrSelfTransfer      = errors.New("cannot transfer to self")
	ErrSignerMismatch    = errors.New("signer does not match payload from")
)

func Build(t TxType, payload []byte, signer, sig, prevHash []byte) (*Tx, error) {
	if len(signer) != PubKeyLen {
		return nil, ErrBadPubKey
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("bad sig length: %d", len(sig))
	}
	if len(prevHash) != HashLen {
		return nil, ErrBadHash
	}
	h := sha256.New()
	h.Write(payload)
	h.Write(sig)
	h.Write(prevHash)
	return &Tx{
		Type:     t,
		Payload:  payload,
		Sig:      sig,
		Signer:   signer,
		PrevHash: prevHash,
		TxHash:   h.Sum(nil),
	}, nil
}

func VerifySig(signer, payload, sig []byte) bool {
	if len(signer) != PubKeyLen || len(sig) != SigLen {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(signer), payload, sig)
}

func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

func SignPayload(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

func ZeroHash() []byte {
	return make([]byte, HashLen)
}
