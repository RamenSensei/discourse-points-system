package ledger

import (
	"bytes"
	"context"
	"errors"
	"sync"
)

type MemStore struct {
	mu            sync.Mutex
	byDiscourseID map[int64]*Account
	byPubKey      map[string]int64 // pubkey-hex -> discourse_id
	txs           []*Tx
}

func NewMemStore() *MemStore {
	return &MemStore{
		byDiscourseID: make(map[int64]*Account),
		byPubKey:      make(map[string]int64),
		txs:           make([]*Tx, 0),
	}
}

func (m *MemStore) Begin(ctx context.Context) (StoreTx, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	bd := make(map[int64]*Account, len(m.byDiscourseID))
	bp := make(map[string]int64, len(m.byPubKey))
	for k, a := range m.byDiscourseID {
		c := *a
		c.Pubkey = bytes.Clone(a.Pubkey)
		bd[k] = &c
	}
	for k, v := range m.byPubKey {
		bp[k] = v
	}
	return &memTx{
		parent:        m,
		byDiscourseID: bd,
		byPubKey:      bp,
		txs:           append([]*Tx(nil), m.txs...),
	}, nil
}

type memTx struct {
	parent        *MemStore
	byDiscourseID map[int64]*Account
	byPubKey      map[string]int64
	txs           []*Tx
	done          bool
}

func (t *memTx) Commit(ctx context.Context) error {
	if t.done {
		return errors.New("tx already done")
	}
	t.done = true
	t.parent.mu.Lock()
	defer t.parent.mu.Unlock()
	t.parent.byDiscourseID = t.byDiscourseID
	t.parent.byPubKey = t.byPubKey
	t.parent.txs = t.txs
	return nil
}

func (t *memTx) Rollback(ctx context.Context) error {
	t.done = true
	return nil
}

func (t *memTx) LockLedger(ctx context.Context) error {
	return nil
}

func (t *memTx) GetAccountByPubKey(ctx context.Context, pubkey []byte) (*Account, error) {
	if len(pubkey) == 0 {
		return nil, nil
	}
	did, ok := t.byPubKey[string(pubkey)]
	if !ok {
		return nil, nil
	}
	a := t.byDiscourseID[did]
	if a == nil {
		return nil, nil
	}
	c := *a
	c.Pubkey = bytes.Clone(a.Pubkey)
	return &c, nil
}

func (t *memTx) GetAccountByDiscourseID(ctx context.Context, did int64) (*Account, error) {
	a, ok := t.byDiscourseID[did]
	if !ok {
		return nil, nil
	}
	c := *a
	c.Pubkey = bytes.Clone(a.Pubkey)
	return &c, nil
}

func (t *memTx) GetAccountsByDiscourseIDs(ctx context.Context, dids []int64) (map[int64]*Account, error) {
	out := make(map[int64]*Account, len(dids))
	for _, did := range dids {
		a, ok := t.byDiscourseID[did]
		if !ok {
			continue
		}
		c := *a
		c.Pubkey = bytes.Clone(a.Pubkey)
		out[did] = &c
	}
	return out, nil
}

func (t *memTx) UpsertAccount(ctx context.Context, a *Account) error {
	c := *a
	c.Pubkey = bytes.Clone(a.Pubkey)
	// Remove old pubkey index if any
	if existing, ok := t.byDiscourseID[a.DiscourseID]; ok && existing.Pubkey != nil {
		delete(t.byPubKey, string(existing.Pubkey))
	}
	t.byDiscourseID[a.DiscourseID] = &c
	if len(c.Pubkey) > 0 {
		t.byPubKey[string(c.Pubkey)] = c.DiscourseID
	}
	return nil
}

func (t *memTx) UpdatePubKey(ctx context.Context, oldPub, newPub []byte) error {
	did, ok := t.byPubKey[string(oldPub)]
	if !ok {
		return ErrUnknownAccount
	}
	a := t.byDiscourseID[did]
	delete(t.byPubKey, string(oldPub))
	a.Pubkey = bytes.Clone(newPub)
	t.byPubKey[string(newPub)] = did
	return nil
}

func (t *memTx) UpdateUsernameAndPubKey(ctx context.Context, did int64, pubkey []byte, username string) error {
	a, ok := t.byDiscourseID[did]
	if !ok {
		return ErrUnknownAccount
	}
	if a.Pubkey != nil {
		delete(t.byPubKey, string(a.Pubkey))
	}
	a.Pubkey = bytes.Clone(pubkey)
	a.Username = username
	t.byPubKey[string(a.Pubkey)] = did
	return nil
}

func (t *memTx) LastTx(ctx context.Context) (*Tx, error) {
	if len(t.txs) == 0 {
		return nil, nil
	}
	return t.txs[len(t.txs)-1], nil
}

func (t *memTx) InsertTx(ctx context.Context, tx *Tx) error {
	for _, existing := range t.txs {
		if bytes.Equal(existing.TxHash, tx.TxHash) {
			return errors.New("duplicate tx_hash")
		}
	}
	t.txs = append(t.txs, tx)
	return nil
}

func (t *memTx) GenesisExists(ctx context.Context) (bool, error) {
	for _, tx := range t.txs {
		if tx.Type == TxGenesis {
			return true, nil
		}
	}
	return false, nil
}

func (t *memTx) TotalBalance(ctx context.Context) (int64, error) {
	var total int64
	for _, a := range t.byDiscourseID {
		total += a.Balance
	}
	return total, nil
}
