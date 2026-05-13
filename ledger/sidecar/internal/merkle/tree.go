// Package merkle implements the RFC 6962 Merkle Tree (used by Certificate
// Transparency, Trillian, and Go's sumdb). Operations needed for our ledger:
//
//   - LeafHash(data) = SHA-256(0x00 || data)
//   - NodeHash(left, right) = SHA-256(0x01 || left || right)
//   - Root(leaves) = root of a tree built bottom-up; odd nodes promote to next level
//   - InclusionProof(leaves, index): audit path proving leaf[index] ∈ root
//   - VerifyInclusion(rootHash, leafHash, index, treeSize, path)
//   - ConsistencyProof(leaves, m, n): proves treeAt(m) ⊆ treeAt(n) for m ≤ n
//   - VerifyConsistency(oldRoot, newRoot, m, n, proof)
//
// The implementation is naive (recomputes from raw leaves each time) and is
// fine up to ~1M leaves. Optimization (cached subtree hashes) is a later
// iteration if needed.
//
// All hashes are 32 bytes (SHA-256). Indices are 0-based, sizes are inclusive
// counts.

package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

const HashLen = sha256.Size

// LeafHash returns the RFC 6962 leaf hash for `data`.
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash returns the RFC 6962 internal-node hash for two children.
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Root computes the RFC 6962 root hash of the tree formed by `leaves` (which
// are raw leaf bytes — they get hashed internally via LeafHash). For an empty
// list, returns the SHA-256 of the empty string per RFC 6962.
func Root(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		h := sha256.New()
		return h.Sum(nil)
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return rootOfHashes(hashes)
}

// RootFromLeafHashes is like Root but takes pre-computed leaf hashes.
func RootFromLeafHashes(leafHashes [][]byte) []byte {
	if len(leafHashes) == 0 {
		h := sha256.New()
		return h.Sum(nil)
	}
	return rootOfHashes(leafHashes)
}

func rootOfHashes(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		return hashes[0]
	}
	k := largestPowerOfTwoLessThan(len(hashes))
	left := rootOfHashes(hashes[:k])
	right := rootOfHashes(hashes[k:])
	return NodeHash(left, right)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n.
// Per RFC 6962, the split point for a subtree of n>1 leaves is the largest k=2^a < n.
func largestPowerOfTwoLessThan(n int) int {
	if n < 2 {
		return 0
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// InclusionProof returns the audit path proving that leaves[index] is part of
// the tree formed by `leaves`. The path is ordered from leaf level up to root.
func InclusionProof(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(leaves))
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return inclusionProof(hashes, index), nil
}

// InclusionProofFromHashes is like InclusionProof but takes leaf hashes directly.
func InclusionProofFromHashes(leafHashes [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leafHashes) {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(leafHashes))
	}
	return inclusionProof(leafHashes, index), nil
}

func inclusionProof(hashes [][]byte, index int) [][]byte {
	if len(hashes) == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(hashes))
	if index < k {
		// continue in left subtree, then add right subtree root
		sub := inclusionProof(hashes[:k], index)
		right := rootOfHashes(hashes[k:])
		return append(sub, right)
	}
	// continue in right subtree, then add left subtree root
	sub := inclusionProof(hashes[k:], index-k)
	left := rootOfHashes(hashes[:k])
	return append(sub, left)
}

// VerifyInclusion checks an audit path produced by InclusionProof.
// Returns nil iff the proof shows leafHash is at the given index in a tree
// of `treeSize` total leaves with the given root.
//
// The proof is ordered deepest-first (matching InclusionProof's output);
// the verifier walks top-down, consuming proof elements from the END at each
// level — this mirrors the recursive split the generator made.
func VerifyInclusion(rootHash, leafHash []byte, index, treeSize int, proof [][]byte) error {
	if index < 0 || index >= treeSize {
		return fmt.Errorf("index %d out of range [0, %d)", index, treeSize)
	}
	h, remaining, err := verifyDescend(leafHash, index, treeSize, proof)
	if err != nil {
		return err
	}
	if remaining != 0 {
		return fmt.Errorf("proof too long: %d unused elements", remaining)
	}
	if !equal(h, rootHash) {
		return errors.New("root mismatch")
	}
	return nil
}

// verifyDescend recursively rebuilds the root-side of the subtree containing
// `leafHash` at `index`. Returns the reconstructed hash and the count of
// unused proof entries (should be 0 at the outermost call).
func verifyDescend(leafHash []byte, index, size int, proof [][]byte) ([]byte, int, error) {
	if size == 1 {
		return leafHash, len(proof), nil
	}
	if len(proof) == 0 {
		return nil, 0, fmt.Errorf("proof too short at size=%d", size)
	}
	k := largestPowerOfTwoLessThan(size)
	sibling := proof[len(proof)-1]
	inner := proof[:len(proof)-1]
	if index < k {
		sub, rem, err := verifyDescend(leafHash, index, k, inner)
		if err != nil {
			return nil, 0, err
		}
		return NodeHash(sub, sibling), rem, nil
	}
	sub, rem, err := verifyDescend(leafHash, index-k, size-k, inner)
	if err != nil {
		return nil, 0, err
	}
	return NodeHash(sibling, sub), rem, nil
}

// ConsistencyProof returns the RFC 6962 proof that the tree of `leaves[:m]`
// (with old root) is a prefix of the tree of `leaves[:n]` (with new root).
// Requires 0 < m ≤ n ≤ len(leaves).
func ConsistencyProof(leaves [][]byte, m, n int) ([][]byte, error) {
	if m <= 0 || m > n || n > len(leaves) {
		return nil, fmt.Errorf("bad m=%d n=%d (len=%d)", m, n, len(leaves))
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return subProof(hashes, m, n, true), nil
}

// ConsistencyProofFromHashes is like ConsistencyProof but takes leaf hashes directly.
func ConsistencyProofFromHashes(leafHashes [][]byte, m, n int) ([][]byte, error) {
	if m <= 0 || m > n || n > len(leafHashes) {
		return nil, fmt.Errorf("bad m=%d n=%d (len=%d)", m, n, len(leafHashes))
	}
	return subProof(leafHashes, m, n, true), nil
}

// subProof implements RFC 6962 SUBPROOF.
func subProof(hashes [][]byte, m, n int, b bool) [][]byte {
	if m == n {
		if b {
			return nil
		}
		return [][]byte{rootOfHashes(hashes[:n])}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		// First subtree fully contained in left; recurse left, then append right subtree root.
		sub := subProof(hashes[:k], m, k, b)
		right := rootOfHashes(hashes[k:n])
		return append(sub, right)
	}
	// m > k: recurse on right subtree (shifted), prepending left subtree root.
	sub := subProof(hashes[k:], m-k, n-k, false)
	left := rootOfHashes(hashes[:k])
	return append(sub, left)
}

// VerifyConsistency checks a consistency proof: that the tree of size m with
// root oldRoot is a prefix of the tree of size n with root newRoot.
func VerifyConsistency(oldRoot, newRoot []byte, m, n int, proof [][]byte) error {
	if m == n {
		if len(proof) != 0 {
			return errors.New("consistency proof must be empty when m == n")
		}
		if !equal(oldRoot, newRoot) {
			return errors.New("m==n but roots differ")
		}
		return nil
	}
	if m == 0 || m > n {
		return fmt.Errorf("bad m=%d n=%d", m, n)
	}
	// Special case: m is a power of two AND is the full size of the (left) subtree.
	// Then the first element of the proof is implicit (it's oldRoot itself).
	pi := 0
	var path [][]byte
	if isPowerOfTwo(m) {
		path = append([][]byte{oldRoot}, proof...)
	} else {
		path = proof
	}
	if len(path) < 1 {
		return errors.New("consistency proof too short")
	}
	hash1 := path[pi]
	hash2 := path[pi]
	pi++
	sz, sn := m, n
	mShift := m - 1 // bit-shift trick per RFC 6962
	nShift := n - 1
	for mShift&1 == 1 {
		mShift >>= 1
		nShift >>= 1
	}
	_, _ = sz, sn
	// Use the canonical iterative algorithm from RFC 6962 §2.1.2.
	r, oldR, newR, err := walkConsistency(hash1, hash2, path[pi:], m, n)
	if err != nil {
		return err
	}
	if !equal(oldR, oldRoot) {
		return fmt.Errorf("old root mismatch (got %x want %x)", oldR, oldRoot)
	}
	if !equal(newR, newRoot) {
		return fmt.Errorf("new root mismatch (got %x want %x)", newR, newRoot)
	}
	_ = r
	return nil
}

// walkConsistency runs the RFC 6962 §2.1.2 verification using `hash1` (current
// accumulator for old subtree) and `hash2` (current accumulator for new subtree).
// It iterates through `proof` consuming entries and returns the final old/new roots.
func walkConsistency(hash1, hash2 []byte, proof [][]byte, m, n int) (_ struct{}, oldRoot []byte, newRoot []byte, err error) {
	// Implementation derived from Trillian's MerkleVerifier.
	// Shift m and n until the rightmost bit of m is 1 (RFC notation: skip "fully covered" levels).
	mm := uint64(m)
	nn := uint64(n)
	mm--
	nn--
	for mm&1 == 1 {
		mm >>= 1
		nn >>= 1
	}
	pi := 0
	for nn > 0 {
		if pi >= len(proof) {
			return struct{}{}, nil, nil, fmt.Errorf("consistency proof too short")
		}
		sibling := proof[pi]
		pi++
		if mm&1 == 1 || mm == nn {
			hash1 = NodeHash(sibling, hash1)
			hash2 = NodeHash(sibling, hash2)
			for mm&1 == 0 && mm > 0 {
				mm >>= 1
				nn >>= 1
			}
		} else {
			hash2 = NodeHash(hash2, sibling)
		}
		mm >>= 1
		nn >>= 1
	}
	if pi != len(proof) {
		return struct{}{}, nil, nil, fmt.Errorf("consistency proof too long: consumed %d of %d", pi, len(proof))
	}
	return struct{}{}, hash1, hash2, nil
}

func isPowerOfTwo(n int) bool { return n > 0 && (n&(n-1)) == 0 }

func equal(a, b []byte) bool {
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
