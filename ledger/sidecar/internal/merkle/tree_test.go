package merkle

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 6962 §2.1: leaf hash = SHA-256(0x00 || data); empty tree = SHA-256("")
func TestEmptyRoot(t *testing.T) {
	got := Root(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(got) != want {
		t.Fatalf("empty root = %x", got)
	}
}

func TestSingleLeaf(t *testing.T) {
	leaf := []byte("hello")
	want := LeafHash(leaf)
	got := Root([][]byte{leaf})
	if !equal(got, want) {
		t.Fatalf("got=%x want=%x", got, want)
	}
}

// Known test vector: 4-leaf tree
//
//	leaves = ["", "", "", ""]
//	Each LeafHash("") = SHA-256(0x00) = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
//	Root should be NodeHash(NodeHash(L,L), NodeHash(L,L))
func TestFourEmptyLeaves(t *testing.T) {
	leaves := [][]byte{{}, {}, {}, {}}
	lh := LeafHash(nil)
	t.Logf("LeafHash(empty) = %x", lh)
	root := Root(leaves)
	// Just verify it equals the manual computation
	mid := NodeHash(lh, lh)
	want := NodeHash(mid, mid)
	if !equal(root, want) {
		t.Fatalf("root mismatch")
	}
}

func TestInclusionRoundtrip(t *testing.T) {
	for _, size := range []int{1, 2, 3, 4, 5, 8, 13, 100, 257} {
		leaves := randomLeaves(t, size)
		root := Root(leaves)
		for _, idx := range []int{0, size / 2, size - 1} {
			if idx < 0 || idx >= size {
				continue
			}
			proof, err := InclusionProof(leaves, idx)
			if err != nil {
				t.Fatalf("size=%d idx=%d build proof: %v", size, idx, err)
			}
			if err := VerifyInclusion(root, LeafHash(leaves[idx]), idx, size, proof); err != nil {
				t.Fatalf("size=%d idx=%d verify: %v", size, idx, err)
			}
		}
	}
}

func TestInclusionRejectsTampering(t *testing.T) {
	leaves := randomLeaves(t, 17)
	root := Root(leaves)
	proof, _ := InclusionProof(leaves, 7)

	// flip a bit in the leaf
	tamperedLeaf := append([]byte(nil), leaves[7]...)
	tamperedLeaf[0] ^= 0xff
	if err := VerifyInclusion(root, LeafHash(tamperedLeaf), 7, 17, proof); err == nil {
		t.Fatal("tampered leaf should fail verification")
	}

	// flip a bit in the proof
	if len(proof) > 0 {
		proof[0][0] ^= 0xff
		if err := VerifyInclusion(root, LeafHash(leaves[7]), 7, 17, proof); err == nil {
			t.Fatal("tampered proof should fail verification")
		}
	}
}

func TestConsistencyRoundtrip(t *testing.T) {
	for _, pair := range [][2]int{
		{1, 1}, {1, 2}, {1, 8}, {3, 5}, {4, 7}, {7, 13}, {8, 16}, {100, 257},
	} {
		m, n := pair[0], pair[1]
		leaves := randomLeaves(t, n)
		oldRoot := Root(leaves[:m])
		newRoot := Root(leaves[:n])
		proof, err := ConsistencyProof(leaves, m, n)
		if err != nil {
			t.Fatalf("m=%d n=%d build: %v", m, n, err)
		}
		if err := VerifyConsistency(oldRoot, newRoot, m, n, proof); err != nil {
			t.Fatalf("m=%d n=%d verify: %v (proof %d nodes)", m, n, err, len(proof))
		}
	}
}

func TestConsistencyRejectsTampering(t *testing.T) {
	n := 100
	leaves := randomLeaves(t, n)
	oldRoot := Root(leaves[:30])
	newRoot := Root(leaves[:n])
	proof, _ := ConsistencyProof(leaves, 30, n)

	// flip the "new" root
	bad := append([]byte(nil), newRoot...)
	bad[0] ^= 0xff
	if err := VerifyConsistency(oldRoot, bad, 30, n, proof); err == nil {
		t.Fatal("tampered new root should fail")
	}
	// flip a proof node
	if len(proof) > 0 {
		proof[0][0] ^= 0xff
		if err := VerifyConsistency(oldRoot, newRoot, 30, n, proof); err == nil {
			t.Fatal("tampered proof should fail")
		}
	}
}

func randomLeaves(t *testing.T, n int) [][]byte {
	t.Helper()
	out := make([][]byte, n)
	for i := range out {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		out[i] = buf
	}
	return out
}
