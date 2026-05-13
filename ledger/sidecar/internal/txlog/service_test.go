package txlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	stdhex "encoding/hex"
	"fmt"
	"testing"
)

// SignedSTHBytes must produce a stable, parseable canonical message so that
// witnesses and the verify CLI can re-derive bytes identically.
func TestSignedSTHBytes_Format(t *testing.T) {
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	got := SignedSTHBytes(42, root, 1_700_000_000_000)
	want := "fp.sth.v1|42|" + stdhex.EncodeToString(root) + "|1700000000000"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSignedSTHBytes_EmptyRoot(t *testing.T) {
	got := SignedSTHBytes(0, []byte{}, 0)
	want := "fp.sth.v1|0||0"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSignedSTHBytes_NegativeTimestamp(t *testing.T) {
	// We don't expect this in practice, but the canonical form should still be
	// deterministic so that mismatches don't silently slip past sig verification.
	root := make([]byte, 32)
	got := SignedSTHBytes(1, root, -5)
	want := fmt.Sprintf("fp.sth.v1|1|%s|-5", stdhex.EncodeToString(root))
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Round-trip: sign canonical bytes with admin key, verify with the published
// pubkey, and confirm tampering (any byte flip anywhere in the canonical
// message) breaks verification.
func TestSignedSTH_SignVerifyRoundtrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := sha256.Sum256([]byte("some-root"))
	msg := SignedSTHBytes(7, root[:], 1234567890)
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("expected verify ok on untouched message")
	}
	// Flip a byte and ensure verify fails.
	tampered := bytes.Clone(msg)
	tampered[10] ^= 0x01
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatalf("expected verify FAIL on tampered message")
	}
	// Flip a byte in the signature instead.
	badSig := bytes.Clone(sig)
	badSig[5] ^= 0x80
	if ed25519.Verify(pub, msg, badSig) {
		t.Fatalf("expected verify FAIL on tampered sig")
	}
}

// Differing tree_size, root, or timestamp must produce different canonical
// bytes so that a STH signed at (n, r1, t1) cannot be passed off as (n, r2, t1)
// (or any other permutation).
func TestSignedSTHBytes_DifferentInputsDifferentBytes(t *testing.T) {
	root1 := bytes.Repeat([]byte{0x11}, 32)
	root2 := bytes.Repeat([]byte{0x22}, 32)
	a := SignedSTHBytes(10, root1, 100)
	b := SignedSTHBytes(10, root2, 100) // different root
	c := SignedSTHBytes(11, root1, 100) // different size
	d := SignedSTHBytes(10, root1, 101) // different ts
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, d) {
		t.Fatalf("canonical bytes collide:\n a=%q\n b=%q\n c=%q\n d=%q", a, b, c, d)
	}
}

// The lowercase-hex encoding of the root must match the standard library
// `encoding/hex` output exactly — this is a stability test against the
// internal `hex()` helper drifting.
func TestInternalHex_MatchesStdlib(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 64} {
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if hex(buf) != stdhex.EncodeToString(buf) {
			t.Fatalf("internal hex differs from stdlib at n=%d", n)
		}
	}
}
