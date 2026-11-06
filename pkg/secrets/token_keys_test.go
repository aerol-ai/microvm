package secrets

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

// Two nodes that hold the same server key derive the same token key pair,
// so a token one signs, the other verifies. Another server key gives an
// unrelated pair, and the seed is not the server key itself.
func TestSandboxTokenKeysAgreeAcrossNodes(t *testing.T) {
	a := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	b := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	other := mustRing(t, RingKey{ID: 0, Key: digestKey(2), Current: true})

	kid, priv, err := a.SandboxTokenSigner()
	if err != nil || kid != 0 {
		t.Fatalf("SandboxTokenSigner = %d, %v", kid, err)
	}
	if bytes.Equal(priv.Seed(), digestKey(1)) {
		t.Fatal("the token key is the server key itself, not derived from it")
	}
	sig := ed25519.Sign(priv, []byte("claims"))
	pubB, ok := b.SandboxTokenVerifyKey(0)
	if !ok || !ed25519.Verify(pubB, []byte("claims"), sig) {
		t.Fatal("a node holding the same server key cannot verify the token")
	}
	pubOther, ok := other.SandboxTokenVerifyKey(0)
	if !ok || ed25519.Verify(pubOther, []byte("claims"), sig) {
		t.Fatal("another server key verified the token")
	}
	if _, ok := a.SandboxTokenVerifyKey(7); ok {
		t.Fatal("an id the ring does not hold has a verify key")
	}
}

// A rotation: a staged key verifies but does not sign; once promoted it
// signs, and the old key still verifies until it is retired (dropped from
// the ring). A key carried over by id (a re-read) keeps its token key.
func TestSandboxTokenKeysFollowTheRotation(t *testing.T) {
	c := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	_, oldPriv, _ := c.SandboxTokenSigner()
	oldSig := ed25519.Sign(oldPriv, []byte("old"))

	// Stage key 1.
	if err := c.SetRing([]RingKey{{ID: 0, Current: true}, {ID: 1, Key: digestKey(2)}}); err != nil {
		t.Fatal(err)
	}
	if kid, _, _ := c.SandboxTokenSigner(); kid != 0 {
		t.Fatalf("a staged key signs (kid %d)", kid)
	}
	if _, ok := c.SandboxTokenVerifyKey(1); !ok {
		t.Fatal("a staged key does not verify")
	}

	// Promote key 1: it signs; key 0 still verifies its tokens.
	if err := c.SetRing([]RingKey{{ID: 0}, {ID: 1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	kid, newPriv, err := c.SandboxTokenSigner()
	if err != nil || kid != 1 || bytes.Equal(newPriv, oldPriv) {
		t.Fatalf("after promote: kid %d err %v", kid, err)
	}
	pub0, ok := c.SandboxTokenVerifyKey(0)
	if !ok || !ed25519.Verify(pub0, []byte("old"), oldSig) {
		t.Fatal("the previous key stopped verifying before it was retired")
	}

	// Retire key 0: its tokens stop verifying.
	if err := c.SetRing([]RingKey{{ID: 1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.SandboxTokenVerifyKey(0); ok {
		t.Fatal("a retired key still verifies")
	}
}

// A revoke drops the token keys with every other key: nothing signs and
// nothing verifies until the ring is restored.
func TestSandboxTokenKeysDropOnRevoke(t *testing.T) {
	c := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	c.Revoke()
	if _, _, err := c.SandboxTokenSigner(); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("SandboxTokenSigner after revoke = %v, want ErrKeyRevoked", err)
	}
	if _, ok := c.SandboxTokenVerifyKey(0); ok {
		t.Fatal("a revoked cipher still verifies")
	}
	if err := c.RestoreRing([]RingKey{{ID: 0, Key: digestKey(1), Current: true}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.SandboxTokenVerifyKey(0); !ok {
		t.Fatal("a restored cipher does not verify")
	}

	var nilCipher *Cipher
	if _, _, err := nilCipher.SandboxTokenSigner(); err == nil {
		t.Fatal("a nil cipher signs")
	}
	if _, ok := nilCipher.SandboxTokenVerifyKey(0); ok {
		t.Fatal("a nil cipher verifies")
	}
}

// A ring whose current entry somehow has no token key (a hand-built ring
// in a test, never buildRing) fails closed rather than signing with nil.
func TestSandboxTokenSignerMissingKeyFailsClosed(t *testing.T) {
	c := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	r := c.ring.Load()
	broken := &keyRing{current: r.current, keys: r.keys, digestKeys: r.digestKeys, tokenKeys: map[uint32]ed25519.PrivateKey{}}
	c.ring.Store(broken)
	if _, _, err := c.SandboxTokenSigner(); err == nil {
		t.Fatal("signed without a token key")
	}
}
