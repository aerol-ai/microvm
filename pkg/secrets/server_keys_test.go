package secrets

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestServerTokenKeys(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ServerSeedSize)
	kid, key, err := ServerTokenKey(seed, 3)
	if err != nil || kid != ServerKeyIDBit|3 {
		t.Fatalf("kid %d %v", kid, err)
	}
	again, other := mustKey(t, seed, 3), mustKey(t, seed, 4)
	if !key.Equal(again) || key.Equal(other) {
		t.Fatal("keys are not one per seed and ring id")
	}
	if mustKey(t, bytes.Repeat([]byte{8}, ServerSeedSize), 3).Equal(key) {
		t.Fatal("another seed gave the same key")
	}
	// A ring-derived key for the same id is a different key.
	c, err := NewCipherRing([]RingKey{{ID: 3, Key: bytes.Repeat([]byte{7}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := c.SandboxTokenVerifyKey(3); !ok || pub.Equal(key.Public()) {
		t.Fatal("a server key equals the ring key")
	}
	if _, _, err := ServerTokenKey(seed[:5], 1); !errors.Is(err, ErrServerSeed) {
		t.Fatalf("short seed = %v", err)
	}
	if _, err := ServerTokenKeyID(ServerKeyIDBit); err == nil {
		t.Fatal("a ring id in the server range")
	}
	if _, _, err := ServerTokenKey(seed, ServerKeyIDBit|1); err == nil {
		t.Fatal("a ring id in the server range derived")
	}
}

func mustKey(t *testing.T, seed []byte, id uint32) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ServerTokenKey(seed, id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestServerSealer(t *testing.T) {
	seed := bytes.Repeat([]byte{1}, ServerSeedSize)
	s, err := NewServerIdentitySealer(seed)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("private"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := s.Open(sealed, []byte("aad")); err != nil || string(plain) != "private" {
		t.Fatalf("open = %q %v", plain, err)
	}
	if _, err := s.Open(sealed, []byte("other")); err == nil {
		t.Fatal("opened under another aad")
	}
	if _, err := s.Open(sealed[:4], []byte("aad")); err == nil {
		t.Fatal("opened a short blob")
	}
	other, _ := NewServerIdentitySealer(bytes.Repeat([]byte{2}, ServerSeedSize))
	if _, err := other.Open(sealed, []byte("aad")); err == nil {
		t.Fatal("another seed opened it")
	}
	// The ring cannot open it: it is not ring-sealed.
	c, _ := NewCipherRing([]RingKey{{ID: 1, Key: bytes.Repeat([]byte{1}, 32), Current: true}})
	if _, err := c.DecryptWithAAD(sealed, []byte("aad")); err == nil {
		t.Fatal("the ring opened a server-sealed blob")
	}
	if _, err := NewServerIdentitySealer(nil); !errors.Is(err, ErrServerSeed) {
		t.Fatalf("no seed = %v", err)
	}
}
