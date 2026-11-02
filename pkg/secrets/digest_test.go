package secrets

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

func digestKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func mustRing(t *testing.T, keys ...RingKey) *Cipher {
	t.Helper()
	c, err := NewCipherRing(keys)
	if err != nil {
		t.Fatalf("NewCipherRing: %v", err)
	}
	return c
}

func mustDigests(t *testing.T, c *Cipher, purpose string, data []byte) []KeyedDigest {
	t.Helper()
	d, err := c.Digests(purpose, data)
	if err != nil {
		t.Fatalf("Digests: %v", err)
	}
	return d
}

func TestDigestsAreKeyedAndStable(t *testing.T) {
	data := []byte(`{"env":{"DB_PASSWORD":"hunter2"}}`)
	a := mustDigests(t, mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true}), "p", data)
	// The same key loaded again: a restart, or another node sharing the key.
	b := mustDigests(t, mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true}), "p", data)
	if len(a) != 1 || a[0].KeyID != 0 || len(a[0].Sum) != sha256.Size {
		t.Fatalf("digests = %+v, want one 32-byte digest under key 0", a)
	}
	if !bytes.Equal(a[0].Sum, b[0].Sum) {
		t.Fatal("the same key and data gave two digests")
	}

	for name, other := range map[string][]KeyedDigest{
		"another key":     mustDigests(t, mustRing(t, RingKey{ID: 0, Key: digestKey(2), Current: true}), "p", data),
		"another purpose": mustDigests(t, mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true}), "q", data),
		"other data":      mustDigests(t, mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true}), "p", append(data, ' ')),
	} {
		if bytes.Equal(other[0].Sum, a[0].Sum) {
			t.Fatalf("%s gave the same digest", name)
		}
	}

	// Not a plain hash, and not an HMAC under the server key itself: the
	// digest key is derived, so a digest says nothing usable about the key.
	plain := sha256.Sum256(data)
	raw := hmac.New(sha256.New, digestKey(1))
	raw.Write([]byte("p\x00"))
	raw.Write(data)
	if bytes.Equal(a[0].Sum, plain[:]) || bytes.Equal(a[0].Sum, raw.Sum(nil)) {
		t.Fatal("the digest is not under a derived key")
	}
	if bytes.Contains(a[0].Sum, []byte("hunter2")) {
		t.Fatal("the digest holds its input")
	}
}

// A rotation's ring gives one digest per key, the current key's first, and a
// key carried over by id (a re-read that does not unwrap it again) keeps the
// digest it had.
func TestDigestsFollowTheRing(t *testing.T) {
	data := []byte("create")
	c := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	before := mustDigests(t, c, "p", data)

	// Stage key 2: key 0 stays current.
	if err := c.SetRing([]RingKey{{ID: 0, Current: true}, {ID: 2, Key: digestKey(2)}}); err != nil {
		t.Fatal(err)
	}
	staged := mustDigests(t, c, "p", data)
	if len(staged) != 2 || staged[0].KeyID != 0 || staged[1].KeyID != 2 || !bytes.Equal(staged[0].Sum, before[0].Sum) {
		t.Fatalf("staged digests = %+v, want key 0 (unchanged) then key 2", staged)
	}

	// Promote key 2.
	if err := c.SetRing([]RingKey{{ID: 0}, {ID: 2, Current: true}}); err != nil {
		t.Fatal(err)
	}
	promoted := mustDigests(t, c, "p", data)
	if len(promoted) != 2 || promoted[0].KeyID != 2 || promoted[1].KeyID != 0 ||
		!bytes.Equal(promoted[0].Sum, staged[1].Sum) || !bytes.Equal(promoted[1].Sum, before[0].Sum) {
		t.Fatalf("promoted digests = %+v, want key 2 then key 0, each unchanged", promoted)
	}

	// A third key staged mid-rotation: the current key first, then by id.
	if err := c.SetRing([]RingKey{{ID: 0}, {ID: 2, Current: true}, {ID: 1, Key: digestKey(3)}}); err != nil {
		t.Fatal(err)
	}
	if three := mustDigests(t, c, "p", data); len(three) != 3 || three[0].KeyID != 2 || three[1].KeyID != 0 || three[2].KeyID != 1 {
		t.Fatalf("three-key digests = %+v, want keys 2, 0, 1", three)
	}

	// Retire key 0.
	if err := c.SetRing([]RingKey{{ID: 2, Current: true}}); err != nil {
		t.Fatal(err)
	}
	if retired := mustDigests(t, c, "p", data); len(retired) != 1 || retired[0].KeyID != 2 || !bytes.Equal(retired[0].Sum, staged[1].Sum) {
		t.Fatalf("retired digests = %+v, want key 2 alone", retired)
	}
}

func TestDigestsRevokeAndRestore(t *testing.T) {
	c := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	before := mustDigests(t, c, "p", nil)
	c.Revoke()
	if _, err := c.Digests("p", nil); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("Digests after revoke = %v, want ErrKeyRevoked", err)
	}
	if err := c.RestoreRing([]RingKey{{ID: 0, Key: digestKey(1), Current: true}}); err != nil {
		t.Fatal(err)
	}
	if after := mustDigests(t, c, "p", nil); !bytes.Equal(after[0].Sum, before[0].Sum) {
		t.Fatal("a restored key gives another digest")
	}
}

func TestDigestsRefuseBadInput(t *testing.T) {
	c := mustRing(t, RingKey{ID: 0, Key: digestKey(1), Current: true})
	for _, purpose := range []string{"", "a\x00b"} {
		if _, err := c.Digests(purpose, nil); err == nil {
			t.Fatalf("Digests(%q) succeeded", purpose)
		}
	}
	var nilCipher *Cipher
	if _, err := nilCipher.Digests("p", nil); err == nil {
		t.Fatal("a nil Cipher digested")
	}
}

// String is the stored and recorded form: the key id, then the hex digest.
func TestKeyedDigestString(t *testing.T) {
	for _, tc := range []struct {
		d    KeyedDigest
		want string
	}{
		{KeyedDigest{KeyID: 0, Sum: []byte{0x00, 0xab}}, "hmac:0:00ab"},
		{KeyedDigest{KeyID: 4294967295, Sum: []byte{0xff}}, "hmac:4294967295:ff"},
		{KeyedDigest{KeyID: 7}, "hmac:7:"},
	} {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}
