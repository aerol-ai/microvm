package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ringKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fixedNonceReader yields one nonce: the first 12 bytes it is asked for.
type fixedNonceReader struct{ b []byte }

func (r *fixedNonceReader) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	r.b = r.b[n:]
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// TestCipherRingDualRead (eng D26): a legacy blob and a key-id blob both
// open; while the legacy key is current the output is today's format; a
// legacy blob whose nonce happens to start with the marker and a ring id
// fails the key-id try cleanly and opens as legacy.
func TestCipherRingDualRead(t *testing.T) {
	k0, k1 := ringKey(t), ringKey(t)
	c, err := NewCipherRing([]RingKey{{ID: 0, Key: k0, Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := c.EncryptWithAAD([]byte("legacy"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	// Today's format: an older build opens it with the bare key.
	gcm, _ := newGCM(k0)
	if got, err := openGCM(gcm, legacy, []byte("aad")); err != nil || string(got) != "legacy" {
		t.Fatalf("legacy format = %q %v", got, err)
	}

	// A legacy blob that looks like a key-id blob for key 1.
	old := randReader
	randReader = &fixedNonceReader{b: []byte{keyIDMarker, 0, 0, 0, 1, 9, 9, 9, 9, 9, 9, 9}}
	tricky, err := c.EncryptWithAAD([]byte("tricky"), nil)
	randReader = old
	if err != nil || SealedKeyID(tricky) != 1 {
		t.Fatalf("tricky = %v id %d", err, SealedKeyID(tricky))
	}

	if err := c.SetRing([]RingKey{{ID: 0, Key: nil}, {ID: 1, Key: k1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	if c.CurrentKeyID() != 1 || !c.Rotating() || len(c.KeyIDs()) != 2 {
		t.Fatalf("ring = current %d ids %v", c.CurrentKeyID(), c.KeyIDs())
	}
	fresh, err := c.EncryptWithAAD([]byte("fresh"), []byte("aad"))
	if err != nil || fresh[0] != keyIDMarker || binary.BigEndian.Uint32(fresh[1:5]) != 1 || SealedKeyID(fresh) != 1 {
		t.Fatalf("fresh = %x %v", fresh[:5], err)
	}
	for _, tc := range []struct {
		blob []byte
		aad  string
		want string
		id   uint32
	}{{legacy, "aad", "legacy", 0}, {fresh, "aad", "fresh", 1}, {tricky, "", "tricky", 0}} {
		var aad []byte
		if tc.aad != "" {
			aad = []byte(tc.aad)
		}
		got, id, err := c.OpenWithKeyID(tc.blob, aad)
		if err != nil || string(got) != tc.want || id != tc.id {
			t.Fatalf("%s: %q id %d %v", tc.want, got, id, err)
		}
	}
	if _, err := c.DecryptWithAAD(fresh, []byte("other")); err == nil {
		t.Fatal("a key-id blob opened under the wrong AAD")
	}
	if _, err := c.Decrypt([]byte{keyIDMarker, 0, 0}); err == nil {
		t.Fatal("a truncated blob opened")
	}

	// Retire key 0: legacy blobs open no more, key-1 blobs still do.
	if err := c.SetRing([]RingKey{{ID: 1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(legacy); err == nil || !strings.Contains(err.Error(), "no key in the ring") {
		t.Fatalf("legacy after retire = %v", err)
	}
	if got, err := c.DecryptWithAAD(fresh, []byte("aad")); err != nil || string(got) != "fresh" {
		t.Fatalf("fresh after retire = %q %v", got, err)
	}
	if c.Rotating() {
		t.Fatal("a one-key ring reports a rotation")
	}
}

func TestCipherSetRingRules(t *testing.T) {
	k0, k1, other := ringKey(t), ringKey(t), ringKey(t)
	c, err := NewCipherRing([]RingKey{{ID: 0, Key: k0, Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name string
		keys []RingKey
		want string
	}{
		{"no current", []RingKey{{ID: 0, Key: k0}}, "exactly one current"},
		{"two current", []RingKey{{ID: 0, Key: k0, Current: true}, {ID: 1, Key: k1, Current: true}}, "exactly one current"},
		{"duplicate id", []RingKey{{ID: 0, Key: k0, Current: true}, {ID: 0, Key: k1}}, "appears twice"},
		{"swapped key under a known id", []RingKey{{ID: 0, Key: other, Current: true}}, "not the key this node already holds"},
		{"nil key never loaded", []RingKey{{ID: 0, Current: true}, {ID: 5}}, "not loaded"},
		{"short key", []RingKey{{ID: 0, Key: k0, Current: true}, {ID: 1, Key: k1[:7]}}, "aes"},
	}
	for _, tc := range bad {
		if err := c.SetRing(tc.keys); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	if c.CurrentKeyID() != 0 || len(c.KeyIDs()) != 1 {
		t.Fatal("a refused ring changed the Cipher")
	}
	if _, err := NewCipherRing([]RingKey{{ID: 0, Key: k0}}); err == nil {
		t.Fatal("a ring with no current key built a Cipher")
	}
	if SealedKeyID([]byte{keyIDMarker, 0}) != 0 || SealedKeyID([]byte{1, 0, 0, 0, 1, 2}) != 0 {
		t.Fatal("SealedKeyID of a short or legacy blob")
	}
	if !c.HoldsKey(0, serverKeyCheck(k0)) || c.HoldsKey(0, serverKeyCheck(other)) || c.HoldsKey(9, nil) {
		t.Fatal("HoldsKey")
	}
	var nilC *Cipher
	if nilC.SetRing(nil) == nil || nilC.RestoreRing(nil) == nil || nilC.CurrentKeyID() != 0 || nilC.KeyIDs() != nil || nilC.Rotating() || nilC.HoldsKey(0, nil) {
		t.Fatal("nil cipher")
	}
	if _, _, _, err := nilC.Reseal(nil, nil); err == nil {
		t.Fatal("nil cipher resealed")
	}
}

// TestCipherRevokeDropsRing (eng D26): revoke drops every ring key, a ring
// change while revoked does not bring them back, and recovery restores the
// whole ring.
func TestCipherRevokeDropsRing(t *testing.T) {
	k0, k1 := ringKey(t), ringKey(t)
	ring := []RingKey{{ID: 0, Key: k0}, {ID: 1, Key: k1, Current: true}}
	c, err := NewCipherRing(ring)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := c.Encrypt([]byte("x"))
	c.Revoke()
	if _, err := c.Decrypt(sealed); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("decrypt while revoked = %v", err)
	}
	if _, _, _, err := c.Reseal(sealed, nil); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("reseal while revoked = %v", err)
	}
	if c.KeyIDs() != nil || c.Rotating() {
		t.Fatal("a revoked Cipher still lists keys")
	}
	if err := c.SetRing(ring); err != nil {
		t.Fatal(err)
	}
	if !c.Revoked() {
		t.Fatal("SetRing revived a revoked Cipher")
	}
	if err := c.RestoreRing([]RingKey{{ID: 0, Key: k1, Current: true}}); err == nil {
		t.Fatal("restore under a known id with another key")
	}
	if err := c.RestoreRing(ring); err != nil || c.Revoked() {
		t.Fatalf("restore = %v", err)
	}
	if got, err := c.Decrypt(sealed); err != nil || string(got) != "x" {
		t.Fatalf("after restore = %q %v", got, err)
	}
}

func TestCipherReseal(t *testing.T) {
	k0, k1 := ringKey(t), ringKey(t)
	c, _ := NewCipherRing([]RingKey{{ID: 0, Key: k0, Current: true}})
	old, _ := c.EncryptWithAAD([]byte("v"), []byte("a"))
	if out, from, changed, err := c.Reseal(old, []byte("a")); err != nil || changed || from != 0 || !bytes.Equal(out, old) {
		t.Fatalf("reseal on the current key = %v %v %d", err, changed, from)
	}
	if err := c.SetRing([]RingKey{{ID: 0}, {ID: 1, Key: k1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	out, from, changed, err := c.Reseal(old, []byte("a"))
	if err != nil || !changed || from != 0 || SealedKeyID(out) != 1 {
		t.Fatalf("reseal = %v %v %d", err, changed, from)
	}
	if got, id, err := c.OpenWithKeyID(out, []byte("a")); err != nil || string(got) != "v" || id != 1 {
		t.Fatalf("resealed opens = %q %d %v", got, id, err)
	}
	if _, _, _, err := c.Reseal(old, []byte("wrong")); err == nil {
		t.Fatal("resealed under the wrong AAD")
	}
	old2 := randReader
	randReader = errReader{}
	_, _, _, err = c.Reseal(old, []byte("a"))
	randReader = old2
	if err == nil {
		t.Fatal("reseal without entropy")
	}
}

func TestRingSteps(t *testing.T) {
	k0, k1 := ringKey(t), ringKey(t)
	ring := []RingEntry{LegacyRingEntry(k0)}
	if NextRingID(ring) != 1 {
		t.Fatal("next id")
	}
	staged, err := NewRingEntry(context.Background(), 1, nil)
	if err != nil || len(staged.Key) != 32 || staged.State != RingStateDecrypt {
		t.Fatalf("staged = %+v %v", staged, err)
	}
	if _, err := StageRingKey(ring, RingEntry{ID: 7, State: RingStateDecrypt}); err == nil {
		t.Fatal("staged a skipped id")
	}
	ring, err = StageRingKey(ring, staged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StageRingKey(ring, RingEntry{ID: 2, State: RingStateDecrypt}); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("second stage = %v", err)
	}
	ring, from, to, err := PromoteRingKey(ring)
	if err != nil || from != 0 || to != 1 || RingSummary(ring) != "0:decrypt,1:current" {
		t.Fatalf("promote = %s %d %d %v", RingSummary(ring), from, to, err)
	}
	if _, _, _, err := PromoteRingKey(ring); err == nil {
		t.Fatal("promoted an old key back")
	}
	if _, err := RetireRingKey(ring, 1); err == nil {
		t.Fatal("retired the current key")
	}
	if _, err := RetireRingKey(ring, 4); err == nil {
		t.Fatal("retired a missing key")
	}
	ring, err = RetireRingKey(ring, 0)
	if err != nil || RingSummary(ring) != "0:retired,1:current" || ring[0].Key != nil || len(ring[0].Check) != 16 {
		t.Fatalf("retire = %+v %v", ring, err)
	}
	if _, err := RetireRingKey(ring, 0); err == nil {
		t.Fatal("retired twice")
	}
	if err := validateRing(ring, false); err != nil {
		t.Fatal(err)
	}
	if NextRingID(ring) != 2 {
		t.Fatal("ids are never reused")
	}
	// Retiring a staged key cancels the rotation.
	cancel := []RingEntry{LegacyRingEntry(k0), {ID: 1, State: RingStateDecrypt, Key: k1, Check: serverKeyCheck(k1)}}
	if out, err := RetireRingKey(cancel, 1); err != nil || RingSummary(out) != "0:current,1:retired" {
		t.Fatalf("cancel = %v", err)
	}
	got := ParseRingSummary("0:retired,1:current,junk,2:decrypt")
	if len(got) != 3 || got[1] != RingStateCurrent || got[2] != RingStateDecrypt {
		t.Fatalf("parse = %v", got)
	}
}

func TestValidateRing(t *testing.T) {
	k := ringKey(t)
	check := serverKeyCheck(k)
	cases := []struct {
		name    string
		ring    []RingEntry
		wrapped bool
		want    string
	}{
		{"empty", nil, false, "empty"},
		{"no check", []RingEntry{{ID: 0, State: RingStateCurrent, Key: k}}, false, "no check"},
		{"bad state", []RingEntry{{ID: 0, State: "old", Key: k, Check: check}}, false, "unknown state"},
		{"retired with bytes", []RingEntry{{ID: 0, State: RingStateRetired, Key: k, Check: check}}, false, "still holds"},
		{"plain key in a wrapped ring", []RingEntry{{ID: 0, State: RingStateCurrent, Key: k, Check: check}}, true, "only its wrapped key"},
		{"check mismatch", []RingEntry{{ID: 0, State: RingStateCurrent, Key: k, Check: make([]byte, 16)}}, false, "matching its check"},
		{"dup", []RingEntry{{ID: 0, State: RingStateCurrent, Key: k, Check: check}, {ID: 0, State: RingStateRetired, Check: check}}, false, "twice"},
		{"no current", []RingEntry{{ID: 0, State: RingStateDecrypt, Key: k, Check: check}}, false, "exactly one current"},
	}
	for _, tc := range cases {
		if err := validateRing(tc.ring, tc.wrapped); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}

func TestKeyRingFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential_encryption.key.ring")
	k0 := ringKey(t)
	staged, _ := NewRingEntry(context.Background(), 1, nil)
	if err := WriteKeyRingFile(path, KeyRingFile{Ring: []RingEntry{staged, LegacyRingEntry(k0)}}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	f, err := ReadKeyRingFile(path)
	if err != nil || f.Ring[0].ID != 0 || len(f.RingKeys()) != 2 {
		t.Fatalf("read = %+v %v", f, err)
	}
	if e, ok := f.Entry(1); !ok || e.State != RingStateDecrypt {
		t.Fatal("entry 1")
	}
	if _, ok := f.Entry(3); ok {
		t.Fatal("entry 3")
	}
	if err := WriteKeyRingFile(path, KeyRingFile{}); err == nil {
		t.Fatal("wrote an empty ring")
	}
	for name, body := range map[string]string{"bad json": "{", "format": `{"format":9,"ring":[]}`, "invalid": `{"format":1,"ring":[]}`} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadKeyRingFile(p); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyRingFile(path); err == nil {
		t.Fatal("a group-readable ring file was read")
	}
	if _, err := ReadKeyRingFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing")
	}
	if err := writeSecretJSON(filepath.Join(dir, "x"), func() {}, ".x-*"); err == nil {
		t.Fatal("marshalled a func")
	}
	if err := writeSecretJSON(filepath.Join(path, "below-a-file"), 1, ".x-*"); err == nil {
		t.Fatal("wrote below a file")
	}
}

// TestWrappedRingFile: a ring wrapped file round-trips; a ring of the
// legacy key alone stays format 1; a hand edit is refused; the ring
// unwraps, skipping keys the Cipher holds.
func TestWrappedRingFile(t *testing.T) {
	ctx := context.Background()
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	k0 := ringKey(t)
	f, err := WrapServerKey(ctx, fake, k0, ProviderAWSKMS, "alias/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries()) != 1 || f.Entries()[0].State != RingStateCurrent {
		t.Fatal("format 1 entries")
	}
	staged, err := NewRingEntry(ctx, 1, fake)
	if err != nil || staged.Wrapped == nil || staged.Key != nil {
		t.Fatalf("wrapped staged = %+v %v", staged, err)
	}
	ring, _ := StageRingKey(f.Entries(), staged)
	nf := f
	if err := nf.SetEntries(ring); err != nil || nf.Format != WrappedKeyRingFormat || !bytes.Equal(nf.Wrapped, f.Wrapped) {
		t.Fatalf("set entries = %v %d", err, nf.Format)
	}
	path := filepath.Join(t.TempDir(), "k.wrapped")
	if err := WriteWrappedKeyFile(path, nf); err != nil {
		t.Fatal(err)
	}
	back, err := ReadWrappedKeyFile(path)
	if err != nil || len(back.Entries()) != 2 {
		t.Fatalf("read back = %v", err)
	}
	keys, err := UnwrapRing(ctx, fake, back, nil)
	if err != nil || len(keys) != 2 || keys[1].Key == nil {
		t.Fatalf("unwrap ring = %v", err)
	}
	c, err := NewCipherRing(keys)
	if err != nil {
		t.Fatal(err)
	}
	keys, err = UnwrapRing(ctx, failWrapper{}, back, c.HoldsKey)
	if err != nil || keys[0].Key != nil || keys[1].Key != nil {
		t.Fatalf("held keys were unwrapped again: %v", err)
	}
	if _, err := UnwrapRing(ctx, failWrapper{}, back, nil); err == nil || !strings.Contains(err.Error(), "ring key 0") {
		t.Fatalf("unwrap failure = %v", err)
	}

	// Promote then retire 0: format 2 with key 1 on top.
	ring, _, _, _ = PromoteRingKey(ring)
	ring, _ = RetireRingKey(ring, 0)
	if err := nf.SetEntries(ring); err != nil || !bytes.Equal(nf.Wrapped, staged.Wrapped) {
		t.Fatalf("after retire = %v", err)
	}
	// A ring of the legacy key alone is format 1.
	one := nf
	if err := one.SetEntries(f.Entries()); err != nil || one.Format != WrappedKeyFormat || one.Ring != nil {
		t.Fatal("legacy-only ring")
	}
	if err := one.SetEntries(nil); err == nil {
		t.Fatal("set an empty ring")
	}

	dir := t.TempDir()
	write := func(name string, v WrappedKeyFile) string {
		p := filepath.Join(dir, name)
		if err := writeSecretJSON(p, v, ".t-*"); err != nil {
			t.Fatal(err)
		}
		return p
	}
	edited := nf
	edited.Wrapped = f.Wrapped
	edited.Check = f.Check
	if _, err := ReadWrappedKeyFile(write("edited", edited)); err == nil || !strings.Contains(err.Error(), "edited by hand") {
		t.Fatalf("hand edit = %v", err)
	}
	f1ring := f
	f1ring.Ring = ring
	if _, err := ReadWrappedKeyFile(write("f1ring", f1ring)); err == nil {
		t.Fatal("format 1 with a ring")
	}
	badRing := nf
	badRing.Ring = []RingEntry{{ID: 0, State: RingStateCurrent, Wrapped: nf.Wrapped, Check: nf.Check}, {ID: 0, State: RingStateRetired, Check: nf.Check}}
	if _, err := ReadWrappedKeyFile(write("badring", badRing)); err == nil {
		t.Fatal("an invalid ring")
	}
	f3 := f
	f3.Format = 3
	if _, err := ReadWrappedKeyFile(write("f3", f3)); err == nil || !strings.Contains(err.Error(), "formats 1 and 2") {
		t.Fatalf("format 3 = %v", err)
	}
}

type failWrapper struct{}

func (failWrapper) Wrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, ErrProviderUnavailable
}
func (failWrapper) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, ErrProviderUnavailable
}

func TestRewrapWrapUnwrapRing(t *testing.T) {
	ctx := context.Background()
	fake, _ := NewFakeKMS()
	v2 := &anyVersion{tag: "vault:v2:", inner: fake}
	v1 := &anyVersion{tag: "vault:v1:", inner: fake}
	k0 := ringKey(t)
	f, err := WrapServerKey(ctx, v1, k0, ProviderVault, "aerolvm-kek")
	if err != nil {
		t.Fatal(err)
	}
	staged, _ := NewRingEntry(ctx, 1, v1)
	ring, _ := StageRingKey(f.Entries(), staged)
	if err := f.SetEntries(ring); err != nil {
		t.Fatal(err)
	}
	f.MigratedFromPlaintext = true
	if f.StaleRingKeys("vault:v2") != 2 || f.StaleRingKeys("vault:v1") != 0 {
		t.Fatal("stale count")
	}
	nf, err := RewrapRing(ctx, v2, f)
	if err != nil || nf.StaleRingKeys("vault:v2") != 0 || !nf.MigratedFromPlaintext || nf.Provider != ProviderVault {
		t.Fatalf("rewrap = %v", err)
	}
	if _, err := RewrapRing(ctx, failWrapper{}, f); err == nil {
		t.Fatal("rewrap without a key store")
	}
	if _, err := RewrapRing(ctx, &wrapOnlyFails{inner: fake}, f); err == nil {
		t.Fatal("rewrap with a failing wrap")
	}

	plain, err := UnwrapRingToFile(ctx, v2, nf)
	if err != nil || len(plain.Ring) != 2 || !bytes.Equal(plain.Ring[0].Key, k0) {
		t.Fatalf("unwrap to file = %v", err)
	}
	if _, err := UnwrapRingToFile(ctx, failWrapper{}, nf); err == nil {
		t.Fatal("unwrap to file without a key store")
	}
	retired, _ := RetireRingKey(plain.Ring, 1)
	back, err := WrapRing(ctx, v2, KeyRingFile{Ring: retired}, ProviderVault, "aerolvm-kek")
	if err != nil || back.Format != WrappedKeyRingFormat || RingSummary(back.Entries()) != "0:current,1:retired" {
		// The retired key's record stays, so the file stays a ring.
		t.Fatalf("wrap ring = %v %d", err, back.Format)
	}
	if _, err := WrapRing(ctx, failWrapper{}, plain, ProviderVault, ""); err == nil {
		t.Fatal("wrap ring without a key store")
	}
	if _, err := WrapRing(ctx, v2, KeyRingFile{}, ProviderVault, ""); err == nil {
		t.Fatal("wrapped an empty ring")
	}
	if _, err := NewRingEntry(ctx, 1, failWrapper{}); err == nil {
		t.Fatal("staged without a key store")
	}
	old := randReader
	randReader = errReader{}
	_, err = NewRingEntry(ctx, 1, nil)
	randReader = old
	if err == nil {
		t.Fatal("staged without entropy")
	}
}

// anyVersion is a Transit-like key: it wraps under its newest version and
// unwraps every version it still has.
type anyVersion struct {
	tag   string
	inner DataKeyWrapper
}

func (a *anyVersion) Wrap(ctx context.Context, k []byte, c map[string]string) ([]byte, error) {
	w, err := a.inner.Wrap(ctx, k, c)
	return append([]byte(a.tag), w...), err
}

func (a *anyVersion) Unwrap(ctx context.Context, w []byte, c map[string]string) ([]byte, error) {
	if i := bytes.IndexByte(w[len("vault:"):], ':'); bytes.HasPrefix(w, []byte("vault:")) && i > 0 {
		w = w[len("vault:")+i+1:]
	}
	return a.inner.Unwrap(ctx, w, c)
}

type wrapOnlyFails struct{ inner DataKeyWrapper }

func (w *wrapOnlyFails) Wrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, ErrProviderThrottled
}
func (w *wrapOnlyFails) Unwrap(ctx context.Context, b []byte, c map[string]string) ([]byte, error) {
	return w.inner.Unwrap(ctx, bytes.TrimPrefix(b, []byte("vault:v1:")), c)
}

// TestOpenServerKeyRings: boot opens custody=file's ring (checking a legacy
// key left in place) and a wrapped ring file.
func TestOpenServerKeyRings(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k0, other := ringKey(t), ringKey(t)
	keyPath := filepath.Join(dir, "credential_encryption.key")
	ringPath := keyPath + ".ring"
	staged, _ := NewRingEntry(ctx, 1, nil)
	ring, _ := StageRingKey([]RingEntry{LegacyRingEntry(k0)}, staged)
	if err := WriteKeyRingFile(ringPath, KeyRingFile{Ring: ring}); err != nil {
		t.Fatal(err)
	}
	in := CustodyInputs{Custody: CustodyFile, RingFileExists: true, RingPath: ringPath, PlaintextPath: keyPath}
	b64 := base64.StdEncoding.EncodeToString
	c, err := OpenServerKey(ctx, in, b64(k0), nil, "", "")
	if err != nil || len(c.KeyIDs()) != 2 || c.CurrentKeyID() != 0 {
		t.Fatalf("file ring = %v", err)
	}
	if _, err := OpenServerKey(ctx, in, b64(other), nil, "", ""); err == nil || !strings.Contains(err.Error(), "not key 0 of the ring") {
		t.Fatalf("mismatched legacy key = %v", err)
	}
	if _, err := OpenServerKey(ctx, in, "!!", nil, "", ""); err == nil {
		t.Fatal("a bad legacy key opened")
	}
	if RetiredKeyStillPresent(in, b64(k0)) {
		t.Fatal("key 0 is live, not retired")
	}
	// Retire key 0: the ring opens without it and flags the leftover key.
	ring, _, _, _ = PromoteRingKey(ring)
	ring, _ = RetireRingKey(ring, 0)
	if err := WriteKeyRingFile(ringPath, KeyRingFile{Ring: ring}); err != nil {
		t.Fatal(err)
	}
	if c, err = OpenServerKey(ctx, in, b64(other), nil, "", ""); err != nil || c.CurrentKeyID() != 1 || len(c.KeyIDs()) != 1 {
		t.Fatalf("retired ring = %v", err)
	}
	if !RetiredKeyStillPresent(in, b64(k0)) || RetiredKeyStillPresent(in, "") {
		t.Fatal("RetiredKeyStillPresent")
	}
	if RetiredKeyStillPresent(CustodyInputs{}, "x") || RetiredKeyStillPresent(CustodyInputs{RingFileExists: true, RingPath: filepath.Join(dir, "none")}, "x") {
		t.Fatal("RetiredKeyStillPresent without a ring")
	}
	if _, err := OpenServerKey(ctx, CustodyInputs{Custody: CustodyFile, RingFileExists: true, RingPath: filepath.Join(dir, "none")}, "", nil, "", ""); err == nil {
		t.Fatal("opened a missing ring")
	}

	// Wrapped custody: a format 2 file opens every live key.
	fake, _ := NewFakeKMS()
	f, _ := WrapServerKey(ctx, fake, k0, ProviderAWSKMS, "")
	wstaged, _ := NewRingEntry(ctx, 1, fake)
	wring, _ := StageRingKey(f.Entries(), wstaged)
	_ = f.SetEntries(wring)
	wpath := filepath.Join(dir, "k.wrapped")
	if err := WriteWrappedKeyFile(wpath, f); err != nil {
		t.Fatal(err)
	}
	win := CustodyInputs{Custody: CustodyWrapped, WrappedFileExists: true, WrappedPath: wpath}
	if c, err := OpenServerKey(ctx, win, "", fake, "", ""); err != nil || len(c.KeyIDs()) != 2 {
		t.Fatalf("wrapped ring = %v", err)
	}
	if _, err := OpenServerKey(ctx, win, "", failWrapper{}, "", ""); err == nil {
		t.Fatal("wrapped ring without a key store")
	}

	for _, tc := range []struct {
		in   CustodyInputs
		want CustodyAction
	}{
		{CustodyInputs{Custody: CustodyFile, RingFileExists: true, WrappedFileExists: true}, ActionPlaintext},
		{CustodyInputs{Custody: CustodyWrapped, RingFileExists: true, WrappedFileExists: true, RingPath: ringPath}, ActionRefuse},
	} {
		if got, _ := DecideCustody(tc.in); got != tc.want {
			t.Fatalf("decide %+v = %v", tc.in, got)
		}
	}
}

// TestResealLocalEnvelope: a local row moves onto the current ring key with
// only its wrapped key changed; key-store rows are left alone.
func TestResealLocalEnvelope(t *testing.T) {
	k0, k1 := ringKey(t), ringKey(t)
	c, _ := NewCipherRing([]RingKey{{ID: 0, Key: k0, Current: true}})
	b := rewrapBinding("sb-1")
	sealed, err := SealRawEnvelopeBound(c, []byte(`{"env":{"K":"v"}}`), []string{"n1"}, b)
	if err != nil {
		t.Fatal(err)
	}
	if out, from, changed, err := ResealLocalEnvelope(sealed, c); err != nil || changed || from != 0 || !bytes.Equal(out, sealed) {
		t.Fatalf("current = %v %v", changed, err)
	}
	if err := c.SetRing([]RingKey{{ID: 0}, {ID: 1, Key: k1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	out, from, changed, err := ResealLocalEnvelope(sealed, c)
	if err != nil || !changed || from != 0 || !SameEnvelopeContent(sealed, out) {
		t.Fatalf("reseal = %v %v", changed, err)
	}
	if plain, err := OpenRawEnvelopeBound(c, out, "n1", b); err != nil || string(plain) != `{"env":{"K":"v"}}` {
		t.Fatalf("open resealed = %q %v", plain, err)
	}
	fake, _ := NewFakeKMS()
	tagged := sealWith(t, &prefixed{tag: "vault:v1:", inner: fake}, b)
	if _, _, _, err := ResealLocalEnvelope(tagged, c); !errors.Is(err, ErrNotLocalRow) {
		t.Fatalf("vault row = %v", err)
	}
	kmsRow := sealWith(t, fake, b)
	if _, _, _, err := ResealLocalEnvelope(kmsRow, c); !errors.Is(err, ErrNotLocalRow) {
		t.Fatalf("kms row = %v", err)
	}
	if _, _, _, err := ResealLocalEnvelope([]byte("{"), c); err == nil {
		t.Fatal("garbage resealed")
	}
	c.Revoke()
	if _, _, _, err := ResealLocalEnvelope(sealed, c); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revoked = %v", err)
	}
}

// TestReplaceWrappedKeyFile: the daemon's rewrap and `sandboxd key rotate`
// never undo each other's edit of the server-key file.
func TestReplaceWrappedKeyFile(t *testing.T) {
	ctx := context.Background()
	fake, _ := NewFakeKMS()
	f, _ := WrapServerKey(ctx, fake, ringKey(t), ProviderAWSKMS, "")
	path := filepath.Join(t.TempDir(), "k.wrapped")
	if err := WriteWrappedKeyFile(path, f); err != nil {
		t.Fatal(err)
	}
	staged, _ := NewRingEntry(ctx, 1, fake)
	ring, _ := StageRingKey(f.Entries(), staged)
	next := f
	_ = next.SetEntries(ring)
	if err := ReplaceWrappedKeyFile(path, f, next); err != nil {
		t.Fatal(err)
	}
	// A second writer that read the old file loses.
	other := f
	other.MigratedFromPlaintext = true
	if err := ReplaceWrappedKeyFile(path, f, other); !errors.Is(err, ErrKeyFileChanged) {
		t.Fatalf("stale writer = %v", err)
	}
	if back, _ := ReadWrappedKeyFile(path); len(back.Entries()) != 2 {
		t.Fatal("the stale writer undid the stage")
	}
	if err := ReplaceWrappedKeyFile(filepath.Join(t.TempDir(), "none"), f, next); err == nil {
		t.Fatal("replaced a missing file")
	}
}

// TestReplaceWrappedKeyFileSerializesWriters: two writers that read the
// same file race their compare-and-swaps; exactly one wins, every time.
// Without the lock across read, compare and rename both pass the compare
// and the second rename silently drops the first one's change.
func TestReplaceWrappedKeyFileSerializesWriters(t *testing.T) {
	ctx := context.Background()
	fake, _ := NewFakeKMS()
	prev, _ := WrapServerKey(ctx, fake, ringKey(t), ProviderAWSKMS, "")
	staged, _ := NewRingEntry(ctx, 1, fake)
	ring, _ := StageRingKey(prev.Entries(), staged)
	next := prev
	if err := next.SetEntries(ring); err != nil {
		t.Fatal(err)
	}
	rewrapped, err := RewrapRing(ctx, fake, prev)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.wrapped")
	for i := 0; i < 100; i++ {
		if err := WriteWrappedKeyFile(path, prev); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		result := make(chan error, 2)
		for _, n := range []WrappedKeyFile{next, rewrapped} {
			go func() { <-start; result <- ReplaceWrappedKeyFile(path, prev, n) }()
		}
		close(start)
		a, b := <-result, <-result
		if (a == nil) == (b == nil) {
			t.Fatalf("attempt %d: want one winner and one ErrKeyFileChanged, got %v and %v", i, a, b)
		}
		if a != nil && !errors.Is(a, ErrKeyFileChanged) || b != nil && !errors.Is(b, ErrKeyFileChanged) {
			t.Fatalf("attempt %d: loser = %v / %v", i, a, b)
		}
	}
}

// TestReplaceKeyRingFile: custody "file" rotation's ring save is the same
// compare-and-swap, including against a ring file that appeared after the
// rotation started from the legacy plaintext key.
func TestReplaceKeyRingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "k.ring")
	legacy := LegacyRingEntry(ringKey(t))
	one := KeyRingFile{Ring: []RingEntry{legacy}}
	if err := ReplaceKeyRingFile(path, nil, one); err != nil {
		t.Fatalf("first write = %v", err)
	}
	// A second rotation that also started from the legacy key loses.
	if err := ReplaceKeyRingFile(path, nil, one); !errors.Is(err, ErrKeyFileChanged) {
		t.Fatalf("stale legacy writer = %v", err)
	}
	read, err := ReadKeyRingFile(path)
	if err != nil {
		t.Fatal(err)
	}
	staged, _ := NewRingEntry(context.Background(), 1, nil)
	entries, _ := StageRingKey(read.Ring, staged)
	two := KeyRingFile{Ring: entries}
	if err := ReplaceKeyRingFile(path, &read, two); err != nil {
		t.Fatalf("stage = %v", err)
	}
	if err := ReplaceKeyRingFile(path, &read, one); !errors.Is(err, ErrKeyFileChanged) {
		t.Fatalf("stale writer = %v", err)
	}
	if back, _ := ReadKeyRingFile(path); len(back.Ring) != 2 {
		t.Fatal("the stale writer undid the stage")
	}
	if err := ReplaceKeyRingFile(path, &read, KeyRingFile{}); err == nil {
		t.Fatal("an empty ring written")
	}
	bad := filepath.Join(t.TempDir(), "bad.ring")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	if err := ReplaceKeyRingFile(bad, &read, two); err == nil || errors.Is(err, ErrKeyFileChanged) {
		t.Fatalf("unreadable ring = %v", err)
	}
	if err := ReplaceKeyRingFile("/dev/null/x/y", nil, one); err == nil {
		t.Fatal("unwritable path accepted")
	}

	// Concurrent writers from the same read: one wins.
	for i := 0; i < 50; i++ {
		if err := WriteKeyRingFile(path, read); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		result := make(chan error, 2)
		for range 2 {
			go func() { <-start; result <- ReplaceKeyRingFile(path, &read, two) }()
		}
		close(start)
		if a, b := <-result, <-result; (a == nil) == (b == nil) {
			t.Fatalf("attempt %d: want one winner, got %v and %v", i, a, b)
		}
	}
}
