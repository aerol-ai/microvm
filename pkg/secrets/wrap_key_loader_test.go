package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func key32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func b64(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

func TestParseUpstreamWrapKeyRing_EmptyAndWhitespace(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n", ",,, , ,"} {
		ring := ParseUpstreamWrapKeyRing(raw)
		if len(ring.Keys) != 0 {
			t.Fatalf("%q: expected empty ring, got %d keys", raw, len(ring.Keys))
		}
	}
}

func TestParseUpstreamWrapKeyRing_SingleKey(t *testing.T) {
	ring := ParseUpstreamWrapKeyRing(b64(key32(0xaa)))
	if len(ring.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(ring.Keys))
	}
	if !bytes.Equal(ring.Keys[0].Bytes, key32(0xaa)) {
		t.Fatalf("key bytes mismatch")
	}
	// No explicit id → auto-assigned k0
	if ring.Keys[0].ID != "k0" {
		t.Fatalf("want id k0, got %q", ring.Keys[0].ID)
	}
}

func TestParseUpstreamWrapKeyRing_NamedAndRotated(t *testing.T) {
	raw := "new:" + b64(key32(0x11)) + ", old:" + b64(key32(0x22))
	ring := ParseUpstreamWrapKeyRing(raw)
	if len(ring.Keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(ring.Keys))
	}
	if ring.Keys[0].ID != "new" || ring.Keys[1].ID != "old" {
		t.Fatalf("ids: %q / %q", ring.Keys[0].ID, ring.Keys[1].ID)
	}
	// First entry is current.
	cur, ok := ring.Current()
	if !ok || cur.ID != "new" {
		t.Fatalf("Current() returned %+v ok=%v", cur, ok)
	}
}

func TestParseUpstreamWrapKeyRing_DropsBadEntries(t *testing.T) {
	// One valid + one short (16-byte) + one not-base64.
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 16))
	raw := b64(key32(0x55)) + ", " + short + ", !!! not base64 !!!"
	ring := ParseUpstreamWrapKeyRing(raw)
	if len(ring.Keys) != 1 {
		t.Fatalf("want 1 key surviving, got %d", len(ring.Keys))
	}
	if !bytes.Equal(ring.Keys[0].Bytes, key32(0x55)) {
		t.Fatalf("wrong key survived")
	}
}

func TestLoadUpstreamWrapKeyRing_MissingFile(t *testing.T) {
	_, err := LoadUpstreamWrapKeyRing(filepath.Join(t.TempDir(), "nope.key"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
}

func TestLoadUpstreamWrapKeyRing_EmptyPath(t *testing.T) {
	_, err := LoadUpstreamWrapKeyRing("")
	if err == nil {
		t.Fatalf("expected error for empty path")
	}
}

func TestLoadUpstreamWrapKeyRing_RejectsLooseMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrap.key")
	body := b64(key32(0xab))
	for _, mode := range []os.FileMode{0o600, 0o604, 0o640, 0o644, 0o444} {
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatalf("write: %v", err)
		}
		// Some umasks may drop bits — re-chmod to be exact.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		_, err := LoadUpstreamWrapKeyRing(path)
		if err == nil {
			t.Fatalf("mode %#o: expected refusal", mode)
		}
	}
}

func TestLoadUpstreamWrapKeyRing_AcceptsTightMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrap.key")
	if err := os.WriteFile(path, []byte(b64(key32(0xcd))), 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	ring, err := LoadUpstreamWrapKeyRing(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(ring.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(ring.Keys))
	}
}

func TestLoadUpstreamWrapKeyRing_NoUsableKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrap.key")
	// All entries malformed → empty ring → error.
	if err := os.WriteFile(path, []byte("not-base64,also-bad"), 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadUpstreamWrapKeyRing(path); err == nil {
		t.Fatalf("expected error for unparseable body")
	}
}

func TestCurrentOnNilRingIsSafe(t *testing.T) {
	var ring *UpstreamWrapKeyRing
	if _, ok := ring.Current(); ok {
		t.Fatalf("nil ring should not have a current key")
	}
	if _, ok := (&UpstreamWrapKeyRing{}).Current(); ok {
		t.Fatalf("empty ring should not have a current key")
	}
}
