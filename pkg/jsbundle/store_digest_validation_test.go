package jsbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A digest is the content-address key and a path component in blobPath, so the
// store must refuse any non-hex digest before it reaches the filesystem. This
// plants a real blob OUTSIDE the blobs/ dir and proves a traversal digest that
// would resolve to it is rejected rather than read — the guard, not a missing
// file, is what stops it.
func TestStoreRejectsTraversalDigest(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(StoreConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}

	// blobPath(d) = <dir>/blobs/<d>.json, so digest "../pwned" resolves to
	// <dir>/pwned.json. Plant a valid bundle there; an unguarded GetByDigest
	// would parse and return it.
	planted := &Bundle{CompatibilityDate: "2026-01-01", MainModule: "main.js", Modules: map[string]string{"main.js": "export default 'pwned'"}}
	raw, err := json.Marshal(planted)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pwned.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if b, err := s.GetByDigest("../pwned"); err == nil {
		t.Fatalf("traversal digest read a file outside blobs/: got %+v", b)
	}

	// A selection of other non-hex keys must also be refused outright.
	for _, d := range []string{"..", "a/b", strings.Repeat("g", 64), "sha256:" + strings.Repeat("a", 64), ""} {
		if _, err := s.GetByDigest(d); err == nil {
			t.Errorf("GetByDigest(%q) = nil error, want rejection", d)
		}
		if err := s.Delete("", d); err == nil {
			t.Errorf("Delete(%q) = nil error, want rejection", d)
		}
	}
}

// A real 64-hex digest still round-trips (the guard doesn't break the happy path).
func TestStoreAcceptsHexDigest(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(StoreConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{CompatibilityDate: "2026-01-01", MainModule: "main.js", Modules: map[string]string{"main.js": "export default {}"}}
	digest, err := s.Put("", "demo", b)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !isHex64(digest) {
		t.Fatalf("Put returned a non-hex digest: %q", digest)
	}
	got, err := s.GetByDigest(digest)
	if err != nil {
		t.Fatalf("GetByDigest(valid) = %v", err)
	}
	if got.MainModule != "main.js" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if !strings.HasPrefix(s.blobPath(digest), filepath.Clean(dir)) {
		t.Fatalf("blobPath escaped store dir: %s", s.blobPath(digest))
	}
}
