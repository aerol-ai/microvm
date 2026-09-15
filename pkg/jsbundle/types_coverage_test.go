package jsbundle

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleValidateEmptyModuleName(t *testing.T) {
	b := Bundle{
		MainModule:        "m.js",
		Modules:           map[string]string{"m.js": "x", "": "y"},
		CompatibilityDate: "2026-01-01",
	}
	if err := b.Validate(); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("err = %v, want ErrInvalidBundle", err)
	}
}

func TestPutValidateAndPersistErrors(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("t", "", &Bundle{}); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("invalid put err = %v", err)
	}

	// blobs/ not writable → WriteFile of the staged blob fails.
	s2, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	blobs := filepath.Join(s2.dir, "blobs")
	if err := os.Chmod(blobs, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blobs, 0o700) })
	bWrite, _ := BuildFromSource("main.js", "export default{};//blob-write-fail", "")
	if _, err := s2.Put("t", "", bWrite); err == nil || !strings.Contains(err.Error(), "write blob") {
		t.Fatalf("want write blob error, got %v", err)
	}

	// Store dir non-writable after blob exists → persistIndexLocked fails.
	s3, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildFromSource("main.js", "export default{};//persist-fail", "")
	// Pre-create the blob so Put skips the write and only hits persist.
	d, err := b.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s3.blobPath(d), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s3.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s3.dir, 0o700) })
	if _, err := s3.Put("t", "n", b); err == nil {
		t.Fatal("want persist error on read-only store dir")
	}
}
