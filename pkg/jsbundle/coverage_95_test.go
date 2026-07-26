package jsbundle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsFileRef(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"file:///tmp/w.js", true},
		{"/tmp/w.js", true},
		{"./x.mjs", true},
		{"Worker.ts", true},
		{"sha256:" + strings.Repeat("a", 64), false},
		{"uploaded-name", false},
		{"  file:///tmp/w.js  ", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsFileRef(tc.ref); got != tc.want {
			t.Fatalf("IsFileRef(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestAsDigestAndIsHex64Edges(t *testing.T) {
	// sha256: prefix with non-hex / wrong length must not look like a digest.
	if _, ok := asDigest("sha256:deadbeef"); ok {
		t.Fatal("short sha256: suffix must not be a digest")
	}
	bad := "sha256:" + strings.Repeat("g", 64)
	if _, ok := asDigest(bad); ok {
		t.Fatal("non-hex sha256: suffix must not be a digest")
	}
	// Uppercase hex is rejected (digests are lowercase).
	if isHex64(strings.Repeat("A", 64)) {
		t.Fatal("uppercase hex must fail isHex64")
	}
	if isHex64(strings.Repeat("a", 63) + "g") {
		t.Fatal("non-hex char must fail isHex64")
	}
}

func TestBuildFromFileReadPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.js")
	if err := os.WriteFile(path, []byte(sampleWorker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	_, err := BuildFromFile(path)
	if err == nil || errors.Is(err, ErrBundleNotFound) || errors.Is(err, ErrUnsupportedRef) {
		t.Fatalf("want a generic read error, got %v", err)
	}
}

func TestBuildFromFileEmptySourceInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.js")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildFromFile(path); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("empty file err = %v, want ErrInvalidBundle", err)
	}
}

func TestBuildFromSourceDefaultsAndValidate(t *testing.T) {
	b, err := BuildFromSource("", "export default {};", "")
	if err != nil {
		t.Fatal(err)
	}
	if b.MainModule != DefaultMainModule || b.CompatibilityDate != DefaultCompatibilityDate {
		t.Fatalf("defaults = %+v", b)
	}
	if _, err := BuildFromSource("main.js", "", ""); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("empty source err = %v, want ErrInvalidBundle", err)
	}
}

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

func TestNewStoreErrors(t *testing.T) {
	if _, err := NewStore(StoreConfig{}); err == nil {
		t.Fatal("empty dir must error")
	}
	// Parent path is a file → MkdirAll fails.
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(StoreConfig{Dir: filepath.Join(parent, "store")}); err == nil {
		t.Fatal("mkdir under file must error")
	}
}

func TestLoadIndexCorruptAndUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	idx := filepath.Join(dir, "index.json")
	if err := os.WriteFile(idx, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(StoreConfig{Dir: dir}); err == nil {
		t.Fatal("corrupt index must error")
	}

	dir2 := t.TempDir()
	s, err := NewStore(StoreConfig{Dir: dir2})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildFromSource("main.js", sampleWorker, "")
	if _, err := s.Put("t", "n", b); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.indexPath(), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.indexPath(), 0o600) })
	if _, err := NewStore(StoreConfig{Dir: dir2}); err == nil {
		t.Fatal("unreadable index must error")
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

func TestGetByDigestCorruptBlob(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	if err := os.WriteFile(s.blobPath(digest), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByDigest(digest); err == nil || !strings.Contains(err.Error(), "parse blob") {
		t.Fatalf("corrupt blob err = %v", err)
	}
}

func TestGetByDigestUnreadable(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("cd", 32)
	path := s.blobPath(digest)
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := s.GetByDigest(digest); err == nil || errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("want generic read error, got %v", err)
	}
}

func TestGCUnreferencedNoopAndBlobRemoveError(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.GCUnreferenced(nil)
	if err != nil || removed != nil {
		t.Fatalf("empty GC = %v err=%v, want nil,nil", removed, err)
	}

	b, _ := BuildFromSource("main.js", "export default{};//gc-err", "")
	d, err := s.Put("t", "", b)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the blob file with a non-empty directory so Remove fails
	// (IsNotExist is false).
	if err := os.Remove(s.blobPath(d)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.blobPath(d), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.blobPath(d), "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GCUnreferenced(nil); err == nil {
		t.Fatal("want Remove error when blob path is a non-empty dir")
	}
}

func TestGCUnreferencedClearsEmptyTenantAndPersistError(t *testing.T) {
	// Sole unnamed digest for a tenant → GC removes it and deletes the tenant key.
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildFromSource("main.js", "export default{};//gc-tenant", "")
	d, err := s.Put("solo", "", b)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.GCUnreferenced(nil)
	if err != nil || len(removed) != 1 || removed[0] != d {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	if _, ok := s.byTenant["solo"]; ok {
		t.Fatal("empty tenant key should be deleted from byTenant")
	}

	// Persist failure after a successful blob remove.
	s2, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := BuildFromSource("main.js", "export default{};//gc-persist", "")
	if _, err := s2.Put("t", "", b2); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s2.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s2.dir, 0o700) })
	if _, err := s2.GCUnreferenced(nil); err == nil {
		t.Fatal("want persist error after GC removals")
	}
}

func TestDeleteBlobRemoveError(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildFromSource("main.js", "export default{};//del-err", "")
	d, err := s.Put("t", "n", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.blobPath(d)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.blobPath(d), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.blobPath(d), "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("t", d); err == nil {
		t.Fatal("want Remove error when last-owner delete hits a non-empty dir blob")
	}
}

func TestResolverSha256BadHex(t *testing.T) {
	r := NewResolver(nil)
	// Not a digest (bad hex) → falls through to name lookup → ErrBundleNotFound.
	ref := "sha256:" + strings.Repeat("z", 64)
	if _, err := r.Resolve(context.Background(), "", ref); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("bad sha256 ref err = %v, want ErrBundleNotFound", err)
	}
}
