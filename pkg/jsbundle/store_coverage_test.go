package jsbundle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
