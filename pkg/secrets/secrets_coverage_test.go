package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKeyMkdirFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "nested", "key")
	if _, err := loadOrGenerateKey("", path); err == nil {
		t.Fatal("expected mkdir failure when parent path is a file")
	}
}

func TestLoadOrGenerateKeyRandFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh", "key")
	old := randReader
	randReader = errReader{}
	t.Cleanup(func() { randReader = old })
	if _, err := loadOrGenerateKey("", path); err == nil {
		t.Fatal("expected error when random source fails during key generation")
	}
}

func TestNewCipherLoadKeyFailure(t *testing.T) {
	if _, err := NewCipher("", "/no/such/parent/and/key"); err == nil {
		t.Fatal("expected error from loadOrGenerateKey failure")
	}
}
