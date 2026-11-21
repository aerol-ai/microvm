package auditlog

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWithExistingFileLock(t *testing.T) {
	dir := t.TempDir()
	ran := 0
	fn := func() error { ran++; return nil }
	if ok, err := WithExistingFileLock("", fn); ok || err == nil {
		t.Fatal("empty lock path accepted")
	}
	missing := filepath.Join(dir, "missing.lock")
	if ok, err := WithExistingFileLock(missing, fn); ok || err != nil || ran != 0 {
		t.Fatalf("missing lock = %v, %v (ran %d)", ok, err, ran)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a missing lock was made")
	}
	if ok, err := WithExistingFileLock(dir, fn); ok || err == nil {
		t.Fatal("a folder taken as a lock")
	}
	lock := filepath.Join(dir, LockFileName)
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := WithExistingFileLock(lock, fn); !ok || err != nil || ran != 1 {
		t.Fatalf("existing lock = %v, %v (ran %d)", ok, err, ran)
	}
	// Held by someone else (a worker): never waited for.
	holder, err := os.OpenFile(lock, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := lockExclusive(holder); err != nil {
		t.Fatal(err)
	}
	if ok, err := WithExistingFileLock(lock, fn); ok || !errors.Is(err, ErrLockBusy) || ran != 1 {
		t.Fatalf("held lock = %v, %v (ran %d)", ok, err, ran)
	}
	if err := unlock(holder); err != nil {
		t.Fatal(err)
	}
	if ok, err := WithExistingFileLock(lock, fn); !ok || err != nil || ran != 2 {
		t.Fatalf("released lock = %v, %v (ran %d)", ok, err, ran)
	}
	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(lock, link); err != nil {
		t.Fatal(err)
	}
	if ok, err := WithExistingFileLock(link, fn); ok || err == nil {
		t.Fatal("a linked lock was followed")
	}
}
