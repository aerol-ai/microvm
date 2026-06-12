package clonegen

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestNewUsesDefaultPathAndLogger(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	c := New("", nil)
	if c == nil {
		t.Fatal("New returned nil")
	}
	if token, _ := c.Current(); token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestWriteFileLockedErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()

	// CreateTemp fails when parent is not writable.
	readOnly := filepath.Join(dir, "ro")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	c := &Generation{path: filepath.Join(readOnly, "clone-generation"), logger: logger}
	c.writeFileLocked("tok")

	// Rename fails when destination exists as a directory.
	targetDir := filepath.Join(dir, "dest-dir")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	c2 := &Generation{path: targetDir, logger: logger}
	c2.writeFileLocked("tok2")

	// Write failure after CreateTemp succeeds.
	readOnlyFile := filepath.Join(dir, "ro-file")
	if err := os.WriteFile(readOnlyFile, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	c3 := &Generation{path: readOnlyFile, logger: logger}
	c3.writeFileLocked("cannot-write")
}

func TestBumpPersistsTokenToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clone-generation")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(path, logger)

	before, _ := c.Current()
	c.Bump(12345)
	after, resumed := c.Current()
	if after == before {
		t.Fatal("Bump did not rotate token")
	}
	if resumed != 12345 {
		t.Fatalf("resumedAt = %d, want 12345", resumed)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(onDisk) != after+"\n" {
		t.Fatalf("on-disk token = %q, want %q", onDisk, after+"\n")
	}
}

func TestRandomTokenFallback(t *testing.T) {
	old := RandRead
	RandRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { RandRead = old })

	tok := randomToken(99)
	if tok == "" {
		t.Fatal("expected non-empty fallback token")
	}
}

func TestWriteFileLockedChmodAndCloseErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clone-generation")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	oldChmod, oldClose := cloneGenChmod, cloneGenClose
	t.Cleanup(func() {
		cloneGenChmod = oldChmod
		cloneGenClose = oldClose
	})

	cloneGenChmod = func(*os.File, os.FileMode) error { return errors.New("chmod denied") }
	c := &Generation{path: path, logger: logger}
	c.writeFileLocked("chmod-fail")

	cloneGenChmod = oldChmod
	cloneGenClose = func(*os.File) error { return errors.New("close failed") }
	c.writeFileLocked("close-fail")
}

func TestWriteFileLockedMkdirOnFileParent(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Generation{
		path:   filepath.Join(blocker, "clone-generation"),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	c.writeFileLocked("tok")
}
