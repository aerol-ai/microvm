package mounts

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestUnmountTreeSkipsNonDirEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	unmountTree(logger, root)
}
