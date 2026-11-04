package toolhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type errorFile struct{}

func (e errorFile) Read(p []byte) (int, error) {
	return 0, errors.New("read error")
}

func (e errorFile) ReadAt(p []byte, off int64) (int, error) {
	return 0, errors.New("read error")
}

func (e errorFile) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (e errorFile) Close() error {
	return nil
}

func TestAtomicWriteFileCreateTempError(t *testing.T) {
	// A directory that does not exist inside the root fails the temp file.
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = atomicWriteFile(root, "nonexistent-directory-123456789/file.txt", errorFile{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAtomicWriteFileCopyError(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	err = atomicWriteFile(root, "testfile.txt", errorFile{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "testfile.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("expected file to not exist, got statErr: %v", statErr)
	}
}
