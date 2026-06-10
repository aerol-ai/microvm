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
	// Passing a non-existent directory makes os.CreateTemp fail
	err := atomicWriteFile("/nonexistent-directory-123456789/file.txt", errorFile{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAtomicWriteFileCopyError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile.txt")

	err := atomicWriteFile(path, errorFile{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected file to not exist, got statErr: %v", statErr)
	}
}
