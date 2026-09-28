package jsbundle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
