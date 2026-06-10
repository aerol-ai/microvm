package wasmmod

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeTestWasm(t *testing.T, dir, name string) string {
	t.Helper()
	return WriteMinimalWasm(t, dir, name)
}

func TestResolverAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	path := writeTestWasm(t, dir, "demo.wasm")
	r := NewResolver(dir)
	got, err := r.Resolve(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != path || got.Digest == "" || got.SizeBytes == 0 {
		t.Fatalf("unexpected resolve: %+v", got)
	}
}

func TestResolverRelativeUnderModulesDir(t *testing.T) {
	dir := t.TempDir()
	writeTestWasm(t, dir, "hello.wasm")
	r := NewResolver(dir)
	got, err := r.Resolve(context.Background(), "hello.wasm")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != filepath.Join(dir, "hello.wasm") {
		t.Fatalf("path = %q", got.Path)
	}
}

func TestValidateRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.wasm")
	if err := os.WriteFile(path, []byte("not wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(path); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestResolverEdgeCases(t *testing.T) {
	r := NewResolver("")
	_, err := r.Resolve(context.Background(), "")
	if err == nil {
		t.Fatal("expected err for empty ref")
	}

	_, err = r.Resolve(context.Background(), "file.wasm")
	if err == nil {
		t.Fatal("expected err for relative path with no modules dir")
	}

	dir := t.TempDir()
	path := writeTestWasm(t, dir, "demo.wasm")
	r = NewResolver(dir)
	got, err := r.Resolve(context.Background(), "file://"+path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != path {
		t.Fatalf("expected path %q, got %q", path, got.Path)
	}

	_ = WriteCheckpointWasm(t, dir, "cp.wasm")
}
