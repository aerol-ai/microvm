package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestRemoveImageDeletesModuleFile(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")

	d := New(Config{ModulesDir: dir, RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(wasmmod.NewResolver(dir))

	if err := d.RemoveImage(context.Background(), modPath); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if _, err := os.Stat(modPath); !os.IsNotExist(err) {
		t.Fatalf("module file still exists after RemoveImage")
	}
}

func TestRemoveImageByDigest(t *testing.T) {
	dir := t.TempDir()
	digest := strings.Repeat("a", 64)
	path := filepath.Join(dir, digest)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := New(Config{ModulesDir: dir, RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(wasmmod.NewResolver(dir))

	if err := d.RemoveImage(context.Background(), digest); err != nil {
		t.Fatalf("RemoveImage digest: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("digest path still exists")
	}
}
