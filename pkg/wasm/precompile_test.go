package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
)

func cacheEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The shared cache, end to end with wazero: a module compiled by the
// trusted step, made read-only and linked into an owner's cache, is read
// back by an engine using that cache (nothing new is written); a module the
// shared cache lacks is compiled and written into the owner's cache, so a
// read-only shared entry never fails a compile.
func TestPrecompileModuleSharesCompiledCode(t *testing.T) {
	stdio := wasmtestguest.Path(t, wasmtestguest.Stdio)
	shared, owner := t.TempDir(), t.TempDir()
	if err := PrecompileModule(context.Background(), shared, stdio); err != nil {
		t.Fatal(err)
	}
	// wazero keeps entries in a folder per version.
	versions := cacheEntries(t, shared)
	if len(versions) != 1 {
		t.Fatalf("shared cache = %v, want one version folder", versions)
	}
	vdir := versions[0]
	entries := cacheEntries(t, filepath.Join(shared, vdir))
	if len(entries) != 1 {
		t.Fatalf("shared entries = %v, want one", entries)
	}
	src := filepath.Join(shared, vdir, entries[0])
	if err := os.Chmod(src, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(owner, vdir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, filepath.Join(owner, vdir, entries[0])); err != nil {
		t.Fatal(err)
	}
	// Compiling it again is a read: nothing new appears.
	if err := PrecompileModule(context.Background(), shared, stdio); err != nil {
		t.Fatal(err)
	}
	SetCompileCacheDir(owner)
	t.Cleanup(func() { SetCompileCacheDir("") })
	eng, err := NewEngineFor(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(context.Background())
	if err := eng.LoadModule(context.Background(), stdio, LoadOptions{MemoryMB: 64}); err != nil {
		t.Fatalf("load through the shared entry: %v", err)
	}
	if got := cacheEntries(t, filepath.Join(owner, vdir)); len(got) != 1 {
		t.Fatalf("owner cache after a hit = %v, want only the shared link", got)
	}
	// A miss: another module compiles and lands in the owner's cache.
	other := filepath.Join(t.TempDir(), "other.wasm")
	if err := os.WriteFile(other, minimalWasm(), 0o600); err != nil {
		t.Fatal(err)
	}
	eng2, err := NewEngineFor(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer eng2.Close(context.Background())
	if err := eng2.LoadModule(context.Background(), other, LoadOptions{MemoryMB: 16}); err != nil {
		t.Fatalf("a miss next to a read-only entry failed: %v", err)
	}
	if got := cacheEntries(t, filepath.Join(owner, vdir)); len(got) != 2 {
		t.Fatalf("owner cache after a miss = %v, want the miss written", got)
	}

	if err := PrecompileModule(context.Background(), "", stdio); err == nil {
		t.Fatal("precompiled without a cache")
	}
	if err := PrecompileModule(context.Background(), shared, filepath.Join(shared, "missing.wasm")); err == nil {
		t.Fatal("precompiled a missing module")
	}
	bad := filepath.Join(t.TempDir(), "bad.wasm")
	if err := os.WriteFile(bad, []byte("not wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrecompileModule(context.Background(), shared, bad); err == nil {
		t.Fatal("precompiled garbage")
	}
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// minimalWasm is the smallest valid module: magic and version.
func minimalWasm() []byte { return []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} }
