package wasmmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestDigestCache_SecondResolveSkipsHash(t *testing.T) {
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "mod.wasm")
	var hashCalls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		hashCalls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	r := NewResolver(dir)
	ctx := context.Background()
	if _, err := r.Resolve(ctx, path); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if _, err := r.Resolve(ctx, path); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := hashCalls.Load(); got != 1 {
		t.Fatalf("hash calls = %d, want 1", got)
	}
}

func TestDigestCache_ModeAlways(t *testing.T) {
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "mod.wasm")
	var hashCalls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		hashCalls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	r := NewResolver(dir)
	r.SetDigestMode(moduleDigestModeAlways)
	ctx := context.Background()
	if _, err := r.Resolve(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, path); err != nil {
		t.Fatal(err)
	}
	if got := hashCalls.Load(); got != 2 {
		t.Fatalf("hash calls = %d, want 2 in always mode", got)
	}
}

func TestDigestCache_InvalidatesOnFileChange(t *testing.T) {
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "mod.wasm")
	var hashCalls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		hashCalls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	r := NewResolver(dir)
	ctx := context.Background()
	rm1, err := r.Resolve(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = WriteCheckpointWasm(t, dir, "mod.wasm")
	rm2, err := r.Resolve(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if rm1.Digest == rm2.Digest {
		t.Fatalf("digest unchanged after file rewrite: %s", rm1.Digest)
	}
	if got := hashCalls.Load(); got != 2 {
		t.Fatalf("hash calls = %d, want 2 after rewrite", got)
	}
}

func TestDigestCache_FailureNotCached(t *testing.T) {
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "mod.wasm")
	var hashCalls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		hashCalls.Add(1)
		return "", 0, fmt.Errorf("hash failed")
	}
	t.Cleanup(func() { fileDigestHasher = old })

	r := NewResolver(dir)
	ctx := context.Background()
	if _, err := r.Resolve(ctx, path); err == nil {
		t.Fatal("expected resolve error")
	}
	if _, err := r.Resolve(ctx, path); err == nil {
		t.Fatal("expected resolve error on retry")
	}
	if got := hashCalls.Load(); got != 2 {
		t.Fatalf("hash calls = %d, want 2 (failure not cached)", got)
	}
}

func TestDigestCache_DropOnPath(t *testing.T) {
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "mod.wasm")
	var hashCalls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		hashCalls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	r := NewResolver(dir)
	ctx := context.Background()
	if _, err := r.Resolve(ctx, path); err != nil {
		t.Fatal(err)
	}
	r.InvalidateDigestCache(path)
	if _, err := r.Resolve(ctx, path); err != nil {
		t.Fatal(err)
	}
	if got := hashCalls.Load(); got != 2 {
		t.Fatalf("hash calls = %d, want 2 after invalidate", got)
	}
	_ = filepath.Base(path)
	_ = os.ErrNotExist
}
