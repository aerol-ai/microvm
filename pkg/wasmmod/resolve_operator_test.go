package wasmmod

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Operator marks what a trusted step may compile for every owner: only a
// file the operator staged directly in the modules dir, found by a reserved
// keyword or a host path. A checkpoint under the modules dir holds bytes a
// worker wrote, and the pull cache and catalogue hold tenants' modules.
func TestResolvedModuleOperator(t *testing.T) {
	modules := t.TempDir()
	mr := NewModuleResolver(modules, filepath.Join(modules, "cache"))
	WriteMinimalWasm(t, modules, "python.wasm")
	checkpoint := filepath.Join(modules, "sb-1", "mem.snap")
	if err := os.MkdirAll(checkpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	snap := WriteMinimalWasm(t, checkpoint, "mem")
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pulled := WriteMinimalWasm(t, mr.CacheDir, "x.wasm")
	outside := WriteMinimalWasm(t, t.TempDir(), "op.wasm")
	mr.Reserved = map[string]string{"python": "python.wasm", "nested": "sb-1/mem.snap/mem"}
	mr.CatalogueLookup = func(_ context.Context, ref string) (string, string, bool) {
		if ref == "byo" {
			return filepath.Join(modules, "python.wasm"), "d", true
		}
		return "", "", false
	}

	for _, tc := range []struct {
		ref  string
		want bool
	}{
		{"python", true},
		{"python.wasm", true},
		{filepath.Join(modules, "python.wasm"), true},
		{"file://" + filepath.Join(modules, "python.wasm"), true},
		{"nested", false},
		{"sb-1/mem.snap/mem", false},
		{snap, false},
		{pulled, false},
		{outside, false},
		{"byo", false},
	} {
		got, err := mr.Resolve(context.Background(), tc.ref)
		if err != nil {
			t.Fatalf("%s: %v", tc.ref, err)
		}
		if got.Operator != tc.want {
			t.Errorf("%s: Operator = %v, want %v", tc.ref, got.Operator, tc.want)
		}
	}

	// A pull cache that is the modules dir itself holds tenants' modules.
	same := NewModuleResolver(modules, modules)
	if got, err := same.Resolve(context.Background(), "python.wasm"); err != nil || got.Operator {
		t.Fatalf("modules dir as the pull cache: %+v, %v", got, err)
	}
	var none *ModuleResolver
	if none.inModulesDir(filepath.Join(modules, "python.wasm")) || NewModuleResolver("", "").inModulesDir("/m/x.wasm") || mr.inModulesDir("") {
		t.Fatal("no modules dir, or no path, counted as the operator's")
	}
}
