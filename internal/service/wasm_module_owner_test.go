package service

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A WASM catalogue row created by one tenant must not be listable, readable,
// usable or deletable by another tenant. Operator-published ("") rows stay
// readable by all. Regression for the no-owner-model bug (identity plan H1).
func TestWasmModuleCatalogue_OwnerScoping(t *testing.T) {
	dir := t.TempDir()
	modPath := filepath.Join(dir, "a.wasm")
	if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: dir}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: modPath, digest: "digest-a"})

	a, b := ownerScopedCtx("acct-A"), ownerScopedCtx("acct-B")
	ref := "oci://registry.example/acct-a/secret:v1"
	created, err := svc.CreateWasmModule(a, models.CreateWasmModuleRequest{ModuleRef: ref})
	if err != nil {
		t.Fatalf("A create: %v", err)
	}
	id := created.ID

	// B cannot list A's module.
	if mods, err := svc.ListWasmModules(b); err != nil || len(mods) != 0 {
		t.Fatalf("B list = %v (err %v), want empty", mods, err)
	}
	// B cannot read it by id (404, not a leak).
	if _, err := svc.GetWasmModule(b, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B get = %v, want ErrNotFound", err)
	}
	// B cannot delete it.
	if err := svc.DeleteWasmModule(b, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B delete = %v, want ErrNotFound", err)
	}
	// B cannot resolve it at create time (boot a sandbox from A's module id).
	if _, _, ok := svc.ResolveOwnedWasmModule(b, id); ok {
		t.Fatal("B resolved A's module id at create time")
	}
	// A still sees and resolves its own.
	if _, err := svc.GetWasmModule(a, id); err != nil {
		t.Fatalf("A get own: %v", err)
	}
	if _, _, ok := svc.ResolveOwnedWasmModule(a, id); !ok {
		t.Fatal("A cannot resolve its own module")
	}

	// An operator-published ("") module is readable by every tenant but a
	// tenant cannot delete it.
	now := created.CreatedAt
	if err := st.UpsertWasmModule(b, store.WasmModuleRecord{
		ID: "std-python", ModuleRef: "python", Status: "ready", ModulePath: modPath,
		Digest: "std", OwnerRef: "", CreatedAt: now, UpdatedAt: now, ReadyAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetWasmModule(b, "std-python"); err != nil {
		t.Fatalf("B get operator-published module: %v", err)
	}
	if err := svc.DeleteWasmModule(b, "std-python"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B delete operator-published module = %v, want refused (ErrNotFound)", err)
	}
	// Operator can delete it.
	if err := svc.DeleteWasmModule(operatorCtx(), "std-python"); err != nil {
		t.Fatalf("operator delete operator-published module: %v", err)
	}
}
