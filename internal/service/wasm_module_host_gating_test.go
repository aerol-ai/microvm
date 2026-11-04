package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// wasmHostGatingHarness is a WASM-enabled service with a real module resolver
// and driver (not the stub), so RemoveImage actually touches files on disk and
// the host-path gate runs end to end. It stages a standard "python" module.
func wasmHostGatingHarness(t *testing.T) (*Service, string) {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	modulesDir := t.TempDir()
	wasmmod.WriteMinimalWasm(t, modulesDir, "python.wasm")
	mr := wasmmod.NewModuleResolver(modulesDir, filepath.Join(t.TempDir(), "cache"))
	mr.Reserved = map[string]string{"python": "python.wasm"}
	mr.CatalogueLookup = svc.ResolveOwnedWasmModule
	svc.SetWasmModuleResolver(mr)
	d := wasmruntime.New(wasmruntime.Config{ModulesDir: modulesDir, RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(mr)
	svc.SetWasmRuntime(d)
	return svc, modulesDir
}

func teamRunnerCtx() context.Context {
	return boundCtx(controlplane.PrincipalOIDC, controlplane.RoleRunner, "payments")
}

// SECURITY (issue #537): deleting a tenant's catalogue row for a shared
// operator-staged module must not remove the bytes. Before the fix, a team
// runner registered module_ref:"python", then deleting the row ran
// RemoveImage("python") and removed ModulesDir/python.wasm — breaking every
// tenant's Python sandboxes on the node. The tenant delete now drops the row
// alone; an operator delete still reclaims the bytes.
func TestDeleteWasmModule_TenantDeleteDoesNotRemoveSharedBytes(t *testing.T) {
	svc, modulesDir := wasmHostGatingHarness(t)
	runner := teamRunnerCtx()
	staged := filepath.Join(modulesDir, "python.wasm")

	mod, err := svc.CreateWasmModule(runner, models.CreateWasmModuleRequest{ModuleRef: "python"})
	if err != nil {
		t.Fatalf("team runner register keyword: %v", err)
	}
	if err := svc.DeleteWasmModule(runner, mod.ID); err != nil {
		t.Fatalf("team runner delete: %v", err)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("staged %s gone after a tenant delete: %v", staged, err)
	}
	// The keyword still resolves for everyone after the tenant delete.
	if _, err := svc.CreateWasmModule(operatorCtx(), models.CreateWasmModuleRequest{ModuleRef: "python"}); err != nil {
		t.Fatalf("operator keyword after tenant delete: %v", err)
	}
}

// An operator delete still reclaims bytes that nothing else references: the
// gate narrows byte removal to host-capable callers, it does not disable GC.
func TestDeleteWasmModule_OperatorStillReclaimsBytes(t *testing.T) {
	svc, modulesDir := wasmHostGatingHarness(t)
	extra := wasmmod.WriteMinimalWasm(t, modulesDir, "op-extra.wasm")

	mod, err := svc.CreateWasmModule(operatorCtx(), models.CreateWasmModuleRequest{ModuleRef: "op-extra.wasm"})
	if err != nil {
		t.Fatalf("operator register: %v", err)
	}
	if err := svc.DeleteWasmModule(operatorCtx(), mod.ID); err != nil {
		t.Fatalf("operator delete: %v", err)
	}
	if _, err := os.Stat(extra); !os.IsNotExist(err) {
		t.Fatalf("operator delete did not reclaim %s (err=%v)", extra, err)
	}
}

// SECURITY (issue #537): a scoped tenant cannot register a catalogue row from a
// raw host path (absolute or file://). Those refs now resolve to not-found, so
// the daemon never reads an arbitrary host file for a tenant. The reserved
// keyword still works.
func TestCreateWasmModule_TenantCannotResolveHostPath(t *testing.T) {
	svc, _ := wasmHostGatingHarness(t)
	runner := teamRunnerCtx()
	outside := wasmmod.WriteMinimalWasm(t, t.TempDir(), "other-tenant.wasm")

	for _, ref := range []string{outside, "file://" + outside, "/etc/hosts"} {
		if _, err := svc.CreateWasmModule(runner, models.CreateWasmModuleRequest{ModuleRef: ref}); !errors.Is(err, wasmmod.ErrModuleNotFound) {
			t.Fatalf("team runner host path %q: want ErrModuleNotFound, got %v", ref, err)
		}
	}
	// The keyword is still available to the tenant.
	if _, err := svc.CreateWasmModule(runner, models.CreateWasmModuleRequest{ModuleRef: "python"}); err != nil {
		t.Fatalf("team runner keyword: %v", err)
	}
	// An operator keeps host-path registration.
	if _, err := svc.CreateWasmModule(operatorCtx(), models.CreateWasmModuleRequest{ModuleRef: outside}); err != nil {
		t.Fatalf("operator host path: %v", err)
	}
}
