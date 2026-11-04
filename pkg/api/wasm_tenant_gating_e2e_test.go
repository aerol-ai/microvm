package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestWasmTenantGatingThroughTheServer (issue #537) is the end-to-end proof:
// a real avm_ runner token, minted and presented over HTTP, flows through the
// real auth middleware and permission gate into the real service + wasmmod
// resolver + wasm driver, with a real core-wasm module staged as the standard
// "python" module. It is the live single-node WASM path for the fix — a scoped
// tenant cannot read a host file via a module ref and cannot delete the
// operator's staged standard module, while the operator PAT keeps both.
func TestWasmTenantGatingThroughTheServer(t *testing.T) {
	// A real core-wasm module (magic + core layer) staged as the "python"
	// standard module. Registration/delete only resolve, validate and file-op;
	// they never instantiate it, so the minimal module is sufficient and the
	// test needs no external fixture (runs offline in CI).
	modulesDir := t.TempDir()
	wasmmod.WriteMinimalWasm(t, modulesDir, "python.wasm")
	staged := filepath.Join(modulesDir, "python.wasm")
	// A host file OUTSIDE ModulesDir a tenant must not be able to read.
	outsideDir := t.TempDir()
	wasmmod.WriteMinimalWasm(t, outsideDir, "other-tenant.wasm")
	secret := filepath.Join(outsideDir, "other-tenant.wasm")

	cfg := config.Config{
		IdentityEnabled:     true,
		EnableWasm:          true,
		WasmModulesDir:      modulesDir,
		WasmStandardModules: map[string]string{"python": "python.wasm"},
	}
	st := storeWith(t, "wasm537")
	svc := service.New(cfg, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	mr := wasmmod.NewModuleResolver(modulesDir, filepath.Join(t.TempDir(), "cache"))
	mr.Reserved = cfg.WasmStandardModules
	mr.CatalogueLookup = svc.ResolveOwnedWasmModule
	svc.SetWasmModuleResolver(mr)
	d := wasmruntime.New(wasmruntime.Config{ModulesDir: modulesDir, RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(mr)
	svc.SetWasmRuntime(d)

	set := &switchableTokens{}
	runner := mintToken(t, set, "ci-deploy", "payments", controlplane.RoleRunner, time.Now().Add(time.Hour))
	srv := NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, identity.NewTokenAuthenticator(set, discardLogger())))

	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	moduleID := func(rec interface{ Bytes() []byte }) string {
		var m struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rec.Bytes(), &m)
		return m.ID
	}

	// 1. Runner, absolute host path outside ModulesDir -> refused, file untouched.
	rec := do(t, srv, http.MethodPost, "/v1/wasm-modules", runner, `{"module_ref":"`+secret+`"}`, nil)
	if rec.Code < 400 {
		t.Fatalf("runner abs host-path create = %d %s; want refused", rec.Code, rec.Body.String())
	}
	if !exists(secret) {
		t.Fatal("runner abs host-path create deleted/moved the host file")
	}

	// 2. Runner, file:// URL -> refused.
	rec = do(t, srv, http.MethodPost, "/v1/wasm-modules", runner, `{"module_ref":"file://`+secret+`"}`, nil)
	if rec.Code < 400 {
		t.Fatalf("runner file:// create = %d %s; want refused", rec.Code, rec.Body.String())
	}

	// 3. Runner, reserved keyword -> allowed (a tenant keeps the standard module).
	rec = do(t, srv, http.MethodPost, "/v1/wasm-modules", runner, `{"module_ref":"python"}`, nil)
	if rec.Code >= 300 {
		t.Fatalf("runner keyword create = %d %s; want success", rec.Code, rec.Body.String())
	}
	runnerModID := moduleID(rec.Body)
	if runnerModID == "" {
		t.Fatalf("no module id in %s", rec.Body.String())
	}

	// 4. Runner deletes its keyword row -> row goes, the shared staged file stays.
	rec = do(t, srv, http.MethodDelete, "/v1/wasm-modules/"+runnerModID, runner, "", nil)
	if rec.Code >= 300 {
		t.Fatalf("runner delete = %d %s; want success", rec.Code, rec.Body.String())
	}
	if !exists(staged) {
		t.Fatalf("BUG #537: a team runner's delete removed the operator-staged %s", staged)
	}

	// 5. Operator PAT keeps the host-path escape: an absolute ref resolves.
	rec = do(t, srv, http.MethodPost, "/v1/wasm-modules", "pat-token", `{"id":"op-abs","module_ref":"`+secret+`"}`, nil)
	if rec.Code >= 300 {
		t.Fatalf("operator abs host-path create = %d %s; want success", rec.Code, rec.Body.String())
	}
}
