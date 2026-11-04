//go:build integration

package suite

// Issue #537: with identity on, a scoped team token must not be able to reach
// the host through a WASM module ref. These cases drive the real avm_ runner
// token against a live single-node WASM daemon.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
)

// UC-295 — a scoped team token cannot register a WASM module from a raw host
// path (absolute or file://): the daemon never reads a host file on a tenant's
// behalf, and the error is the same whether the path exists or not (no host-
// file existence oracle). The reserved keyword still resolves (issue #537).
func TestIdentityWasmHostPathRefused(t *testing.T) {
	harness.Require(t, sc, "UC-295")
	runner := mintToken(t, "uc295", "runner", harness.TeamPayments)

	register := func(ref string) *harness.APIResponse {
		t.Helper()
		return statusAs(t, runner.API, http.MethodPost, "/v1/wasm-modules",
			models.CreateWasmModuleRequest{ModuleRef: ref})
	}

	// Every raw host-path form is refused. /etc/hosts and /etc/shadow are real
	// host files; the ModulesDir path is the operator's staged standard module,
	// which a tenant may reach only through the keyword, never by path.
	staged := "/var/lib/sandboxd/wasm/modules/" + defaultStagedWasmModule + ".wasm"
	for _, ref := range []string{
		"/etc/hosts",
		"/etc/shadow",
		"file:///etc/hosts",
		staged,
		"file://" + staged,
	} {
		if resp := register(ref); resp.Status/100 == 2 {
			t.Fatalf("team runner registered host-path ref %q (must be refused): %s", ref, resp)
		}
	}

	// No host-file existence oracle: a real host file and a missing one get the
	// same status for a scoped tenant.
	existing := register("/etc/hosts")
	missing := register("/etc/aerolvm-no-such-file-uc295.wasm")
	if existing.Status != missing.Status {
		t.Fatalf("host-file existence oracle: /etc/hosts = %d, missing path = %d (must be identical)", existing.Status, missing.Status)
	}

	// The reserved keyword still resolves for the tenant (positive control).
	resp := register(defaultStagedWasmModule)
	var mod models.WasmModule
	if resp.Status/100 != 2 || resp.JSON(&mod) != nil || mod.ID == "" {
		t.Fatalf("team runner registering the %q keyword = %s (must still work)", defaultStagedWasmModule, resp)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = runner.API.Do(cctx, http.MethodDelete, "/v1/wasm-modules/"+mod.ID, nil)
	})
}

// UC-296 — a scoped team token's module delete never removes a shared standard
// module. A runner registers the "python" keyword (its own catalogue row over
// the operator-staged bytes) and deletes it; without the #537 fix the delete
// re-resolves the keyword and removes the staged file, breaking Python for every
// tenant on the node. The fix reclaims bytes only for a host-capable caller, so
// the staged module survives: the operator can still register the keyword, which
// re-reads the staged file.
func TestIdentityWasmDeleteKeepsStandardModule(t *testing.T) {
	harness.Require(t, sc, "UC-296")
	runner := mintToken(t, "uc296", "runner", harness.TeamPayments)

	resp := statusAs(t, runner.API, http.MethodPost, "/v1/wasm-modules",
		models.CreateWasmModuleRequest{ModuleRef: defaultStagedWasmModule})
	var mod models.WasmModule
	if resp.Status/100 != 2 || resp.JSON(&mod) != nil || mod.ID == "" {
		t.Fatalf("runner register %q = %s", defaultStagedWasmModule, resp)
	}
	if resp := statusAs(t, runner.API, http.MethodDelete, "/v1/wasm-modules/"+mod.ID, nil); resp.Status/100 != 2 {
		t.Fatalf("runner delete its own row = %s", resp)
	}

	// The shared staged module survived: the operator registering the keyword
	// re-resolves and re-reads the staged file, which only succeeds if the
	// tenant's delete left it on disk.
	opResp := statusAs(t, operatorAPI(), http.MethodPost, "/v1/wasm-modules",
		models.CreateWasmModuleRequest{ModuleRef: defaultStagedWasmModule})
	var opMod models.WasmModule
	if opResp.Status/100 != 2 || opResp.JSON(&opMod) != nil {
		t.Fatalf("BUG #537: after a team runner's delete the operator can no longer register %q — the staged module was removed: %s", defaultStagedWasmModule, opResp)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = operatorAPI().Do(cctx, http.MethodDelete, "/v1/wasm-modules/"+opMod.ID, nil)
	})
}
