//go:build integration

package isolate

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// P0 RELEASE GATE — hostile-isolate containment (plans/isolate-runtime.md
// §2.1 + §11). Specified in Phase 1 (this file), EXECUTES at the end of
// Phase 3, when create, capability enforcement, and the egress proxy all
// exist to be attacked.
//
// The gate: run a hostile isolate — (1) OOM allocator, (2) tight CPU loop,
// (3) attempted access outside granted capabilities — and assert:
//
//	(a) group-level resource caps hold: the jail's cgroup bounds the
//	    tenant's workerd process; sibling groups' latency is unaffected;
//	(b) undeclared capabilities are untouchable: an egress fetch() to a
//	    non-allowlisted destination is refused at the host proxy, and
//	    non-network grants (env/KV) not in the manifest are absent;
//	(c) sandboxd survives: the daemon serves API traffic throughout;
//	(d) the offending group is torn down and its members rehydrated per
//	    §2.1 teardown semantics (in-flight requests to co-resident
//	    sandboxes of that tenant get 503 + Retry-After; the group is
//	    recreated and ephemeral members come back blank).
//
// The gate makes NO cross-tenant memory-safety claim — Spectre between
// co-resident isolates is untestable by CI; the per-tenant OS-process
// boundary is the answer, and the docs say so.
//
// Placement: tag-gated CI job (`go test -tags=integration`, pinned workerd
// binary fetched in the job) — the wasm-integration / test-acme-e2e
// precedent. `make test` never runs this.
func TestP0HostileIsolateContainment(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd binary not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	d := New(Config{
		WorkerdPath:      workerd,
		RunDir:           t.TempDir(),
		GroupGranularity: GroupPerTenant,
		UseJail:          true,
		JailChrootBase:   t.TempDir(),
		JailUID:          1000,
		JailGID:          1000,
	}, nil)

	// Phase-3 shape: this create carries the hostile bundle; the assertions
	// (a)-(d) above attack the running group. Until the create path lands,
	// the driver rejects and the gate is pending by design.
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "testdata/hostile-bundle.js",
		TenantID:  "p0-gate-tenant",
	}, "sb-p0-gate", "", nil)
	if errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Skip("P0 gate pending: isolate create path not yet implemented (executes end of Phase 3, plans/isolate-runtime.md §11)")
	}

	// Ratchet: the moment the create path lands, this test FAILS rather than
	// silently passing — the release gate must be implemented before the
	// tier ships, and this failure is what enforces it.
	t.Fatalf("isolate create path has landed (err=%v) — implement the P0 hostile-isolate gate assertions (a)-(d) specified above before release", err)
}
