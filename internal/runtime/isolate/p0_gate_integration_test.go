//go:build integration

package isolate

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// P0 RELEASE GATE — hostile-isolate containment (plans/isolate-runtime.md
// §2.1 + §11). Executes end of Phase 3 once create, capability enforcement,
// and the egress proxy exist.
//
// Asserts:
//
//	(a) group-level resource caps hold (cgroup presence when UseJail; soft
//	    check — full OOM/CPU soak is Linux-only and best-effort here);
//	(b) undeclared capabilities are untouchable: egress fetch() to a
//	    non-allowlisted destination is refused at the host proxy;
//	(c) the driver survives the hostile traffic (subsequent Invoke still works);
//	(d) Destroy tears the offending group down (LoadedCount / group gone).
//
// No cross-tenant memory-safety claim (Spectre is untestable by CI).
func TestP0HostileIsolateContainment(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd binary not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	dir := t.TempDir()
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(dir, "bundles")})
	if err != nil {
		t.Fatal(err)
	}
	// Hostile bundle: spins briefly then tries an undeclared egress fetch.
	src := `export default { async fetch(req) {
  const url = new URL(req.url);
  if (url.pathname === "/spin") {
    const end = Date.now() + 50;
    while (Date.now() < end) {}
    return new Response("spun");
  }
  if (url.pathname === "/egress") {
    try {
      const r = await fetch("https://example.invalid/");
      return new Response("egress-ok:" + r.status);
    } catch (e) {
      return new Response("egress-err:" + (e && e.message ? e.message : e), { status: 502 });
    }
  }
  return new Response("ok");
}};`
	b, err := jsbundle.BuildFromSource("hostile.js", src, "")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := bundleStore.Put("p0", "hostile", b)
	if err != nil {
		t.Fatal(err)
	}

	d := New(Config{
		WorkerdPath:      workerd,
		RunDir:           filepath.Join(dir, "run"),
		GroupGranularity: GroupPerTenant,
		UseJail:          false, // CI hosts may lack cgroup; jail is covered by unit tests
		IdleTTL:          0,
	}, nil)
	d.SetBundleResolver(NewBundleResolver(jsbundle.NewResolver(bundleStore)))
	d.SetHostSupervisor(NewHostSupervisor(Config{
		WorkerdPath: workerd,
		RunDir:      filepath.Join(dir, "run"),
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Sibling "good" sandbox in the same tenant group — must keep serving after
	// the hostile one is destroyed (d).
	goodSrc := `export default { async fetch() { return new Response("good"); } };`
	good, err := jsbundle.BuildFromSource("good.js", goodSrc, "")
	if err != nil {
		t.Fatal(err)
	}
	goodDigest, err := bundleStore.Put("p0", "good", good)
	if err != nil {
		t.Fatal(err)
	}

	hostileState, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime:         models.RuntimeIsolate,
		ModuleRef:       "sha256:" + digest,
		TenantID:        "p0-gate-tenant",
		NetworkBlockAll: false,
		NetworkAllowOut: []string{"127.0.0.1/32"}, // example.invalid NOT allowed
	}, "sb-hostile", "", nil)
	if err != nil {
		t.Fatalf("create hostile: %v", err)
	}
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "sha256:" + goodDigest,
		TenantID:  "p0-gate-tenant",
	}, "sb-good", "", nil); err != nil {
		t.Fatalf("create good: %v", err)
	}

	// (b) Undeclared egress is refused — either the Go proxy 403s (surfaced as
	// the shim/EGRESS response) or the isolate sees a fetch failure. Never a
	// clean "egress-ok".
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://isolate/egress", nil)
	resp, err := d.InvokeHTTP(ctx, "sb-hostile", req)
	if err != nil {
		t.Fatalf("invoke egress: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "egress-ok:") {
		t.Fatalf("undeclared egress succeeded (body=%q) — capability boundary broken", body)
	}

	// (c) Driver still serves after hostile traffic.
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "http://isolate/spin", nil)
	resp, err = d.InvokeHTTP(ctx, "sb-hostile", req)
	if err != nil {
		t.Fatalf("invoke spin after egress: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("spin status = %d after hostile egress", resp.StatusCode)
	}

	// (d) Destroy the hostile sandbox; sibling keeps serving; last-member is
	// not yet (good remains), so the group stays up.
	if err := d.Destroy(ctx, &models.Sandbox{ID: hostileState.SandboxID}); err != nil {
		t.Fatalf("destroy hostile: %v", err)
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "http://isolate/", nil)
	resp, err = d.InvokeHTTP(ctx, "sb-good", req)
	if err != nil {
		t.Fatalf("sibling invoke after hostile destroy: %v", err)
	}
	sibBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(sibBody) != "good" {
		t.Fatalf("sibling = %d %q, want 200 good", resp.StatusCode, sibBody)
	}

	// Tear the last member; group must be gone.
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-good"}); err != nil {
		t.Fatalf("destroy good: %v", err)
	}
	d.groupsMu.Lock()
	_, still := d.groups["p0-gate-tenant"]
	d.groupsMu.Unlock()
	if still {
		t.Fatal("group still in router after last-member destroy")
	}

	// (a) Soft check: jail profile invariants are unit-tested; when UseJail is
	// on in production the cgroup name is deterministic. Here we assert the
	// jail builder still produces a non-root, path-safe spec for the tenant.
	spec, err := BuildJailSpec(Config{
		UseJail: true, JailChrootBase: "/srv/isolate-jail",
		JailUID: 1000, JailGID: 1000,
	}, "p0-gate-tenant", 1, 256)
	if err != nil {
		t.Fatalf("jail spec: %v", err)
	}
	if spec.UID != 1000 || spec.GID != 1000 || !strings.Contains(spec.CgroupName, "p0-gate-tenant") {
		t.Fatalf("jail spec = %+v", spec)
	}
}
