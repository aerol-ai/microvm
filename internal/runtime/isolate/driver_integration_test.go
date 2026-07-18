//go:build integration

package isolate

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDriverCreateEndToEnd is the Phase-2 proof at the driver level: the real
// jsbundle resolver + workerd supervisor, a file:// bundle, driver.Create
// spawns the group process and loads the bundle, and the loaded isolate serves
// a request through the group host. Tag-gated (needs a real workerd via
// SB_ISOLATE_WORKERD_PATH). Two sandboxes in one tenant share one process.
func TestDriverCreateEndToEnd(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}
	runDir, err := os.MkdirTemp("/tmp", "isodrv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	bundleDir := t.TempDir()
	writeBundle := func(name, body string) string {
		p := filepath.Join(bundleDir, name)
		src := `export default { async fetch(r) { return new Response(` + jsonQuote(body) + `); } };`
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return "file://" + p
	}

	cfg := Config{
		WorkerdPath:      workerd,
		RunDir:           runDir,
		GroupGranularity: GroupPerTenant,
		JailChrootBase:   "/srv/isolate-jail",
		JailUID:          1000,
		JailGID:          1000,
	}
	d := New(cfg, nil)
	d.SetBundleResolver(NewBundleResolver(jsbundle.NewResolver(nil))) // file:// needs no store
	d.SetHostSupervisor(NewHostSupervisor(cfg))

	ctx := context.Background()
	a, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: writeBundle("a.js", "alpha"), TenantID: "acme", MemoryMB: 128}, "sb-a", "", nil)
	if err != nil {
		t.Fatalf("create sb-a: %v", err)
	}
	if a.Status != models.SandboxStatusStarted {
		t.Fatalf("sb-a status = %s", a.Status)
	}
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: writeBundle("b.js", "beta"), TenantID: "acme", MemoryMB: 128}, "sb-b", "", nil); err != nil {
		t.Fatalf("create sb-b: %v", err)
	}

	// One process for both (per-tenant).
	d.groupsMu.Lock()
	ngroups := len(d.groups)
	var host GroupHost
	for _, g := range d.groups {
		host = g.host
	}
	d.groupsMu.Unlock()
	if ngroups != 1 {
		t.Fatalf("groups = %d, want 1 (per-tenant)", ngroups)
	}

	// Each isolate serves its own bundle through the group host.
	invoke := func(id string) string {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ctrl/", nil)
		resp, err := host.Invoke(ctx, id, req)
		if err != nil {
			t.Fatalf("invoke %s: %v", id, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := invoke("sb-a"); got != "alpha" {
		t.Fatalf("sb-a served %q, want alpha", got)
	}
	if got := invoke("sb-b"); got != "beta" {
		t.Fatalf("sb-b served %q, want beta", got)
	}

	// Destroy the last member tears the process down.
	_ = d.Destroy(ctx, &models.Sandbox{ID: "sb-a"})
	_ = d.Destroy(ctx, &models.Sandbox{ID: "sb-b"})
	d.groupsMu.Lock()
	remaining := len(d.groups)
	d.groupsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("groups after destroy = %d, want 0", remaining)
	}
}

func jsonQuote(s string) string { return `"` + s + `"` }
