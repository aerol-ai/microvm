//go:build integration

package isolate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func requireWorkerd(t *testing.T) string {
	t.Helper()
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}
	return workerd
}

func shortRunDir(t *testing.T) string {
	t.Helper()
	// macOS unix-socket sun_path is ~104 chars; keep the root short.
	dir, err := os.MkdirTemp("/tmp", "iso3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func phase3Driver(t *testing.T, workerd, runDir string) *Driver {
	t.Helper()
	cfg := Config{
		WorkerdPath:      workerd,
		RunDir:           runDir,
		GroupGranularity: GroupPerTenant,
		UseJail:          false,
		JailChrootBase:   filepath.Join(runDir, "jail"),
		JailUID:          1000,
		JailGID:          1000,
		IdleTTL:          0, // tests drive reaper explicitly
	}
	d := New(cfg, nil)
	d.SetBundleResolver(NewBundleResolver(jsbundle.NewResolver(nil)))
	d.SetHostSupervisor(NewHostSupervisor(cfg))
	return d
}

func writeFileBundle(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	src := `export default { async fetch(r) { return new Response(` + jsonQuote(body) + `); } };`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + p
}

// TestPhase3IngressPortGatewayEndToEnd: Create → EnsureHTTPListener → SyncAllowedPorts
// → HTTP GET the loopback mediator → isolate fetch handler responds. This is the
// expose_port upstream path without Caddy.
func TestPhase3IngressPortGatewayEndToEnd(t *testing.T) {
	workerd := requireWorkerd(t)
	runDir := shortRunDir(t)
	d := phase3Driver(t, workerd, runDir)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	bundleDir := t.TempDir()
	ref := writeFileBundle(t, bundleDir, "ing.js", "ingress-ok")
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: "ing", MemoryMB: 128,
	}, "sb-ing", "", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: "sb-ing"}) })

	addr, err := d.EnsureHTTPListener(ctx, "sb-ing", 8080)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	d.SyncAllowedPorts("sb-ing", []int{8080})

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET mediator: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ingress-ok" {
		t.Fatalf("mediator = %d %q, want 200 ingress-ok", resp.StatusCode, body)
	}

	// Disallowed port → 403 at the mediator (never reaches the isolate).
	d.SyncAllowedPorts("sb-ing", []int{9090})
	resp, err = http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed port status = %d, want 403", resp.StatusCode)
	}
}

// TestPhase3PerSandboxEgressEndToEnd proves the §4 redesign live against real
// workerd: egress is attributed PER SANDBOX by slot, so two sandboxes in the
// SAME tenant group get DIFFERENT policies enforced. An allow-listed sandbox
// reaches an allowed host and is refused a non-allowed one; a block-all sandbox
// in the same group is refused everything. Attribution is the slot socket — a
// forged x-sb-id on the outbound is irrelevant.
//
// A policy denial surfaces to the isolate as an upstream 403 from the egress
// proxy (body "status=403"); an allowed fetch is 200 (reachable) or 502/throw
// (allowed but unreachable), never 403 — so the allow assertion holds even where
// the runner has no outbound internet.
func TestPhase3PerSandboxEgressEndToEnd(t *testing.T) {
	workerd := requireWorkerd(t)
	runDir := shortRunDir(t)
	d := phase3Driver(t, workerd, runDir)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bundleDir := t.TempDir()
	src := `export default { async fetch(req) {
  const u = new URL(req.url);
  try {
    const r = await fetch(u.searchParams.get("t"));
    return new Response("status=" + r.status);
  } catch (e) {
    return new Response("throw=" + (e && e.message ? e.message : String(e)));
  }
}};`
	p := filepath.Join(bundleDir, "eg.js")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := "file://" + p

	// Two sandboxes in ONE tenant group with DIFFERENT egress policies.
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: "eg-tenant", MemoryMB: 128,
		NetworkAllowOut: []string{"example.com"},
	}, "sb-allow", "", nil); err != nil {
		t.Fatalf("create allow: %v", err)
	}
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: "sb-allow"}) })
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: "eg-tenant", MemoryMB: 128,
		NetworkBlockAll: true,
	}, "sb-block", "", nil); err != nil {
		t.Fatalf("create block: %v", err)
	}
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: "sb-block"}) })

	invoke := func(id, target string) string {
		u := "http://isolate/?t=" + url.QueryEscape(target)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := d.InvokeHTTP(ctx, id, req)
		if err != nil {
			t.Fatalf("invoke %s: %v", id, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b)
	}

	// Allowed sandbox → allowed host: PERMITTED (not a policy 403).
	if got := invoke("sb-allow", "https://example.com/"); strings.Contains(got, "status=403") {
		t.Fatalf("allow→example.com = %q, want it permitted (not a 403 policy denial)", got)
	}
	// Allowed sandbox → NON-allowed host: DENIED by its own allowlist.
	if got := invoke("sb-allow", "https://not-allowed.example/"); !strings.Contains(got, "status=403") {
		t.Fatalf("allow→not-allowed = %q, want status=403 (allowlist enforced)", got)
	}
	// Block-all sandbox in the SAME group → allowed host still DENIED (proving
	// per-sandbox differentiation, not a group-wide policy).
	if got := invoke("sb-block", "https://example.com/"); !strings.Contains(got, "status=403") {
		t.Fatalf("block→example.com = %q, want status=403 (block-all)", got)
	}
}

// TestPhase3IdleReaperReloadsOnInvoke: idle reap stops the group; the next
// Invoke re-acquires a group and re-pins the bundle (scale-to-zero path).
func TestPhase3IdleReaperReloadsOnInvoke(t *testing.T) {
	workerd := requireWorkerd(t)
	runDir := shortRunDir(t)
	d := phase3Driver(t, workerd, runDir)
	d.cfg.IdleTTL = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ref := writeFileBundle(t, t.TempDir(), "idle.js", "after-reap")
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: "idle", MemoryMB: 128,
	}, "sb-idle", "", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: "sb-idle"}) })

	// Force idle and reap.
	d.groupsMu.Lock()
	for _, g := range d.groups {
		g.lastUsed = time.Now().Add(-2 * time.Minute)
	}
	d.groupsMu.Unlock()
	d.reapIdleGroups(time.Minute)

	d.groupsMu.Lock()
	n := len(d.groups)
	d.groupsMu.Unlock()
	if n != 0 {
		t.Fatalf("groups after reap = %d, want 0", n)
	}

	// Next invoke must reload (spawn + re-pin) and serve.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://isolate/", nil)
	resp, err := d.InvokeHTTP(ctx, "sb-idle", req)
	if err != nil {
		t.Fatalf("invoke after reap: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "after-reap" {
		t.Fatalf("after-reap = %d %q", resp.StatusCode, body)
	}
}

// TestPhase3ExecInvokeHandler: toolbox exec maps to fetch-handler invoke.
func TestPhase3ExecInvokeHandler(t *testing.T) {
	workerd := requireWorkerd(t)
	runDir := shortRunDir(t)
	d := phase3Driver(t, workerd, runDir)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	ref := writeFileBundle(t, t.TempDir(), "exec.js", "exec-ok")
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: "exec", MemoryMB: 128,
	}, "sb-exec", "", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: "sb-exec"}) })

	body, _ := json.Marshal(models.ExecRequest{Command: "/"})
	req := httptest.NewRequest(http.MethodPost, "/toolbox/exec", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	d.ServeToolbox(ctx, "sb-exec", "", rr, req)
	if rr.Code != 200 {
		t.Fatalf("exec status = %d body %s", rr.Code, rr.Body.String())
	}
	var result models.ExecResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Stdout != "exec-ok" || result.ExitCode != 0 {
		t.Fatalf("exec result = %+v", result)
	}

	// Unsupported toolbox verb → 501.
	req = httptest.NewRequest(http.MethodGet, "/toolbox/files", nil)
	rr = httptest.NewRecorder()
	d.ServeToolbox(ctx, "sb-exec", "", rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("files status = %d, want 501", rr.Code)
	}
}
