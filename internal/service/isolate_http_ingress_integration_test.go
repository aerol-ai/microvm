//go:build integration

package service

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestIsolateHTTPIngressIntegration mirrors the WASM expose_port ingress test:
// ExposePort installs a Caddy route that dials the isolate PortGateway loopback
// mediator, and a GET to that mediator reaches the isolate fetch handler.
// Tag-gated (needs real workerd).
func TestIsolateHTTPIngressIntegration(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available at %s: %v", workerd, err)
	}

	runDir, err := os.MkdirTemp("/tmp", "isoing")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	rec, caddySrv, caddyClient := newRecordingHTTPRouteCaddy(t)
	defer caddySrv.Close()

	isoCfg := isolateruntime.Config{
		WorkerdPath:      workerd,
		RunDir:           runDir,
		GroupGranularity: isolateruntime.GroupPerTenant,
		UseJail:          false,
		JailChrootBase:   filepath.Join(runDir, "jail"),
		JailUID:          1000,
		JailGID:          1000,
	}
	driver := isolateruntime.New(isoCfg, nil)
	driver.SetBundleResolver(isolateruntime.NewBundleResolver(jsbundle.NewResolver(nil)))
	driver.SetHostSupervisor(isolateruntime.NewHostSupervisor(isoCfg))

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.CaddyAdminURL = caddySrv.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.HTTPClientTimeout = time.Second
	svc.caddy = caddyClient
	svc.SetIsolateRuntime(driver)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	bundlePath := filepath.Join(t.TempDir(), "h.js")
	if err := os.WriteFile(bundlePath, []byte(
		`export default { async fetch() { return new Response("expose-ok"); } };`,
	), 0o644); err != nil {
		t.Fatal(err)
	}

	created, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "file://" + bundlePath,
		TenantID:  "ingress",
		MemoryMB:  128,
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	id := created.Sandbox.ID
	t.Cleanup(func() { _ = driver.Destroy(context.Background(), &models.Sandbox{ID: id}) })

	// Ensure store row has loopback IP (create path sets it).
	sb, err := st.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sb.ContainerIP == "" {
		t.Fatal("expected ContainerIP=127.0.0.1 on isolate sandbox")
	}

	exp, err := svc.ExposePort(ctx, id, 8080, "http")
	if err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if exp.PublicURL == "" {
		t.Fatal("empty public URL")
	}

	wantDial, err := svc.isolateHTTPDial(ctx, id, 8080)
	if err != nil {
		t.Fatalf("isolateHTTPDial: %v", err)
	}
	routeID := caddy.PortRouteID(id, 8080)
	route, ok := rec.routes[routeID]
	if !ok {
		t.Fatalf("caddy route %q missing; have %v", routeID, rec.routes)
	}
	if dial := routeDial(t, route); dial != wantDial {
		t.Fatalf("route dial = %q, want %q", dial, wantDial)
	}

	// Hit the mediator directly (what Caddy would dial).
	resp, err := http.Get("http://" + wantDial + "/")
	if err != nil {
		t.Fatalf("GET mediator: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "expose-ok" {
		t.Fatalf("mediator = %d %q", resp.StatusCode, body)
	}
}
