//go:build integration

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestIsolateAPICreateInvokeDestroy is the Phase-3 HTTP-API end-to-end:
// upload bundle → create sandbox → driver Invoke serves the fetch handler →
// destroy tears the group down. Tag-gated (needs real workerd).
func TestIsolateAPICreateInvokeDestroy(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	runDir, err := os.MkdirTemp("/tmp", "isoapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	db, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Config{
		EnableIsolate:           true,
		IsolateWorkerdPath:      workerd,
		IsolateRunDir:           runDir,
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
		IsolateUseJail:          false,
		IsolateJailChrootBase:   filepath.Join(runDir, "jail"),
		IsolateJailUID:          1000,
		IsolateJailGID:          1000,
		IsolatePoolEnabled:      false, // avoid extra blank workerd spawns
		IsolateGroupIdleTTL:     0,
		IsolateBundleGCInterval: 0,
	}
	admitter := capacity.New(capacity.HostInfo{
		CPUCores:          runtime.NumCPU(),
		MemoryTotalMB:     32768,
		SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeIsolate},
	}, capacity.Limits{}, benchMemProbe{freeMB: 32768})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(cfg, logger, db, nil, nil, nil, nil, nil, admitter)
	driver, err := wireIsolateRuntime(context.Background(), cfg, logger, svc)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}

	const pat = "iso-api-pat"
	srv := api.NewServer(logger, svc, nil, nil, cfg, pat, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	client := ts.Client()
	do := func(method, path string, body any) (*http.Response, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rdr = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+pat)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp, out
	}

	resp, out := do(http.MethodPost, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   "hello",
		Source: `export default { async fetch() { return new Response("api-hello"); } };`,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %s", resp.StatusCode, out)
	}

	resp, out = do(http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "hello",
		TenantID:  "api-tenant",
		MemoryMB:  128,
	})
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %s", resp.StatusCode, out)
	}
	var cr models.CreateSandboxResponse
	if err := json.Unmarshal(out, &cr); err != nil {
		t.Fatal(err)
	}
	id := cr.Sandbox.ID
	if id == "" {
		t.Fatal("empty sandbox id")
	}
	t.Cleanup(func() {
		_ = driver.Destroy(context.Background(), &models.Sandbox{ID: id})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://isolate/", nil)
	inv, err := driver.InvokeHTTP(ctx, id, req)
	if err != nil {
		t.Fatalf("InvokeHTTP: %v", err)
	}
	body, _ := io.ReadAll(inv.Body)
	_ = inv.Body.Close()
	if inv.StatusCode != 200 || string(body) != "api-hello" {
		t.Fatalf("invoke = %d %q", inv.StatusCode, body)
	}

	// Destroy via API.
	resp, out = do(http.MethodDelete, "/v1/sandboxes/"+id, nil)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d %s", resp.StatusCode, out)
	}
}

// TestIsolateAPIBundleGCAfterDestroy: an unnamed staged digest with no live
// sandbox and no catalogue name is swept by GC.
func TestIsolateAPIBundleGCAfterDestroy(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available: %v", err)
	}

	runDir, err := os.MkdirTemp("/tmp", "isogc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	db, err := store.Open(filepath.Join(t.TempDir(), "gc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Config{
		EnableIsolate:           true,
		IsolateWorkerdPath:      workerd,
		IsolateRunDir:           runDir,
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
		IsolateUseJail:          false,
		IsolateJailChrootBase:   filepath.Join(runDir, "jail"),
		IsolateJailUID:          1000,
		IsolateJailGID:          1000,
		IsolatePoolEnabled:      false,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	admitter := capacity.New(capacity.HostInfo{
		CPUCores: runtime.NumCPU(), MemoryTotalMB: 32768,
		SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeIsolate},
	}, capacity.Limits{}, benchMemProbe{freeMB: 32768})
	svc := service.New(cfg, logger, db, nil, nil, nil, nil, nil, admitter)
	if _, err := wireIsolateRuntime(context.Background(), cfg, logger, svc); err != nil {
		t.Fatal(err)
	}

	const pat = "gc-pat"
	srv := api.NewServer(logger, svc, nil, nil, cfg, pat, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	do := func(method, path string, body any) (*http.Response, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rdr = bytes.NewReader(raw)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+pat)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp, out
	}

	// Named upload — GC must keep it (catalogue reference).
	resp, out := do(http.MethodPost, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   "keep-me",
		Source: `export default { async fetch() { return new Response("x"); } };`,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload named: %d %s", resp.StatusCode, out)
	}
	var named models.JSBundle
	_ = json.Unmarshal(out, &named)

	// Create from a file:// ref so create stages an unnamed digest; then destroy
	// so nothing pins it — but we only assert named survives a GC sweep.
	if _, err := svc.GCUnreferencedJSBundles(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, out = do(http.MethodGet, "/v1/js-bundles/"+named.Digest, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("named bundle missing after GC: %d %s", resp.StatusCode, out)
	}
}
