package isolate

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

const testWorker = `export default { async fetch(req) { return new Response("hi"); } };`

func testBundle(t *testing.T) *jsbundle.Bundle {
	t.Helper()
	b, err := jsbundle.BuildFromSource("m.js", testWorker, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shortRunDir returns a run dir under /tmp (short) rather than t.TempDir(),
// which on macOS produces paths that blow past the ~104-char unix-socket
// sun_path limit. Cleaned up on test end.
func shortRunDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "iso")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if len(filepath.Join(dir, hostSocketName)) > 100 {
		t.Skipf("socket path too long for this env: %s", dir)
	}
	return dir
}

func TestCapnpConfigContents(t *testing.T) {
	cfg := capnpConfig("/run/control.sock", "/run/host.sock", "/run/egress.sock", "acme")
	for _, want := range []string{
		`address = "unix:/run/control.sock"`,
		`external = (address = "unix:/run/host.sock"`,
		`external = (address = "unix:/run/egress.sock"`,
		`workerLoader = (id = "acme")`,
		`(name = "HOST", service = "host")`,
		`(name = "EGRESS", service = "egress")`,
		`compatibilityFlags = ["experimental"]`,
		`embed "controller.js"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}
}

func TestValidateLoaderID(t *testing.T) {
	ok := []string{"acme", "default", "a-b_c.d", "T3nant0"}
	bad := []string{"", "a/b", "a b", `a"b`, "a\nb", "..", "a;b"}
	for _, k := range ok {
		if err := validateLoaderID(k); err != nil {
			t.Errorf("validateLoaderID(%q) = %v, want ok", k, err)
		}
	}
	for _, k := range bad {
		if err := validateLoaderID(k); err == nil {
			t.Errorf("validateLoaderID(%q) = nil, want error", k)
		}
	}
}

func TestNewHostValidation(t *testing.T) {
	if _, err := NewHost(HostConfig{GroupKey: "acme", RunDir: "/x"}); err == nil {
		t.Fatal("want error for missing workerd path")
	}
	if _, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "bad/key", RunDir: "/x"}); err == nil {
		t.Fatal("want error for invalid group key")
	}
	if _, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme"}); err == nil {
		t.Fatal("want error for missing run dir")
	}
	h, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if h.controlSock != filepath.Join("/x", controlSocketName) {
		t.Fatalf("control sock = %q", h.controlSock)
	}
}

func TestLoadUnloadCount(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: "/x"})
	if err := h.Load("", testBundle(t)); err == nil {
		t.Fatal("want error for empty id")
	}
	if err := h.Load("sb-1", &jsbundle.Bundle{}); err == nil {
		t.Fatal("want validation error for empty bundle")
	}
	if err := h.Load("sb-1", testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if err := h.Load("sb-2", testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if h.LoadedCount() != 2 {
		t.Fatalf("count = %d, want 2", h.LoadedCount())
	}
	// Re-load replaces, does not double-count.
	_ = h.Load("sb-1", testBundle(t))
	if h.LoadedCount() != 2 {
		t.Fatalf("count after re-load = %d, want 2", h.LoadedCount())
	}
	if n := h.Unload("sb-1"); n != 1 {
		t.Fatalf("unload → %d remaining, want 1", n)
	}
	if n := h.Unload("sb-2"); n != 0 {
		t.Fatalf("unload → %d remaining, want 0", n)
	}
}

// TestBundleServerServesPinnedBundle exercises the bundle-server handler in
// isolation (no workerd): pin a bundle, hit the host socket the way the
// controller's provider would, assert the wire JSON round-trips.
func TestBundleServerServesPinnedBundle(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t)})
	if err := h.startBundleServer(); err != nil {
		t.Fatal(err)
	}
	defer h.stopServers()
	_ = h.Load("sb-1", testBundle(t))

	client := unixHTTPClient(h.hostSock)
	// Hit for a pinned id.
	resp, err := client.Get("http://host/bundle/sb-1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var wire bundleWireJSON
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if wire.MainModule != "m.js" || wire.Modules["m.js"] != testWorker || wire.CompatibilityDate == "" {
		t.Fatalf("wire = %+v", wire)
	}

	// Unpinned id → 404, which the controller surfaces as a 502 load failure.
	miss, err := client.Get("http://host/bundle/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer miss.Body.Close()
	if miss.StatusCode != http.StatusNotFound {
		t.Fatalf("miss status = %d, want 404", miss.StatusCode)
	}
}

// TestEgressServerAttributedFailClosed asserts the Phase-3 egress boundary
// refuses unattributed traffic and sandboxes without a registered policy.
func TestEgressServerAttributedFailClosed(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t)})
	if err := h.startEgressServer(); err != nil {
		t.Fatal(err)
	}
	defer h.stopServers()
	client := unixHTTPClient(h.egressSock)

	// No x-sb-id → deny.
	resp, err := client.Get("http://egress/anything")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unattributed egress status = %d, want 403", resp.StatusCode)
	}

	// x-sb-id present but no policy registered → deny.
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("x-sb-id", "sb-1")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "no policy") {
		t.Fatalf("no-policy status/body = %d %q", resp.StatusCode, body)
	}

	// BlockAll policy → deny even with attribution.
	h.SetEgressPolicy("sb-1", EgressPolicy{BlockAll: true})
	req, _ = http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("x-sb-id", "sb-1")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("block-all status = %d, want 403", resp.StatusCode)
	}
}

// TestWriteConfigProducesFiles covers the offline half of Start: the generated
// controller module + capnp config land in the run dir with the group's
// sockets wired. (The workerd spawn itself is integration-only.)
func TestWriteConfigProducesFiles(t *testing.T) {
	dir := shortRunDir(t)
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: dir})
	if err := h.writeConfig(); err != nil {
		t.Fatal(err)
	}
	ctrl, err := os.ReadFile(filepath.Join(dir, controllerModuleName))
	if err != nil || !strings.Contains(string(ctrl), "x-sb-id") {
		t.Fatalf("controller.js = %q err=%v", ctrl, err)
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "config.capnp"))
	if err != nil || !strings.Contains(string(cfg), `workerLoader = (id = "acme")`) {
		t.Fatalf("config.capnp missing loader id: %q err=%v", cfg, err)
	}
	if !strings.Contains(string(cfg), h.hostSock) {
		t.Fatalf("config.capnp does not wire host sock %q", h.hostSock)
	}
}

// TestStopIdempotent covers Stop with no running process: it tears down servers
// (started here without workerd) and is safe to call twice.
func TestStopIdempotent(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t)})
	if err := h.startBundleServer(); err != nil {
		t.Fatal(err)
	}
	if err := h.startEgressServer(); err != nil {
		t.Fatal(err)
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("second Stop (idempotent): %v", err)
	}
	if _, err := os.Stat(h.hostSock); !os.IsNotExist(err) {
		t.Fatalf("host sock not removed after Stop: %v", err)
	}
}

func TestInvokeBeforeStartErrors(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t)})
	req, _ := http.NewRequest(http.MethodGet, "http://ctrl/", nil)
	if _, err := h.Invoke(context.Background(), "sb-1", req); err == nil {
		t.Fatal("Invoke before Start should error")
	}
}

// ensure the unix listener path is usable in the test env (guards a confusing
// failure mode where TempDir paths exceed the 104-char sun_path limit).
func TestUnixSocketPathFits(t *testing.T) {
	sock := filepath.Join(t.TempDir(), hostSocketName)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket path too long in this env: %v", err)
	}
	_ = ln.Close()
}
