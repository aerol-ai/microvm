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
	cfg := capnpConfig("/run/control.sock", "/run/host.sock",
		[]string{"/run/egress-0.sock", "/run/egress-1.sock"}, "/run/egress-deny.sock", "acme")
	for _, want := range []string{
		`address = "unix:/run/control.sock"`,
		`external = (address = "unix:/run/host.sock"`,
		`external = (address = "unix:/run/egress-deny.sock"`,
		`(name = "egress0", external = (address = "unix:/run/egress-0.sock"`,
		`(name = "egress1", external = (address = "unix:/run/egress-1.sock"`,
		`workerLoader = (id = "acme")`,
		`(name = "HOST", service = "host")`,
		`(name = "EGRESS_DENY", service = "egressDeny")`,
		`(name = "EGRESS_0", service = "egress0")`,
		`(name = "EGRESS_1", service = "egress1")`,
		`compatibilityFlags = ["experimental"]`,
		`embed "controller.js"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}
	// The old single shared "egress" service must be gone.
	if strings.Contains(cfg, `(name = "EGRESS", service = "egress")`) {
		t.Fatalf("config still wires the removed single EGRESS service:\n%s", cfg)
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

// TestEgressDenyServerAndSlotLifecycle covers the §4 slot model end to end
// (offline, no workerd): the always-on EGRESS_DENY service, slot assignment for
// allow-all sandboxes, no-slot for block-all, per-slot SSRF enforcement, pool
// exhaustion falling back to deny (never a shared slot), and Unload freeing a
// slot for reuse.
func TestEgressDenyServerAndSlotLifecycle(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t), EgressPoolSize: 2})
	if err := h.startEgressDenyServer(); err != nil {
		t.Fatal(err)
	}
	defer h.stopServers()

	// EGRESS_DENY always 403s — this is what block-all / no-slot sandboxes bind.
	deny := unixHTTPClient(h.egressDenySock)
	resp, err := deny.Get("http://egress/anything")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "no egress slot") {
		t.Fatalf("deny status/body = %d %q", resp.StatusCode, body)
	}

	// Block-all sandbox claims no slot (binds EGRESS_DENY).
	h.SetEgressPolicy("sb-block", EgressPolicy{BlockAll: true})
	if _, ok := h.slotByID["sb-block"]; ok {
		t.Fatal("block-all sandbox must not claim a slot")
	}

	// Allow-all sandbox claims slot 0 and binds its dedicated socket.
	h.SetEgressPolicy("sb-1", EgressPolicy{})
	slot, ok := h.slotByID["sb-1"]
	if !ok {
		t.Fatal("sb-1 got no slot")
	}
	if h.idBySlot[slot] != "sb-1" {
		t.Fatalf("idBySlot[%d] = %q, want sb-1", slot, h.idBySlot[slot])
	}
	if _, err := os.Stat(h.egressSocks[slot]); err != nil {
		t.Fatalf("slot socket not bound: %v", err)
	}

	// The slot socket still blocks SSRF even under an allow-all policy: the
	// socket attributes the request to sb-1, whose policy allows all HOSTS but
	// the IP-range guard refuses loopback/metadata.
	slotClient := unixHTTPClient(h.egressSocks[slot])
	resp, err = slotClient.Get("http://127.0.0.1:21212/v1/sandboxes")
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(sb), "blocked") {
		t.Fatalf("SSRF via slot = %d %q, want 403 blocked", resp.StatusCode, sb)
	}

	// Second allow-all sandbox gets a DISTINCT slot; the pool (size 2) is now full.
	h.SetEgressPolicy("sb-2", EgressPolicy{})
	if _, ok := h.slotByID["sb-2"]; !ok || h.slotByID["sb-2"] == slot {
		t.Fatalf("sb-2 slot = %v (ok=%v), want a distinct slot", h.slotByID["sb-2"], ok)
	}

	// Third sandbox: pool exhausted → no slot (deny-all fallback, logged) — it
	// must NOT share another sandbox's slot.
	h.SetEgressPolicy("sb-3", EgressPolicy{})
	if _, ok := h.slotByID["sb-3"]; ok {
		t.Fatal("sb-3 must not get a slot from an exhausted pool")
	}

	// Unload frees sb-1's slot and removes its socket; the slot is then reusable.
	sock1 := h.egressSocks[slot]
	h.Unload("sb-1")
	if _, ok := h.slotByID["sb-1"]; ok {
		t.Fatal("Unload did not release the slot")
	}
	if _, err := os.Stat(sock1); !os.IsNotExist(err) {
		t.Fatalf("slot socket not removed after Unload: %v", err)
	}
	h.SetEgressPolicy("sb-3", EgressPolicy{})
	if _, ok := h.slotByID["sb-3"]; !ok {
		t.Fatal("sb-3 should reclaim the freed slot")
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
	// The controller binds globalOutbound to the sandbox's egress slot service.
	if !strings.Contains(string(ctrl), `env["EGRESS_" + slot]`) || !strings.Contains(string(ctrl), "EGRESS_DENY") {
		t.Fatalf("controller.js missing slot-based egress binding: %q", ctrl)
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "config.capnp"))
	if err != nil || !strings.Contains(string(cfg), `workerLoader = (id = "acme")`) {
		t.Fatalf("config.capnp missing loader id: %q err=%v", cfg, err)
	}
	if !strings.Contains(string(cfg), h.hostSock) {
		t.Fatalf("config.capnp does not wire host sock %q", h.hostSock)
	}
	// The egress pool + deny service are declared (default pool size).
	if !strings.Contains(string(cfg), "EGRESS_DENY") || !strings.Contains(string(cfg), `(name = "EGRESS_0"`) {
		t.Fatalf("config.capnp missing egress pool/deny wiring: %q", cfg)
	}
}

// TestStopIdempotent covers Stop with no running process: it tears down servers
// (started here without workerd) and is safe to call twice.
func TestStopIdempotent(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t)})
	if err := h.startBundleServer(); err != nil {
		t.Fatal(err)
	}
	if err := h.startEgressDenyServer(); err != nil {
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
