package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

type workerFenceStub struct {
	mu      sync.Mutex
	applies int
	rules   []workerfence.Rule
	err     error
}

func (f *workerFenceStub) Apply(rules []workerfence.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	if f.err != nil {
		return f.err
	}
	f.rules = rules
	return nil
}

func (f *workerFenceStub) Check(rules []workerfence.Rule) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return workerfence.Key(f.rules) == workerfence.Key(rules), f.err
}

func (f *workerFenceStub) Remove() error { return nil }

// spawnThroughGate starts a worker that drops, as the driver would.
func spawnThroughGate() error {
	_, err := worker.Confine(worker.DefaultSpawner, worker.Confinement{UID: 61000, GID: 61000})(context.Background(), "/run/x.sock")
	return err
}

// The fence goes in when workers drop and the host firewall is on, before
// any worker starts; a dropped worker is refused while it is not in.
func TestWireWasmWorkerFence(t *testing.T) {
	t.Cleanup(func() { worker.SetConfineGate(nil) })
	origBackend, origGOOS := newWorkerFenceBackend, workerFenceGOOS
	t.Cleanup(func() { newWorkerFenceBackend, workerFenceGOOS = origBackend, origGOOS })
	stub := &workerFenceStub{}
	newWorkerFenceBackend = func() workerfence.Backend { return stub }
	drop := worker.Confinement{UID: 61000, GID: 61000}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// No drop, not Linux, or the host firewall off: no fence, no gate.
	workerFenceGOOS = "linux"
	if host := wireWasmWorkerFence(ctx, config.Config{EnableNetworkRules: true}, worker.Confinement{}, quietLogger()); host != "" || stub.applies != 0 {
		t.Fatalf("no drop: host=%q applies=%d", host, stub.applies)
	}
	if host := wireWasmWorkerFence(ctx, config.Config{}, drop, quietLogger()); host != "" || stub.applies != 0 || spawnThroughGate() != nil {
		t.Fatalf("firewall off: host=%q applies=%d", host, stub.applies)
	}
	workerFenceGOOS = "darwin"
	if host := wireWasmWorkerFence(ctx, config.Config{EnableNetworkRules: true}, drop, quietLogger()); host != "" {
		t.Fatalf("not linux: host=%q", host)
	}

	// On: installed at once, the driver binds listeners on the fence's
	// address, and workers start.
	workerFenceGOOS = "linux"
	host := wireWasmWorkerFence(ctx, config.Config{EnableNetworkRules: true}, drop, quietLogger())
	if host != workerfence.GuestListenHost || stub.applies != 1 || spawnThroughGate() != nil {
		t.Fatalf("on: host=%q applies=%d", host, stub.applies)
	}
	if k := workerfence.Key(stub.rules); !strings.Contains(k, "uid 61000 accept reply 127.0.97.1 -> 127.0.0.0/8") || !strings.Contains(k, "uid 61000 drop 127.0.0.0/8") ||
		!strings.Contains(k, "uid 61000 drop local") || strings.Contains(k, "accept tcp "+workerfence.GuestListenHost) {
		t.Fatalf("rules = %s", k)
	}

	// Enterprise mode always fences; an install the kernel refuses keeps
	// dropped workers from starting, and the next start retries it.
	stub2 := &workerFenceStub{err: errors.New("netlink: operation not permitted")}
	newWorkerFenceBackend = func() workerfence.Backend { return stub2 }
	if host := wireWasmWorkerFence(ctx, config.Config{EnterpriseMode: true}, drop, quietLogger()); host != workerfence.GuestListenHost {
		t.Fatalf("enterprise: host=%q", host)
	}
	if err := spawnThroughGate(); err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("dropped worker started without the fence: %v", err)
	}
	stub2.mu.Lock()
	stub2.err = nil
	stub2.mu.Unlock()
	if err := spawnThroughGate(); err != nil {
		t.Fatalf("the gate did not retry the install: %v", err)
	}
	if _, err := worker.Confine(worker.DefaultSpawner, drop)(worker.WithoutConfinement(context.Background()), "/run/x.sock"); err != nil {
		t.Fatalf("a root-only worker was asked: %v", err)
	}
}

// The exceptions, the floor and the node ports are read each sync.
func TestWorkerFenceSpec(t *testing.T) {
	dir := t.TempDir()
	origResolv := resolvConfPath
	t.Cleanup(func() { resolvConfPath = origResolv })
	resolvConfPath = filepath.Join(dir, "resolv.conf")
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(resolvConfPath, "nameserver 127.0.0.53\nnameserver 10.0.0.2\n")
	opFile := filepath.Join(dir, "operator.yaml")
	write(opFile, "version: 1\nupstream_proxy:\n  url: http://127.0.0.1:3128\ndeny_cidrs:\n  - 10.200.0.0/16\n")
	t.Setenv("SB_AUDIT_INGEST_PORT", "41000")
	prevPorts := egresspolicy.NodeAllowedPorts()
	t.Cleanup(func() { egresspolicy.SetNodeAllowedPorts(prevPorts) })
	egresspolicy.SetNodeAllowedPorts([]uint16{443})
	prevFloor := egresspolicy.FileFloor()
	t.Cleanup(func() { egresspolicy.SetFileFloor(prevFloor) })
	egresspolicy.SetFileFloor([]netip.Prefix{netip.MustParsePrefix("10.96.0.1/32")})

	spec := workerFenceSpec(config.Config{EgressOperatorFile: opFile}, worker.Confinement{UID: 61000, GID: 61000})
	rules, err := workerfence.Plan(spec)
	if err != nil {
		t.Fatal(err)
	}
	key := workerfence.Key(rules)
	for _, want := range []string{
		"accept tcp 127.0.0.1/32 port 41000 (audit ingest)",
		"accept udp 127.0.0.53/32 port 53 (name server)",
		"accept tcp 127.0.0.53/32 port 53 (name server)",
		// A name server off loopback may still be one of the node's own
		// addresses, which the fence now drops: it keeps its exception.
		"accept udp 10.0.0.2/32 port 53 (name server)",
		"accept tcp 127.0.0.1/32 port 3128 (upstream proxy)",
		"drop 10.200.0.0/16",  // the operator's deny_cidrs
		"drop 10.96.0.1/32",   // the floor file
		"drop 169.254.0.0/16", // link-local, the metadata endpoints in it
		"accept local tcp port 443 (node port)",
		"drop local",
	} {
		if !strings.Contains(key, want) {
			t.Errorf("plan lacks %q: %s", want, key)
		}
	}
	if strings.Contains(key, "accept tcp "+workerfence.GuestListenHost) {
		t.Errorf("guest listeners got an exception: %s", key)
	}

	// Nothing readable: no exceptions, the fixed floor still there.
	resolvConfPath = filepath.Join(dir, "none")
	t.Setenv("SB_AUDIT_INGEST_PORT", "")
	spec = workerFenceSpec(config.Config{EgressOperatorFile: filepath.Join(dir, "none")}, worker.Confinement{UID: 61000, GID: 61000})
	if len(spec.Allow) != 0 || !slices.Contains(spec.Floor, netip.MustParsePrefix("169.254.169.254/32")) {
		t.Fatalf("bare spec = %+v", spec)
	}
}

func TestUpstreamAllows(t *testing.T) {
	u := func(raw string) *operator.UpstreamProxy {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &operator.UpstreamProxy{URL: parsed}
	}
	if upstreamAllows(nil) != nil || upstreamAllows(&operator.UpstreamProxy{}) != nil {
		t.Fatal("no proxy gave exceptions")
	}
	if got := upstreamAllows(u("http://localhost")); len(got) != 2 || got[0].PortLo != 80 {
		t.Fatalf("localhost = %+v", got)
	}
	if got := upstreamAllows(u("https://[::1]")); len(got) != 1 || got[0].PortLo != 443 || got[0].Prefix.Bits() != 128 {
		t.Fatalf("[::1] = %+v", got)
	}
	if upstreamAllows(u("http://proxy.corp.internal:8080")) != nil {
		t.Fatal("a proxy named by a name the fence cannot follow gave exceptions")
	}
}

func TestLocalAddrs(t *testing.T) {
	orig := nodeInterfaceAddrs
	t.Cleanup(func() { nodeInterfaceAddrs = orig })
	nodeInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)}, &net.IPAddr{IP: net.ParseIP("10.0.0.9")}, &net.IPNet{IP: net.IP{1}}}, nil
	}
	if got := localAddrs(); len(got) != 1 || got[0] != netip.MustParsePrefix("10.0.0.5/24") {
		t.Fatalf("local = %v", got)
	}
	nodeInterfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("netlink") }
	if got := localAddrs(); got != nil {
		t.Fatalf("failed read = %v", got)
	}
}
