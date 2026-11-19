package daemon

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/network/workerfence"
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
	origBackend, origGOOS, origRange := newWorkerFenceBackend, workerFenceGOOS, localPortRangePath
	t.Cleanup(func() { newWorkerFenceBackend, workerFenceGOOS, localPortRangePath = origBackend, origGOOS, origRange })
	stub := &workerFenceStub{}
	newWorkerFenceBackend = func() workerfence.Backend { return stub }
	localPortRangePath = filepath.Join(t.TempDir(), "missing")
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
	if k := workerfence.Key(stub.rules); !strings.Contains(k, "uid 61000 drop 127.0.0.0/8") || !strings.Contains(k, "127.0.97.1/32 ports 1024-65535 (guest listeners)") {
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

// The exceptions are read from the node each sync.
func TestWorkerFenceSpec(t *testing.T) {
	dir := t.TempDir()
	origResolv, origRange := resolvConfPath, localPortRangePath
	t.Cleanup(func() { resolvConfPath, localPortRangePath = origResolv, origRange })
	resolvConfPath = filepath.Join(dir, "resolv.conf")
	localPortRangePath = filepath.Join(dir, "range")
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(resolvConfPath, "nameserver 127.0.0.53\nnameserver 10.0.0.2\n")
	write(localPortRangePath, "32768\t60999\n")
	opFile := filepath.Join(dir, "operator.yaml")
	write(opFile, "version: 1\nupstream_proxy:\n  url: http://127.0.0.1:3128\n")
	t.Setenv("SB_AUDIT_INGEST_PORT", "41000")

	spec := workerFenceSpec(config.Config{EgressOperatorFile: opFile}, worker.Confinement{UID: 61000, GID: 61000})
	rules, err := workerfence.Plan(spec)
	if err != nil {
		t.Fatal(err)
	}
	key := workerfence.Key(rules)
	for _, want := range []string{
		"accept tcp 127.0.97.1/32 ports 32768-60999 (guest listeners)",
		"accept tcp 127.0.0.1/32 port 41000 (audit ingest)",
		"accept udp 127.0.0.53/32 port 53 (name server)",
		"accept tcp 127.0.0.53/32 port 53 (name server)",
		"accept tcp 127.0.0.1/32 port 3128 (upstream proxy)",
	} {
		if !strings.Contains(key, want) {
			t.Errorf("plan lacks %q: %s", want, key)
		}
	}
	if strings.Contains(key, "10.0.0.2") {
		t.Errorf("a name server outside the fence got an exception: %s", key)
	}

	// Nothing readable: only the guest listeners, on every unprivileged port.
	resolvConfPath, localPortRangePath = filepath.Join(dir, "none"), filepath.Join(dir, "none")
	t.Setenv("SB_AUDIT_INGEST_PORT", "")
	spec = workerFenceSpec(config.Config{EgressOperatorFile: filepath.Join(dir, "none")}, worker.Confinement{UID: 61000, GID: 61000})
	if len(spec.Allow) != 1 || spec.Allow[0].PortLo != 1024 || spec.Allow[0].PortHi != 65535 {
		t.Fatalf("bare spec = %+v", spec.Allow)
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
