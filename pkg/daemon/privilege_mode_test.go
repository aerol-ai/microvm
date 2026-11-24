package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	versionapi "github.com/containerd/containerd/api/services/version/v1"
	cntrclient "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// The agent and the helper agree on where the helper listens.
func TestRootdSocketDefaultsAgree(t *testing.T) {
	got := []string{config.DefaultRootdSocket, rootclient.DefaultSocket, rootd.DefaultSocket}
	if slices.Compact(slices.Clone(got))[0] != got[0] || len(slices.Compact(slices.Clone(got))) != 1 {
		t.Fatalf("sandboxd, client and helper sockets differ: %v", got)
	}
}

func splitConfig() config.Config {
	return config.Config{PrivilegeMode: privmode.Split, ContainerEngine: models.ContainerEngineContainerd, ContainerdNativeNetnsPoolEnabled: true}
}

// wasmSplit is split mode with WASM on as the helper runs it: workers
// dropped, on wazero, sandboxd in the worker group, the resident host on.
func wasmSplit(c *config.Config) {
	c.EnableWasm, c.WasmWorkerDropPrivs, c.WasmWorkerUID, c.WasmWorkerGID, c.WasmResidentHostEnabled = true, true, 61000, 61000, true
}

func TestCheckPrivilegeMode(t *testing.T) {
	old := agentGroups
	agentGroups = func() ([]int, error) { return []int{20, 61000}, nil }
	t.Cleanup(func() { agentGroups = old })
	if err := checkPrivilegeMode(config.Config{PrivilegeMode: privmode.Single, ContainerEngine: models.ContainerEngineDocker, EnableNetworkRules: true}); err != nil {
		t.Fatalf("single mode: %v", err)
	}
	if err := checkPrivilegeMode(splitConfig()); err != nil {
		t.Fatalf("split mode with nothing the helper lacks: %v", err)
	}
	// M1 PR 5 and 5b: the host firewall, enterprise mode's fence and the
	// hostname gateway's host side are the helper's now.
	for _, set := range []func(*config.Config){
		func(c *config.Config) { c.EnableNetworkRules = true },
		func(c *config.Config) { c.EnterpriseMode = true },
		func(c *config.Config) { c.EgressFQDNEnabled = true },
		// Ingress proxy routing's host ports, and the rollback of a boot
		// that engaged it, are the helper's from PR 5b.
		func(c *config.Config) { c.IngressProxyRouting = true },
		func(c *config.Config) { c.DBPath = filepath.Join(engagedMarkerDir(t), "state.db") },
		// M1 PR 9: V8 isolate groups, jailed by the helper, and WASM
		// workers and resident hosts, started by it.
		func(c *config.Config) { c.EnableIsolate, c.IsolateUseJail = true, true },
		wasmSplit,
		func(c *config.Config) { wasmSplit(c); c.WasmEngine = "wazero" },
		// A warm pool the resident host makes moot is never wired.
		func(c *config.Config) { wasmSplit(c); c.WasmPoolEnabled = true },
		// M1 PR 15: the WASM warm pool's slot workers are the helper's.
		func(c *config.Config) { wasmSplit(c); c.WasmResidentHostEnabled, c.WasmPoolEnabled = false, true },
		// M1 PR 9b: Firecracker VMs, through the helper's jailer, on a
		// node whose network rules are off.
		func(c *config.Config) { c.EnableFirecracker, c.UseJailer = true, true },
		// M1 PR 14: and with them on, the guests' firewall is the helper's.
		func(c *config.Config) { c.EnableFirecracker, c.UseJailer, c.EnableNetworkRules = true, true, true },
		func(c *config.Config) { c.EnableFirecracker, c.UseJailer, c.EnterpriseMode = true, true, true },
	} {
		cfg := splitConfig()
		set(&cfg)
		if err := checkPrivilegeMode(cfg); err != nil {
			t.Fatalf("split mode refused what the helper does: %v", err)
		}
	}
	for _, tc := range []struct {
		name string
		set  func(*config.Config)
		want string
		gap  []privmode.Step
	}{
		{"the Docker engine", func(c *config.Config) { c.ContainerEngine = models.ContainerEngineDocker }, "SB_CONTAINER_ENGINE=containerd", nil},
		{"no netns pool", func(c *config.Config) { c.ContainerdNativeNetnsPoolEnabled = false }, "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", nil},
		{"the warm pool", func(c *config.Config) { c.ContainerdPoolEnabled = true }, "warm pool", []privmode.Step{privmode.StepWarmPool}},
		{"WASM workers kept root", func(c *config.Config) { wasmSplit(c); c.WasmWorkerDropPrivs = false }, "SB_WASM_WORKER_DROP_PRIVS", nil},
		{"WASM on wasmtime", func(c *config.Config) { wasmSplit(c); c.WasmEngine = "wasmtime" }, "SB_WASM_ENGINE=wasmtime", nil},
		{"WASM workers as sandboxd", func(c *config.Config) { wasmSplit(c); c.WasmWorkerUID = os.Getuid() }, "sandboxd's own uid", nil},
		{"sandboxd outside the worker group", func(c *config.Config) { wasmSplit(c); c.WasmWorkerGID = 4242 }, "member of the WASM worker group", nil},
		// The helper jails every group it runs: an unjailed one is single
		// mode only, for good.
		{"V8 isolates unjailed", func(c *config.Config) { c.EnableIsolate = true }, "SB_ISOLATE_USE_JAIL=true", nil},
		// The helper runs every VM through its jailer: an unjailed one is
		// single mode only.
		{"Firecracker unjailed", func(c *config.Config) { c.EnableFirecracker = true }, "SB_FIRECRACKER_USE_JAILER=true", nil},
		{"the warm VM pool", func(c *config.Config) {
			c.EnableFirecracker, c.UseJailer, c.FirecrackerVMMPoolEnabled = true, true, true
		},
			"warm VM pool", []privmode.Step{privmode.StepFirecrackerWarmPool}},
		{"gVisor moves", func(c *config.Config) { c.GvisorCheckpointMoves = true }, "gVisor checkpoint", []privmode.Step{privmode.StepMoves}},
		{"several at once, each named", func(c *config.Config) {
			c.GvisorCheckpointMoves, c.EnableFirecracker, c.UseJailer, c.FirecrackerVMMPoolEnabled = true, true, true, true
		}, "Firecracker", []privmode.Step{privmode.StepFirecrackerWarmPool, privmode.StepMoves}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := splitConfig()
			tc.set(&cfg)
			err := checkPrivilegeMode(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			var g *privmode.Gap
			if tc.gap == nil {
				if errors.As(err, &g) {
					t.Fatalf("a lasting need reads as a gap: %v", err)
				}
				return
			}
			if !errors.As(err, &g) || !slices.Equal(g.Steps, tc.gap) {
				t.Fatalf("gap %+v, want %v", g, tc.gap)
			}
		})
	}
}

// engagedMarkerDir is a data folder whose marker says the last boot
// engaged ingress proxy routing.
func engagedMarkerDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "state.db")}
	if err := writeBypassMarker(ingressRoutingMarkerPath(cfg), true); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMountsOffFor(t *testing.T) {
	if got := mountsOffFor(config.Config{}); got != "" {
		t.Fatalf("single mode on a VM: %q", got)
	}
	// Split mode mounts through the root helper (M1 PR 8): no refusal at
	// boot, and the pod checks of F13 do not apply (the helper mounts in
	// the runtime's own namespace).
	split := splitConfig()
	split.HostProcessCgroupParent = "/kubepods/pod1/sandboxes"
	if got := mountsOffFor(split); got != "" {
		t.Fatalf("split mode: %q", got)
	}
}

func TestNewRootHelper(t *testing.T) {
	if newRootHelper(config.Config{PrivilegeMode: privmode.Single}, nil) != nil {
		t.Fatal("single mode built a helper client")
	}
	cfg := splitConfig()
	cfg.RootdSocket = "/run/h/root.sock"
	c := newRootHelper(cfg, nil)
	if c == nil || c.Socket() != "/run/h/root.sock" {
		t.Fatalf("split mode client %v", c)
	}
	_ = c.Close()
	// PR 4 review: the network calls are bounded by the network timeout,
	// which the helper's own burst test and benchmark run with too (they
	// build their client with rootclient's defaults).
	got := rootHelperConfig(cfg)
	if got.Timeout != rootclient.DefaultTimeout || got.NetworkTimeout != rootclient.DefaultNetworkTimeout || got.NetworkTimeout < 30*time.Second {
		t.Fatalf("helper client bounds: call %v, network %v", got.Timeout, got.NetworkTimeout)
	}
}

// fakeHostNetwork answers EnsureHostNetwork from a list.
type fakeHostNetwork struct {
	answers []error
	subnet  string
	calls   int
}

func (f *fakeHostNetwork) EnsureHostNetwork(context.Context) (string, error) {
	f.calls++
	if len(f.answers) > 0 {
		err := f.answers[0]
		f.answers = f.answers[1:]
		if err != nil {
			return "", err
		}
	}
	return f.subnet, nil
}

func TestResolveSplitBridgeSubnet(t *testing.T) {
	origWait, origRetry := helperBootWait, helperBootRetry
	t.Cleanup(func() { helperBootWait, helperBootRetry = origWait, origRetry })
	helperBootWait, helperBootRetry = 200*time.Millisecond, time.Millisecond
	ctx := context.Background()
	down := fmt.Errorf("%w: no socket", rootclient.ErrUnavailable)

	f := &fakeHostNetwork{subnet: "10.88.0.0/16", answers: []error{down, down}}
	if got, err := resolveSplitBridgeSubnet(ctx, config.Config{}, f, testLogger()); err != nil || got != "10.88.0.0/16" || f.calls != 3 {
		t.Fatalf("a helper that comes up = %q, %v after %d calls", got, err, f.calls)
	}
	f = &fakeHostNetwork{subnet: "10.200.0.0/16"}
	if got, err := resolveSplitBridgeSubnet(ctx, config.Config{ContainerdBridgeSubnet: "10.200.0.0/16"}, f, testLogger()); err != nil || got != "10.200.0.0/16" {
		t.Fatalf("matching setting = %q, %v", got, err)
	}
	if _, err := resolveSplitBridgeSubnet(ctx, config.Config{ContainerdBridgeSubnet: "10.88.0.0/16"}, f, testLogger()); err == nil || !strings.Contains(err.Error(), "10.200.0.0/16") {
		t.Fatalf("a setting the helper's config disagrees with: %v", err)
	}
	refused := &rootclient.RefusedError{Err: status.Error(codes.PermissionDenied, "no")}
	f = &fakeHostNetwork{answers: []error{refused}}
	if _, err := resolveSplitBridgeSubnet(ctx, config.Config{}, f, testLogger()); err == nil || f.calls != 1 {
		t.Fatalf("an answer that is not a helper down is not waited out: %v after %d", err, f.calls)
	}
	f = &fakeHostNetwork{answers: slices.Repeat([]error{down}, 1000)}
	start := time.Now()
	if _, err := resolveSplitBridgeSubnet(ctx, config.Config{}, f, testLogger()); !errors.Is(err, rootclient.ErrUnavailable) {
		t.Fatalf("a helper that never comes = %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("waited %v; the bound is %v", d, helperBootWait)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	helperBootWait = time.Hour
	if _, err := resolveSplitBridgeSubnet(cctx, config.Config{}, &fakeHostNetwork{answers: []error{down}}, testLogger()); !errors.Is(err, context.Canceled) {
		t.Fatalf("a stop while waiting = %v", err)
	}
}

// memHelper is the helper's network calls in memory.
type memHelper struct {
	mu      sync.Mutex
	ns      map[string]string // name -> address
	removed []string
	err     error
	next    int
	// marked are the containers whose groups the driver asked to mark.
	marked []string
}

func newMemHelper() *memHelper { return &memHelper{ns: map[string]string{}} }

func (m *memHelper) RealizeNetns(_ context.Context, name string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", "", m.err
	}
	if ip, ok := m.ns[name]; ok {
		return "/run/netns/" + name, ip, nil
	}
	m.next++
	ip := fmt.Sprintf("10.88.0.%d", m.next+1)
	m.ns[name] = ip
	return "/run/netns/" + name, ip, nil
}

func (m *memHelper) RemoveNetns(_ context.Context, name, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed = append(m.removed, name+" "+ip)
	delete(m.ns, name)
	return m.err
}

func (m *memHelper) DisableNetnsIPv6(context.Context, string) error { return m.err }

func (m *memHelper) NetnsAddrs(_ context.Context, name string) (bool, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, nil, m.err
	}
	ip, ok := m.ns[name]
	if !ok {
		return false, nil, nil
	}
	return true, []string{ip}, nil
}

func TestHelperNetnsHost(t *testing.T) {
	ctx := context.Background()
	m := newMemHelper()
	h := newHelperNetnsHost(m, "10.88.0.0/16", testLogger())
	if _, _, err := h.Realize(ctx, netns.Slot{SlotID: "aerol-netns-0"}); err == nil {
		t.Fatal("a slot with no owner was realized")
	}
	path, ip, err := h.Realize(ctx, netns.Slot{SlotID: "aerol-netns-0", SandboxID: "aerol-netns-0"})
	if err != nil || path != "/run/netns/aerol-netns-0" || ip != "10.88.0.2" {
		t.Fatalf("Realize = %q %q %v", path, ip, err)
	}
	// A claimed slot keeps the name it was realized under.
	claimed := netns.Slot{SlotID: "aerol-netns-0", SandboxID: "sb-1", NetnsPath: path, ContainerIP: ip}
	if addrs, err := h.IPv4Addrs(ctx, claimed); err != nil || !slices.Equal(addrs, []string{ip}) {
		t.Fatalf("IPv4Addrs = %v %v", addrs, err)
	}
	if err := h.DisableIPv6(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if !h.exists(path) || h.exists("") || h.exists("/run/netns/never") {
		t.Fatal("exists answered wrong")
	}
	if err := h.Remove(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	// A recorded address outside the range is not sent: the helper would
	// refuse it, and a stale row is no security event.
	if err := h.Remove(ctx, netns.Slot{SlotID: "s", SandboxID: "sb-2", NetnsPath: "/run/netns/sb-2", ContainerIP: "172.17.0.4"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Remove(ctx, netns.Slot{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.removed, []string{"aerol-netns-0 10.88.0.2", "sb-2 "}) {
		t.Fatalf("removed %v", m.removed)
	}
	for _, err := range []error{
		h.DisableIPv6(ctx, netns.Slot{SandboxID: "x"}),
		func() error { _, err := h.IPv4Addrs(ctx, netns.Slot{SandboxID: "x"}); return err }(),
	} {
		if err == nil {
			t.Fatal("a slot with no path was asked about")
		}
	}
	// A helper that cannot answer keeps the slot at boot.
	m.err = rootclient.ErrUnavailable
	if !h.exists(path) {
		t.Fatal("a helper error reaped a slot")
	}
}

// TestHelperNetnsHostCleansUpAFailedBuild (PR 4 review): a build the agent
// gave up on may have left a namespace and a lease that nothing would name
// again; Realize removes them under the build's name, with a context of
// its own. A build the helper never ran is not followed by a removal.
func TestHelperNetnsHostCleansUpAFailedBuild(t *testing.T) {
	refused := &rootclient.RefusedError{Refusal: rootclient.Refusal{Call: "RealizeNetns", Reason: "not_sandbox_netns"}, Err: errors.New("no")}
	for _, c := range []struct {
		name    string
		err     error
		removed bool
	}{
		{"timed out", fmt.Errorf("%w: deadline exceeded", rootclient.ErrUnavailable), true},
		{"cancelled", context.Canceled, true},
		{"failed in the helper", errors.New("cni add: exit status 1"), true},
		{"refused", refused, false},
		{"too old", &rootclient.UnsupportedError{Feature: "RealizeNetns"}, false},
		{"busy", fmt.Errorf("%w: 64 running", rootclient.ErrBusy), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &failingRealize{err: c.err}
			h := newHelperNetnsHost(f, "10.88.0.0/16", testLogger())
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // the caller's own context has ended; the removal must not use it
			if _, _, err := h.Realize(ctx, netns.Slot{SlotID: "s-1", SandboxID: "sb-1"}); !errors.Is(err, c.err) && err != c.err {
				t.Fatalf("Realize = %v, want %v", err, c.err)
			}
			want := []string(nil)
			if c.removed {
				want = []string{"sb-1"}
			}
			if !slices.Equal(f.removed, want) {
				t.Fatalf("removed %v, want %v", f.removed, want)
			}
			if c.removed && f.removeCtxErr != nil {
				t.Fatalf("the removal ran on an ended context: %v", f.removeCtxErr)
			}
		})
	}
}

type failingRealize struct {
	memHelper
	err          error
	removed      []string
	removeCtxErr error
}

func (f *failingRealize) RealizeNetns(context.Context, string) (string, string, error) {
	return "", "", f.err
}

func (f *failingRealize) RemoveNetns(ctx context.Context, name, _ string) error {
	f.removed = append(f.removed, name)
	f.removeCtxErr = ctx.Err()
	return nil
}

// TestWireNetnsPoolThroughTheHelper: in split mode the pool is seeded and
// reconciled here, and every namespace step goes to the helper: nothing
// in process (no CNI config, no sysctl).
func TestWireNetnsPoolThroughTheHelper(t *testing.T) {
	origSysctls := ensureForwardingSysctls
	t.Cleanup(func() { ensureForwardingSysctls = origSysctls })
	ensureForwardingSysctls = func() error {
		t.Fatal("split mode set sysctls in process")
		return nil
	}
	st := openDaemonTestStore(t)
	cfg := splitConfig()
	cfg.ContainerdNetnsPoolSize, cfg.ContainerdNetnsPoolDepth = 3, 1
	cfg.ContainerdNetnsPoolRefillInterval = time.Hour
	cfg.ContainerdBridgeSubnet = "10.88.0.0/16"
	cfg.ContainerdCNIConfPath = filepath.Join(t.TempDir(), "never", "aerolvm.conflist")
	m := newMemHelper()
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pool, err := wireNetnsPool(ctx, cfg, testLogger(), st, driver, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Stop)
	if _, err := os.Stat(cfg.ContainerdCNIConfPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("split mode wrote the CNI config in process: %v", err)
	}
	// The refiller prewarms its depth through the helper.
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.ns)
		m.mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no warm slot was realized through the helper")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h := netns.NewRuntimeHandoff(pool.pool, pool.host)
	path, ip, err := h.Provision(ctx, "sb-1")
	if err != nil || !strings.HasPrefix(path, "/run/netns/") || ip == "" {
		t.Fatalf("Provision = %q %q %v", path, ip, err)
	}
	if err := h.Release(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	removed := slices.Clone(m.removed)
	m.mu.Unlock()
	if len(removed) != 1 || !strings.HasSuffix(removed[0], ip) {
		t.Fatalf("removed %v, want the claimed slot with %s", removed, ip)
	}
}

// TestWireContainerEngineSplit: the engine's wiring hands the driver the
// helper, and the pool goes through it.
func TestWireContainerEngineSplit(t *testing.T) {
	st := openDaemonTestStore(t)
	cfg := splitConfig()
	cfg.ContainerdNamespace, cfg.ContainerdSocket = "aerolvm", "/run/containerd/containerd.sock"
	cfg.ContainerdNetnsPoolSize, cfg.ContainerdNetnsPoolRefillInterval = 1, time.Hour
	cfg.ContainerdBridgeSubnet = "10.88.0.0/16"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	h := &engineHelper{memHelper: newMemHelper()}
	w, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if w.netns == nil {
		t.Fatal("no netns pool")
	}
	// The driver is in split mode, with the helper's container parts (M1
	// PR 7): a create names no gap, and goes on to its own checks (this
	// test's config has no toolbox binary).
	_, err = w.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine"}, "sb-1", "t", nil)
	if errors.Is(err, privmode.ErrGap) || err == nil || !strings.Contains(err.Error(), "SB_TOOLBOX_BINARY_PATH") {
		t.Fatalf("Create = %v, want past the gaps", err)
	}
	// F10's marks go to the helper (M1 PR 6), by container: the cgroup
	// tree below holds the parent alone, so a mark written in process
	// would fail.
	root := t.TempDir()
	for f, v := range map[string]string{"cgroup.controllers": "cpu memory pids", "sandboxes/cgroup.subtree_control": "cpu memory pids"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := cntr.CgroupRoot
	cntr.CgroupRoot = root
	t.Cleanup(func() { cntr.CgroupRoot = orig })
	cfg.ContainerdCgroupParent = "/sandboxes"
	w2, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w2.Stop)
	if err := w2.driver.MarkOOMVictim(ctx, "/sandboxes/sb-1"); err != nil {
		t.Fatal(err)
	}
	h.memHelper.mu.Lock()
	defer h.memHelper.mu.Unlock()
	if !slices.Equal(h.memHelper.marked, []string{"sb-1"}) {
		t.Fatalf("marked %v", h.memHelper.marked)
	}
}

// engineHelper is the whole helper the engine wiring takes.
type engineHelper struct {
	*memHelper
	*memFirewall
}

func (*engineHelper) Socket() string                      { return "/nonexistent/root.sock" }
func (*engineHelper) ContainerdOptions() []cntrclient.Opt { return nil }

// MarkSandboxCgroup records each container the driver asks the helper to
// mark.
func (h *engineHelper) MarkSandboxCgroup(_ context.Context, id string) error {
	h.memHelper.mu.Lock()
	defer h.memHelper.mu.Unlock()
	h.memHelper.marked = append(h.memHelper.marked, id)
	return nil
}

// splitHelper serves the helper's real server for a split-mode boot: its
// network in memory, containerd's version answered as the gate would.
func splitHelper(t *testing.T, sock string) *stubNetwork {
	t.Helper()
	base := filepath.Dir(filepath.Dir(sock))
	cfg := rootd.Config{
		Socket: sock, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()),
		Policy: rootpolicy.Policy{
			Namespace: "aerolvm", Snapshotter: "overlayfs", SnapshotterRoot: "/var/lib/containerd/snap",
			NetnsDir: "/run/netns", MovesDir: filepath.Join(base, "moves"), FIFODir: filepath.Join(base, "run", "fifo"),
			Limits: rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
		},
		Files: rootd.FileDirs{Hosts: filepath.Join(base, "state", "hosts"), Ready: filepath.Join(base, "run", "ready"),
			Runsc: filepath.Join(base, "state", "runsc"), AgentReady: filepath.Join(base, "agent", "ready")},
	}
	cfg.Policy.HelperFileRoots = []string{cfg.Files.Hosts, cfg.Files.Ready}
	cfg.Policy.RunscConfigPaths = []string{filepath.Join(cfg.Files.Runsc, "config.toml"), filepath.Join(cfg.Files.Runsc, "restore.toml")}
	net := &stubNetwork{ns: map[string]rootd.NetnsState{}}
	srv, err := rootd.New(cfg, rootd.Options{
		Peer:    egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
		Network: net,
		Containerd: func(_ any, ss grpc.ServerStream) error {
			if name, _ := grpc.MethodFromServerStream(ss); name != "/containerd.services.version.v1.Version/Version" {
				return status.Errorf(codes.Unavailable, "no containerd behind this test helper (%s)", name)
			}
			if err := ss.RecvMsg(&emptypb.Empty{}); err != nil {
				return err
			}
			return ss.SendMsg(&versionapi.VersionResponse{Version: "2.1.4", Revision: "test"})
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return net
}

// stubNetwork is rootd.NetworkHost in memory.
type stubNetwork struct {
	mu   sync.Mutex
	ns   map[string]rootd.NetnsState
	next int
}

func (s *stubNetwork) Subnet() netip.Prefix { return netip.MustParsePrefix("10.88.0.0/16") }
func (s *stubNetwork) EnsureHost() error    { return nil }
func (s *stubNetwork) Inspect(p string) (rootd.NetnsState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ns[p], nil
}
func (s *stubNetwork) Realize(_ context.Context, _, p string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	ip := fmt.Sprintf("10.88.1.%d", s.next)
	s.ns[p] = rootd.NetnsState{Exists: true, IPv4: []string{ip}}
	return ip, nil
}
func (s *stubNetwork) Remove(_ context.Context, _, p, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ns, p)
	return nil
}
func (s *stubNetwork) DisableIPv6(string) error { return nil }
func (s *stubNetwork) Bridge() string           { return "aerolvm0" }
func (s *stubNetwork) LeaseOf(name string) (netip.Addr, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for path, st := range s.ns {
		if filepath.Base(path) == name && len(st.IPv4) > 0 {
			return netip.MustParseAddr(st.IPv4[0]), true, nil
		}
	}
	return netip.Addr{}, false, nil
}

func (s *stubNetwork) Leaseholder(ip netip.Addr) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, st := range s.ns {
		if len(st.IPv4) > 0 && st.IPv4[0] == ip.String() {
			return filepath.Base(p), true, nil
		}
	}
	return "", false, nil
}

// TestRun_SplitMode: sandboxd boots in privilege mode split against the
// helper's own server: it waits for the helper, takes the sandboxes'
// range from it, and wires the containerd engine and its netns pool
// through it. Then it stops cleanly.
func TestRun_SplitMode(t *testing.T) {
	setBaseRunEnv(t)
	// /tmp: a socket's path must fit in sun_path (104 bytes on macOS).
	dir, err := os.MkdirTemp("/tmp", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sock", "root.sock")
	net := splitHelper(t, sock)
	origUID := rootHelperUID
	t.Cleanup(func() { rootHelperUID = origUID })
	rootHelperUID = uint32(os.Getuid()) // the test's own process stands in for root
	t.Setenv("SB_PRIVILEGE_MODE", "split")
	t.Setenv("SB_ROOTD_SOCKET", sock)
	t.Setenv("SB_CONTAINER_ENGINE", "containerd")
	t.Setenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", "true")
	t.Setenv("SB_CONTAINERD_NETNS_POOL_SIZE", "2")
	t.Setenv("SB_CONTAINERD_RUN_DIR", filepath.Join(dir, "ctr"))
	t.Setenv("SB_EGRESS_FQDN_ENABLED", "false")
	t.Setenv("SB_CONTAINERD_NETNS_POOL_DEPTH", "1")
	if err := runWithAutoCancel(t, 300*time.Millisecond, nil); err != nil {
		t.Fatalf("Run in split mode: %v", err)
	}
	net.mu.Lock()
	defer net.mu.Unlock()
	if net.next == 0 {
		t.Fatal("no namespace was built through the helper: the warm slot came from somewhere else")
	}
}

// TestRun_SplitModeRefusals: a split node this build cannot run stops at
// start, by name; one whose helper never comes stops within the bound.
func TestRun_SplitModeRefusals(t *testing.T) {
	t.Run("the Docker engine", func(t *testing.T) {
		setBaseRunEnv(t)
		t.Setenv("SB_PRIVILEGE_MODE", "split")
		if err := Run(context.Background(), testLogger(), nil); err == nil || !strings.Contains(err.Error(), "SB_CONTAINER_ENGINE=containerd") {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("no helper", func(t *testing.T) {
		setBaseRunEnv(t)
		origWait, origRetry := helperBootWait, helperBootRetry
		t.Cleanup(func() { helperBootWait, helperBootRetry = origWait, origRetry })
		helperBootWait, helperBootRetry = 100*time.Millisecond, 10*time.Millisecond
		t.Setenv("SB_PRIVILEGE_MODE", "split")
		t.Setenv("SB_ROOTD_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		t.Setenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", "true")
		t.Setenv("SB_EGRESS_FQDN_ENABLED", "false")
		err := Run(context.Background(), testLogger(), nil)
		if !errors.Is(err, rootclient.ErrUnavailable) || !strings.Contains(err.Error(), "root helper") {
			t.Fatalf("Run = %v, want the helper unavailable", err)
		}
	})
}

// TestImageBuilderFor: the API gets the engine's builder as it is, in
// every privilege mode, and no builder (not a typed nil) without one.
func TestImageBuilderFor(t *testing.T) {
	if b := imageBuilderFor(nil); b != nil {
		t.Fatalf("no containerd engine: got %v, want no builder", b)
	}
	ib := cntr.NewImageBuilder(nil, nil)
	if b := imageBuilderFor(ib); b != ib {
		t.Fatalf("got %T, want the engine's builder", b)
	}
}

// TestBuildKitBuilderFor: a rootless node's builder imports each build's
// OCI archive (split mode always has one: config refuses split without
// it); any other node keeps today's root buildkitd and its containerd
// worker.
func TestBuildKitBuilderFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{"single, today's buildkitd", config.Config{PrivilegeMode: privmode.Single, ContainerdBuildKitAddr: "unix:///run/buildkit/buildkitd.sock"}, false},
		{"single, rootless opted in", config.Config{PrivilegeMode: privmode.Single, ContainerdBuildKitRootless: true, ContainerdBuildMaxImageBytes: 1 << 20}, true},
		{"split", config.Config{PrivilegeMode: privmode.Split, ContainerdBuildKitRootless: true, ContainerdBuildMaxImageBytes: 1 << 20}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := buildKitBuilderFor(tc.cfg, nil, testLogger())
			if got := b.ImportsArchives(); got != tc.want {
				t.Fatalf("ImportsArchives = %v, want %v", got, tc.want)
			}
		})
	}
}

type recordReclaim struct{ calls []string }

func (r *recordReclaim) Reclaim(_ context.Context, kind, source string) error {
	r.calls = append(r.calls, kind+" "+source)
	return nil
}

func (r *recordReclaim) ReclaimVolume(_ context.Context, source string) error {
	r.calls = append(r.calls, "helper "+source)
	return nil
}

// In split mode an NFS volume's files are the helper's to delete; an S3
// one's stay sandboxd's (the aws CLI needs no rights). Single mode keeps
// its own reclaimer.
func TestVolumeReclaimerFor(t *testing.T) {
	own := &recordReclaim{}
	if got := volumeReclaimerFor(config.Config{}, own, nil); got != own {
		t.Fatal("single mode")
	}
	if got := volumeReclaimerFor(splitConfig(), own, nil); got != own {
		t.Fatal("split mode before a helper client")
	}
	if got := volumeReclaimerFor(splitConfig(), own, rootclient.New(rootclient.Config{})); got == service.VolumeReclaimer(own) {
		t.Fatal("split mode kept sandboxd's reclaimer for NFS")
	}
	r := splitReclaimer{own: own, helper: own}
	_ = r.Reclaim(context.Background(), volumes.BackendNFS, "h:/e/t/v")
	_ = r.Reclaim(context.Background(), volumes.BackendS3, "b/p/t/v")
	if !slices.Equal(own.calls, []string{"helper h:/e/t/v", "s3 b/p/t/v"}) {
		t.Fatalf("calls %v", own.calls)
	}
}

// newMountManager: sandboxd's own manager in single mode; in split mode one
// that sends every call to the helper, set once the client exists.
func TestNewMountManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	m, set, err := newMountManager(config.Config{MountsRootPath: filepath.Join(dir, "m"), MountsCredentialsRuntimeDir: filepath.Join(dir, "c")}, logger, "")
	if err != nil || m == nil {
		t.Fatal(err)
	}
	set(nil)
	m.Close()
	sm, set, err := newMountManager(splitConfig(), logger, "")
	if err != nil {
		t.Fatal(err)
	}
	// No client yet: a mount set fails as the helper unavailable, and
	// nothing is made in sandboxd's own folders.
	specs := []models.MountSpec{{Type: models.MountTypeNFS, Target: "/d", Source: "h:/e"}}
	if _, err := sm.MountAll(context.Background(), "sb-1", specs); !errors.Is(err, rootclient.ErrUnavailable) {
		t.Fatalf("before the client: %v", err)
	}
	set(rootclient.New(rootclient.Config{Socket: filepath.Join(dir, "none.sock"), Timeout: 100 * time.Millisecond}))
	if _, err := sm.MountAll(context.Background(), "sb-1", specs); !errors.Is(err, rootclient.ErrUnavailable) {
		t.Fatalf("no helper on the socket: %v", err)
	}
}
