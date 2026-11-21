package daemon

import (
	"context"
	"errors"
	"fmt"
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

func TestCheckPrivilegeMode(t *testing.T) {
	if err := checkPrivilegeMode(config.Config{PrivilegeMode: privmode.Single, ContainerEngine: models.ContainerEngineDocker, EnableNetworkRules: true}); err != nil {
		t.Fatalf("single mode: %v", err)
	}
	if err := checkPrivilegeMode(splitConfig()); err != nil {
		t.Fatalf("split mode with nothing the helper lacks: %v", err)
	}
	for _, tc := range []struct {
		name string
		set  func(*config.Config)
		want string
		gap  []privmode.Step
	}{
		{"the Docker engine", func(c *config.Config) { c.ContainerEngine = models.ContainerEngineDocker }, "SB_CONTAINER_ENGINE=containerd", nil},
		{"no netns pool", func(c *config.Config) { c.ContainerdNativeNetnsPoolEnabled = false }, "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", nil},
		{"the firewall", func(c *config.Config) { c.EnableNetworkRules = true }, "host firewall", []privmode.Step{privmode.StepFirewall}},
		{"the hostname gateway", func(c *config.Config) { c.EgressFQDNEnabled = true }, "host firewall", []privmode.Step{privmode.StepFirewall}},
		{"enterprise mode's fence", func(c *config.Config) { c.EnterpriseMode = true }, "host firewall", []privmode.Step{privmode.StepFirewall}},
		{"the warm pool", func(c *config.Config) { c.ContainerdPoolEnabled = true }, "warm pool", []privmode.Step{privmode.StepWarmPool}},
		{"WASM", func(c *config.Config) { c.EnableWasm = true }, "WASM", []privmode.Step{privmode.StepHostProcesses}},
		{"V8 isolates", func(c *config.Config) { c.EnableIsolate = true }, "V8", []privmode.Step{privmode.StepHostProcesses}},
		{"Firecracker", func(c *config.Config) { c.EnableFirecracker = true }, "Firecracker", []privmode.Step{privmode.StepHostProcesses}},
		{"gVisor moves", func(c *config.Config) { c.GvisorCheckpointMoves = true }, "gVisor checkpoint", []privmode.Step{privmode.StepMoves}},
		{"ingress proxy routing", func(c *config.Config) { c.IngressProxyRouting = true }, "host-port forwarding", []privmode.Step{privmode.StepHostPorts}},
		{"a rollback of ingress proxy routing", func(c *config.Config) {
			c.DBPath = filepath.Join(engagedMarkerDir(t), "state.db")
		}, "host-port forwarding", []privmode.Step{privmode.StepHostPorts}},
		{"several at once, each named", func(c *config.Config) { c.EnableNetworkRules, c.EnableWasm = true, true }, "WASM",
			[]privmode.Step{privmode.StepFirewall, privmode.StepHostProcesses}},
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
	if got := mountsOffFor(splitConfig()); !strings.Contains(got, "external storage") || !strings.Contains(got, "SB_PRIVILEGE_MODE=single") {
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
	// The driver is in split mode: a create names its gaps.
	_, err = w.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine"}, "sb-1", "t", nil)
	if !errors.Is(err, privmode.ErrGap) {
		t.Fatalf("Create = %v, want a Gap", err)
	}
}

// engineHelper is the whole helper the engine wiring takes.
type engineHelper struct{ *memHelper }

func (*engineHelper) Socket() string                      { return "/nonexistent/root.sock" }
func (*engineHelper) ContainerdOptions() []cntrclient.Opt { return nil }

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
