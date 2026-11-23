package daemon

import (
	"context"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/hostproc"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// fakeHostHelper is the root helper's host calls, recording each.
type fakeHostHelper struct {
	calls []string
	resp  *rootdpb.SpawnHostResponse
	hosts []*rootdpb.RunningHost
	err   error
	held  *rootclient.HostProcess
}

func (f *fakeHostHelper) note(c string) { f.calls = append(f.calls, c) }

func (f *fakeHostHelper) PrepareHost(_ context.Context, kind rootdpb.HostKind, id string) (string, error) {
	f.note("prepare " + rootdpb.HostKindName(kind) + " " + id)
	return "/srv/isolate-jail/" + id + "/run", f.err
}

func (f *fakeHostHelper) SpawnHost(_ context.Context, req *rootdpb.SpawnHostRequest) (*rootdpb.SpawnHostResponse, error) {
	l := req.GetLimits()
	f.note("spawn " + req.GetId() + " " + strings.Join([]string{fmtU(uint64(l.GetCpuMillis())), fmtU(l.GetMemoryMb()), fmtU(uint64(l.GetPids()))}, "/"))
	return f.resp, f.err
}

func (f *fakeHostHelper) StopHost(_ context.Context, _ rootdpb.HostKind, id string) (bool, error) {
	f.note("stop " + id)
	return true, f.err
}

func (f *fakeHostHelper) ListHosts(context.Context, rootdpb.HostKind) ([]*rootdpb.RunningHost, error) {
	f.note("list")
	return f.hosts, f.err
}

func (f *fakeHostHelper) SetHostLimits(_ context.Context, _ rootdpb.HostKind, id string, _ *rootdpb.HostLimits) error {
	f.note("limits " + id)
	return f.err
}

func (f *fakeHostHelper) HoldHost(kind rootdpb.HostKind, id string, pid int, ticks uint64) *rootclient.HostProcess {
	f.note("hold " + id)
	return f.held
}

func (f *fakeHostHelper) OpenHost(_ context.Context, _ rootdpb.HostKind, id string, _ int, _ uint64) (*rootclient.HostProcess, error) {
	f.note("open " + id)
	return f.held, f.err
}

func (f *fakeHostHelper) GrantWasmMounts(_ context.Context, sandboxID string, kind rootdpb.HostKind, hostID string) (int, error) {
	f.note("lend " + sandboxID + " " + rootdpb.HostKindName(kind) + " " + hostID)
	return 1, f.err
}

func fmtU(n uint64) string { return strconv.FormatUint(n, 10) }

// TestSplitMountLender: sandboxd names the host to lend a sandbox's mounts
// to by the socket it dials, which must be one the helper serves a WASM
// host on.
func TestSplitMountLender(t *testing.T) {
	f := &fakeHostHelper{}
	lend := splitMountLender(f, "/run/aerolvm-rootd/wasm")
	ctx := context.Background()
	for _, sock := range []string{"/run/aerolvm-rootd/wasm/w-sb-1.sock", "/run/aerolvm-rootd/wasm/r-o0123456789abcdef-b.sock"} {
		if err := lend(ctx, "sb-1", sock); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(f.calls, []string{"lend sb-1 wasm_worker sb-1", "lend sb-1 wasm_resident o0123456789abcdef-b"}) {
		t.Fatalf("calls %v", f.calls)
	}
	for _, bad := range []string{"/var/lib/sandboxd/wasm/run/sockets/sb-1.sock", "/run/aerolvm-rootd/wasm/w-../x.sock", "/run/aerolvm-rootd/wasm/x.sock"} {
		if err := lend(ctx, "sb-1", bad); err == nil {
			t.Errorf("lent through %s", bad)
		}
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls %v", f.calls)
	}
	f.err = errors.New("helper down")
	if err := lend(ctx, "sb-1", "/run/aerolvm-rootd/wasm/w-sb-1.sock"); !errors.Is(err, f.err) {
		t.Fatalf("lend = %v", err)
	}
}

func TestSplitWorkerdLauncher(t *testing.T) {
	ctx := context.Background()
	f := &fakeHostHelper{resp: &rootdpb.SpawnHostResponse{Pid: 42, StartTicks: 7}}
	l := splitWorkerdLauncher{h: f}
	var _ pkgisolate.JailLauncher = l
	if run, err := l.Prepare(ctx, "g"); err != nil || run != "/srv/isolate-jail/g/run" {
		t.Fatalf("Prepare = %q, %v", run, err)
	}
	if _, err := l.Start(ctx, "g", pkgisolate.Limits{CPU: 0.0001, MemoryMB: 128, Pids: 64}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetLimits(ctx, "g", pkgisolate.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Stop(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Open(ctx, "g", 42, 7); err != nil {
		t.Fatal(err)
	}
	f.hosts = []*rootdpb.RunningHost{{Id: "g"}, {Id: "left"}}
	if groups, err := l.Groups(ctx); err != nil || !slices.Equal(groups, []string{"g", "left"}) {
		t.Fatalf("Groups = %v, %v", groups, err)
	}
	// A small CPU cap rounds up, never down to none.
	want := []string{"prepare workerd g", "spawn g 1/128/64", "hold g", "limits g", "stop g", "open g", "list"}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls %v, want %v", f.calls, want)
	}
	// The helper's errors come back as they are; an answer with no process
	// is no host.
	boom := errors.New("boom")
	f.err = boom
	if _, err := l.Start(ctx, "g", pkgisolate.Limits{}); !errors.Is(err, boom) {
		t.Fatalf("Start = %v", err)
	}
	if _, err := l.Open(ctx, "g", 1, 1); !errors.Is(err, boom) {
		t.Fatalf("Open = %v", err)
	}
	if _, err := l.Groups(ctx); !errors.Is(err, boom) {
		t.Fatalf("Groups = %v", err)
	}
	f.err, f.resp = nil, &rootdpb.SpawnHostResponse{}
	if _, err := l.Start(ctx, "g", pkgisolate.Limits{}); err == nil {
		t.Fatal("a host with no process was held")
	}
}

func TestHostLimitsOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		in   pkgisolate.Limits
		want *rootdpb.HostLimits
	}{
		{pkgisolate.Limits{}, &rootdpb.HostLimits{}},
		{pkgisolate.Limits{CPU: 1.5, MemoryMB: 512, Pids: 100}, &rootdpb.HostLimits{CpuMillis: 1500, MemoryMb: 512, Pids: 100}},
		{pkgisolate.Limits{CPU: -1, MemoryMB: -1, Pids: -1}, &rootdpb.HostLimits{}},
		{pkgisolate.Limits{CPU: 1e12, Pids: math.MaxInt}, &rootdpb.HostLimits{CpuMillis: math.MaxUint32, Pids: math.MaxUint32}},
	} {
		got := hostLimits(tc.in)
		if got.GetCpuMillis() != tc.want.GetCpuMillis() || got.GetMemoryMb() != tc.want.GetMemoryMb() || got.GetPids() != tc.want.GetPids() {
			t.Errorf("hostLimits(%+v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestWireIsolateRuntimeSplit: in privilege mode split the V8 driver gets
// the helper as its jail launcher, and boot builds no jail base and needs
// no root: the helper does both.
func TestWireIsolateRuntimeSplit(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	f := &fakeHostHelper{}
	driver, err := wireIsolateRuntime(context.Background(), config.Config{
		IsolateWorkerdPath:      "/nonexistent/workerd",
		IsolateRunDir:           t.TempDir(),
		IsolateUseJail:          true,
		IsolateJailChrootBase:   "/nonexistent/jail",
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
	}, testLogger(), svc, f)
	if err != nil || driver == nil {
		t.Fatalf("wireIsolateRuntime in split = %v, %v", driver, err)
	}
	// Boot adoption asked the helper what it holds; nothing was jailed here.
	if !slices.Contains(f.calls, "list") {
		t.Fatalf("boot did not ask the helper for its groups: %v", f.calls)
	}
	var _ hostproc.Process = (*rootclient.HostProcess)(nil)
}

func TestSplitWasmLauncher(t *testing.T) {
	ctx := context.Background()
	sock := "/run/aerolvm-rootd/wasm/w-sb-1.sock"
	f := &fakeHostHelper{resp: &rootdpb.SpawnHostResponse{Pid: 9, StartTicks: 3, Socket: sock}}
	var gotReq *rootdpb.SpawnHostRequest
	l := splitWasmLauncher{h: recordSpawn{f, &gotReq}, kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, cacheRoot: "/c"}
	t.Setenv("SB_AUDIT_INGEST_PORT", "7000")
	t.Setenv("SB_NODE_ID", "")
	if _, err := l.Launch(ctx, "sb-1", sock, "/c/owners/operator"); err != nil {
		t.Fatal(err)
	}
	if gotReq.GetWasm().GetCache() != "operator" || !slices.Contains(gotReq.GetWasm().GetEnv(), "SB_AUDIT_INGEST_PORT=7000") ||
		slices.ContainsFunc(gotReq.GetWasm().GetEnv(), func(e string) bool { return strings.HasPrefix(e, "SB_NODE_ID") }) {
		t.Fatalf("spec %v", gotReq.GetWasm())
	}
	// The helper serves it elsewhere: the two settings differ, and the
	// host is stopped rather than left unreachable.
	f.resp = &rootdpb.SpawnHostResponse{Pid: 9, Socket: "/other/w-sb-1.sock"}
	if _, err := l.Launch(ctx, "sb-1", sock, ""); err == nil || !strings.Contains(err.Error(), "SB_ROOTD_WASM_SOCKET_DIR") {
		t.Fatalf("socket mismatch: %v", err)
	}
	if !slices.Contains(f.calls, "stop sb-1") {
		t.Fatalf("a host on another socket was left: %v", f.calls)
	}
	f.resp = &rootdpb.SpawnHostResponse{Socket: sock}
	if _, err := l.Launch(ctx, "sb-1", sock, ""); err == nil {
		t.Fatal("a host with no process")
	}
	f.err = errors.New("boom")
	if _, err := l.Launch(ctx, "sb-1", sock, ""); !errors.Is(err, f.err) {
		t.Fatalf("Launch = %v", err)
	}
}

// recordSpawn keeps the last SpawnHost request.
type recordSpawn struct {
	*fakeHostHelper
	last **rootdpb.SpawnHostRequest
}

func (r recordSpawn) SpawnHost(ctx context.Context, req *rootdpb.SpawnHostRequest) (*rootdpb.SpawnHostResponse, error) {
	*r.last = req
	return r.fakeHostHelper.SpawnHost(ctx, req)
}

func TestSplitWasmWorkers(t *testing.T) {
	f := &fakeHostHelper{hosts: []*rootdpb.RunningHost{
		{Kind: rootdpb.HostKind_HOST_KIND_WORKERD, Id: "g", Pid: 1, StartTicks: 1},
		{Kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, Id: "sb-1", Pid: 2, StartTicks: 2},
		{Kind: rootdpb.HostKind_HOST_KIND_WASM_RESIDENT, Id: "b-2", Pid: 3, StartTicks: 3},
		{Kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, Id: "gone", Pid: 0},
		{Kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, Id: "../bad", Pid: 4},
	}}
	list := splitWasmWorkers(f, "/run/aerolvm-rootd/wasm", testLogger())
	found, err := list(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].Socket != "/run/aerolvm-rootd/wasm/w-sb-1.sock" || found[0].Resident ||
		found[1].Socket != "/run/aerolvm-rootd/wasm/r-b-2.sock" || !found[1].Resident || found[1].PID != 3 {
		t.Fatalf("found %+v", found)
	}
	if !slices.Contains(f.calls, "stop gone") {
		t.Fatalf("a host with no process was not removed: %v", f.calls)
	}
	f.err = errors.New("helper down")
	if _, err := list(context.Background()); err == nil {
		t.Fatal("a failed list was taken")
	}
}

// TestCheckSplitWasmGroups: sandboxd's own groups decide whether it can
// share files with the worker user; an unreadable list refuses the node.
func TestCheckSplitWasmGroups(t *testing.T) {
	old := agentGroups
	t.Cleanup(func() { agentGroups = old })
	agentGroups = func() ([]int, error) { return nil, errors.New("no /proc") }
	cfg := splitConfig()
	cfg.EnableWasm, cfg.WasmWorkerDropPrivs, cfg.WasmWorkerUID, cfg.WasmWorkerGID = true, true, 61000, 61000
	if err := checkPrivilegeMode(cfg); err == nil || !strings.Contains(err.Error(), "groups") {
		t.Fatalf("unreadable groups: %v", err)
	}
}

// TestWireWasmRuntimeSplit: in privilege mode split the WASM driver's
// workers and resident hosts start through the helper, boot adoption asks
// it what runs, and no fence or cgroup of sandboxd's own is made.
func TestWireWasmRuntimeSplit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	f := &fakeHostHelper{}
	pool := wireWasmRuntime(ctx, config.Config{
		WasmRunDir: t.TempDir(), WasmModulesDir: t.TempDir(), WasmEngine: "wazero", WasmResidentHostEnabled: true,
		WasmWorkerUID: 61000, WasmWorkerGID: 61000, EnableNetworkRules: true, RootdWasmSocketDir: "/run/aerolvm-rootd/wasm",
	}, testLogger(), svc, st, f)
	if pool != nil {
		t.Fatalf("a warm pool in split: %v", pool)
	}
	if !slices.Contains(f.calls, "list") {
		t.Fatalf("boot adoption did not ask the helper: %v", f.calls)
	}
}

// TestWireWasmWarmPoolSplit: in privilege mode split the WASM warm pool is
// wired (M1 PR 15), each slot's worker on the helper's socket for the
// slot's id.
func TestWireWasmWarmPoolSplit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	pool := wireWasmRuntime(ctx, config.Config{
		WasmRunDir: t.TempDir(), WasmModulesDir: t.TempDir(), WasmEngine: "wazero", WasmPoolEnabled: true, WasmPoolDepthDefault: 1,
		WasmWorkerUID: 61000, WasmWorkerGID: 61000, RootdWasmSocketDir: "/run/aerolvm-rootd/wasm",
	}, testLogger(), svc, st, &fakeHostHelper{})
	if pool == nil {
		t.Fatal("no warm pool in split")
	}
	defer pool.Close()
	sock := splitSlotSocket("/run/aerolvm-rootd/wasm")
	if got, err := sock("pool-0123456789abcdef"); err != nil || got != "/run/aerolvm-rootd/wasm/w-pool-0123456789abcdef.sock" {
		t.Fatalf("slot socket %q %v", got, err)
	}
	if _, err := sock("../x"); err == nil {
		t.Fatal("a socket for a bad slot id")
	}
}
