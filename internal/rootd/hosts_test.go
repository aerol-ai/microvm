package rootd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/isolate"
)

// fakeHostKernel keeps groups in memory and starts each host as a real,
// harmless process (sleep), so Wait, pids and kills are real.
type fakeHostKernel struct {
	mu      sync.Mutex
	groups  map[string][]int
	limits  map[string]rootpolicy.HostLimits
	started []string
	killed  []string
	ticks   map[int]uint64
	// failures, by method name.
	fail map[string]error
	// exitAtStart makes a started host's start time unreadable: it exited.
	exitAtStart bool
}

func newFakeHostKernel() *fakeHostKernel {
	return &fakeHostKernel{groups: map[string][]int{}, limits: map[string]rootpolicy.HostLimits{}, ticks: map[int]uint64{}, fail: map[string]error{}}
}

func (k *fakeHostKernel) EnsureGroup(group string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["EnsureGroup"]; err != nil {
		return err
	}
	if _, ok := k.groups[group]; !ok {
		k.groups[group] = nil
	}
	return nil
}

func (k *fakeHostKernel) SetLimits(group string, l rootpolicy.HostLimits) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["SetLimits"]; err != nil {
		return err
	}
	k.limits[group] = l
	return nil
}

func (k *fakeHostKernel) Start(cmd *exec.Cmd, group string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["Start"]; err != nil {
		return err
	}
	if _, ok := k.groups[group]; !ok {
		return errors.New("start in a group that was not made")
	}
	// The launcher's command is what the host would run; a sleep stands in.
	k.started = append(k.started, group+" "+strings.Join(cmd.Args, " "))
	cmd.Path, cmd.Args, cmd.Env = "/bin/sleep", []string{"sleep", "60"}, nil
	cmd.SysProcAttr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	k.groups[group] = append(k.groups[group], cmd.Process.Pid)
	if !k.exitAtStart {
		k.ticks[cmd.Process.Pid] = uint64(1000 + cmd.Process.Pid)
	}
	return nil
}

func (k *fakeHostKernel) Procs(group string) ([]int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["Procs"]; err != nil {
		return nil, err
	}
	return slices.Clone(k.groups[group]), nil
}

func (k *fakeHostKernel) Kill(_ context.Context, group string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["Kill"]; err != nil {
		return err
	}
	for _, pid := range k.groups[group] {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	}
	k.killed = append(k.killed, group)
	if _, ok := k.groups[group]; ok {
		k.groups[group] = nil
	}
	return nil
}

func (k *fakeHostKernel) RemoveGroup(group string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["RemoveGroup"]; err != nil {
		return err
	}
	if len(k.groups[group]) > 0 {
		return errors.New("group not empty")
	}
	delete(k.groups, group)
	return nil
}

func (k *fakeHostKernel) Groups(parent string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail["Groups"]; err != nil {
		return nil, err
	}
	var out []string
	for g := range k.groups {
		if path.Dir(g) == parent {
			out = append(out, path.Base(g))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (k *fakeHostKernel) StartTicks(pid int) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t, ok := k.ticks[pid]
	if !ok {
		return 0, errors.New("no such process")
	}
	return t, nil
}

// fakeLauncher is a kind's own part, recording each call.
type fakeLauncher struct {
	mu        sync.Mutex
	calls     []string
	prepared  map[string]bool
	leftovers []string
	fail      map[string]error
	maxPids   uint32
	noLimits  bool
	sock      string
	startedFn func() error
}

func newFakeLauncher() *fakeLauncher {
	return &fakeLauncher{prepared: map[string]bool{}, fail: map[string]error{}, maxPids: 100}
}

func (l *fakeLauncher) note(c string) {
	l.mu.Lock()
	l.calls = append(l.calls, c)
	l.mu.Unlock()
}

func (l *fakeLauncher) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

func (l *fakeLauncher) prepare(id string, running bool) (*rootdpb.PrepareHostResponse, error) {
	l.note(fmt.Sprintf("prepare %s running=%v", id, running))
	if err := l.fail["prepare"]; err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.prepared[id] = true
	l.mu.Unlock()
	return &rootdpb.PrepareHostResponse{RunDir: "/jail/" + id + "/run"}, nil
}

func (l *fakeLauncher) command(_ context.Context, id string, _ *rootdpb.SpawnHostRequest) (*exec.Cmd, func(), error) {
	l.note("command " + id)
	if err := l.fail["command"]; err != nil {
		return nil, nil, err
	}
	return exec.Command("/helper", "--host", id), func() { l.note("done " + id) }, nil
}

func (l *fakeLauncher) socket(id string) string {
	if l.sock == "" {
		return ""
	}
	return l.sock + "/" + id + ".sock"
}

func (l *fakeLauncher) limits(lim rootpolicy.HostLimits) (rootpolicy.HostLimits, bool) {
	if l.noLimits {
		return lim, false
	}
	if lim.Pids == 0 || lim.Pids > l.maxPids {
		lim.Pids = l.maxPids
	}
	return lim, true
}

func (l *fakeLauncher) started(context.Context, *exec.Cmd) error {
	if l.startedFn != nil {
		return l.startedFn()
	}
	return nil
}

func (l *fakeLauncher) teardown(id string) error {
	l.note("teardown " + id)
	return l.fail["teardown"]
}

func (l *fakeLauncher) present() ([]string, error) {
	if err := l.fail["present"]; err != nil {
		return nil, err
	}
	return slices.Clone(l.leftovers), nil
}

// hostsRig is a server rig whose helper serves the workerd kind, with a
// fake kernel and a fake launcher put in its place.
func hostsRig(t *testing.T) (*rig, *fakeHostKernel, *fakeLauncher) {
	t.Helper()
	kernel, l := newFakeHostKernel(), newFakeLauncher()
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = testHostsConfig(t)
		o.HostKernel = kernel
		o.hostLaunchers = map[rootpolicy.HostKind]hostLauncher{rootpolicy.HostWorkerd: l}
	})
	t.Cleanup(func() {
		kernel.mu.Lock()
		for _, pids := range kernel.groups {
			for _, pid := range pids {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
				}
			}
		}
		kernel.mu.Unlock()
		r.srv.hosts.reaping.Wait()
	})
	return r, kernel, l
}

// testHostsConfig names the workerd kind, as ConfigFromEnv does with
// SB_ENABLE_ISOLATE: settings the server checks, never used to start one.
func testHostsConfig(t testing.TB) HostsConfig {
	dir := t.TempDir()
	return HostsConfig{
		LogPath: filepath.Join(dir, "hosts.log"),
		Workerd: &WorkerdHostsConfig{
			Jail: isolate.RootJail{ChrootBase: filepath.Join(dir, "jail"), WorkerdPath: "/usr/local/bin/workerd",
				UID: 1000, GID: 1000, AgentUID: 65531, SeccompMode: isolate.SeccompEnforce, ShimPath: "/usr/local/bin/aerolvm-rootd"},
			PidsMax: 512,
		},
	}
}

func hostClient(r *rig) rootdpb.RootHelperClient { return rootdpb.NewRootHelperClient(r.conn) }

const workerd = rootdpb.HostKind_HOST_KIND_WORKERD

func TestHostsVersionListsKinds(t *testing.T) {
	r, _, _ := hostsRig(t)
	resp, err := hostClient(r).Version(callCtx(t), &rootdpb.VersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range hostFeatures {
		if !slices.Contains(resp.GetFeatures(), f) {
			t.Errorf("features %v lack %s", resp.GetFeatures(), f)
		}
	}
	if !slices.Equal(resp.GetHosts(), []string{"workerd"}) {
		t.Fatalf("hosts %v, want [workerd]", resp.GetHosts())
	}
	// A helper whose settings name no kind lists none, and answers each
	// host call as one it lacks.
	plain := newRig(t, nil)
	resp, err = hostClient(plain).Version(callCtx(t), &rootdpb.VersionRequest{})
	if err != nil || len(resp.GetHosts()) != 0 {
		t.Fatalf("plain helper hosts %v (%v)", resp.GetHosts(), err)
	}
	c := hostClient(plain)
	for name, call := range map[string]func() error{
		"PrepareHost": func() error {
			_, err := c.PrepareHost(callCtx(t), &rootdpb.PrepareHostRequest{Kind: workerd, Id: "g"})
			return err
		},
		"SpawnHost": func() error {
			_, err := c.SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g"})
			return err
		},
		"StopHost": func() error {
			_, err := c.StopHost(callCtx(t), &rootdpb.StopHostRequest{Kind: workerd, Id: "g"})
			return err
		},
		"ListHosts": func() error { _, err := c.ListHosts(callCtx(t), &rootdpb.ListHostsRequest{}); return err },
		"SetHostLimits": func() error {
			_, err := c.SetHostLimits(callCtx(t), &rootdpb.SetHostLimitsRequest{Kind: workerd, Id: "g"})
			return err
		},
	} {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s on a helper with no host kind: %v, want Unimplemented", name, err)
		}
	}
}

// TestHostsRefuseHostileRequests is the broken-agent list for the host
// calls (plan §3.6): each request a compromised agent could send is
// refused, and each refusal is reported with its rule.
func TestHostsRefuseHostileRequests(t *testing.T) {
	r, kernel, l := hostsRig(t)
	c := hostClient(r)
	for _, tc := range []struct {
		name   string
		req    *rootdpb.SpawnHostRequest
		code   codes.Code
		reason string
	}{
		{"no kind", &rootdpb.SpawnHostRequest{Id: "g"}, codes.InvalidArgument, ReasonHostKind},
		{"a kind no build knows", &rootdpb.SpawnHostRequest{Kind: 99, Id: "g"}, codes.InvalidArgument, ReasonHostKind},
		{"a dot path", &rootdpb.SpawnHostRequest{Kind: workerd, Id: ".."}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a separator", &rootdpb.SpawnHostRequest{Kind: workerd, Id: "a/../../etc"}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a hidden name (the base tree)", &rootdpb.SpawnHostRequest{Kind: workerd, Id: ".base"}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"an option", &rootdpb.SpawnHostRequest{Kind: workerd, Id: "-rf"}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"an empty id", &rootdpb.SpawnHostRequest{Kind: workerd}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"more memory than the node", &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g", Limits: &rootdpb.HostLimits{MemoryMb: 1 << 20}},
			codes.InvalidArgument, string(rootpolicy.RuleHostLimits)},
		{"more CPU than the node", &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g", Limits: &rootdpb.HostLimits{CpuMillis: 3000}},
			codes.InvalidArgument, string(rootpolicy.RuleHostLimits)},
		{"more pids than a sandbox may hold", &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g", Limits: &rootdpb.HostLimits{Pids: 5000}},
			codes.InvalidArgument, string(rootpolicy.RuleHostLimits)},
		{"a WASM spec on a V8 host", &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g", Wasm: &rootdpb.WasmHostSpec{}},
			codes.InvalidArgument, ReasonBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(r.refused())
			_, err := c.SpawnHost(callCtx(t), tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("SpawnHost: %v, want %v", err, tc.code)
			}
			reason, refused := rootdpb.RefusalReason(err)
			if !refused || reason != tc.reason {
				t.Fatalf("refusal %q (%v), want %q", reason, refused, tc.reason)
			}
			if got := r.refused(); len(got) != before+1 || got[len(got)-1].Reason != tc.reason {
				t.Fatalf("refusal not reported: %v", got)
			}
		})
	}
	// A kind this build knows that the helper does not serve is a version
	// skew, never a refusal: it would page someone for an old helper.
	before := len(r.refused())
	if _, err := c.SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, Id: "sb-1"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("unserved kind: %v, want Unimplemented", err)
	}
	if len(r.refused()) != before {
		t.Fatal("an unserved kind was reported as a refusal")
	}
	if len(kernel.started) != 0 || len(l.seen()) != 0 {
		t.Fatalf("a refused request reached the kernel or the launcher: %v %v", kernel.started, l.seen())
	}
	// The other calls check the same.
	for name, call := range map[string]func() error{
		"PrepareHost": func() error {
			_, err := c.PrepareHost(callCtx(t), &rootdpb.PrepareHostRequest{Kind: workerd, Id: "../x"})
			return err
		},
		"StopHost": func() error {
			_, err := c.StopHost(callCtx(t), &rootdpb.StopHostRequest{Kind: workerd, Id: "a/b"})
			return err
		},
		"SetHostLimits": func() error {
			_, err := c.SetHostLimits(callCtx(t), &rootdpb.SetHostLimitsRequest{Kind: workerd, Id: "g", Limits: &rootdpb.HostLimits{MemoryMb: 1 << 30}})
			return err
		},
		"ListHosts": func() error { _, err := c.ListHosts(callCtx(t), &rootdpb.ListHostsRequest{Kind: 77}); return err },
	} {
		if _, refused := rootdpb.RefusalReason(call()); !refused {
			t.Errorf("%s: a hostile request was not refused", name)
		}
	}
}

func TestHostsSpawnStopList(t *testing.T) {
	r, kernel, l := hostsRig(t)
	c := hostClient(r)
	group := rootpolicy.HostGroup(rootpolicy.HostWorkerd, "tenant-a")

	run, err := c.PrepareHost(callCtx(t), &rootdpb.PrepareHostRequest{Kind: workerd, Id: "tenant-a"})
	if err != nil || run.GetRunDir() != "/jail/tenant-a/run" {
		t.Fatalf("PrepareHost = %v, %v", run, err)
	}
	resp, err := c.SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: workerd, Id: "tenant-a",
		Limits: &rootdpb.HostLimits{CpuMillis: 500, MemoryMb: 128}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPid() == 0 || resp.GetStartTicks() != uint64(1000+resp.GetPid()) || resp.GetAlready() {
		t.Fatalf("SpawnHost = %v", resp)
	}
	// Unset pids take the kind's own bound: a group is never unlimited.
	if got := kernel.limits[group]; got != (rootpolicy.HostLimits{CPUMillis: 500, MemoryMB: 128, Pids: 100}) {
		t.Fatalf("limits %+v", got)
	}
	if len(kernel.started) != 1 || kernel.started[0] != group+" /helper --host tenant-a" {
		t.Fatalf("started %v", kernel.started)
	}
	// A second spawn answers the host as it is and starts nothing.
	again, err := c.SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: workerd, Id: "tenant-a"})
	if err != nil || !again.GetAlready() || again.GetPid() != resp.GetPid() || len(kernel.started) != 1 {
		t.Fatalf("second SpawnHost = %v, %v (started %v)", again, err, kernel.started)
	}
	// A running group keeps its limits up to date, and the kind's bound.
	if _, err := c.SetHostLimits(callCtx(t), &rootdpb.SetHostLimitsRequest{Kind: workerd, Id: "tenant-a",
		Limits: &rootdpb.HostLimits{MemoryMb: 256, Pids: 1000}}); err != nil {
		t.Fatal(err)
	}
	if got := kernel.limits[group]; got != (rootpolicy.HostLimits{MemoryMB: 256, Pids: 100}) {
		t.Fatalf("limits after SetHostLimits %+v", got)
	}

	// The list holds the running host, and a leftover the kind keeps (a
	// jail with no group) with no process.
	l.leftovers = []string{"tenant-a", "left-behind"}
	list, err := c.ListHosts(callCtx(t), &rootdpb.ListHostsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]uint32{}
	for _, h := range list.GetHosts() {
		if h.GetKind() != workerd {
			t.Fatalf("listed %v", h)
		}
		got[h.GetId()] = h.GetPid()
	}
	if len(got) != 2 || got["tenant-a"] != resp.GetPid() || got["left-behind"] != 0 {
		t.Fatalf("ListHosts = %v", got)
	}

	stopped, err := c.StopHost(callCtx(t), &rootdpb.StopHostRequest{Kind: workerd, Id: "tenant-a"})
	if err != nil || !stopped.GetHad() {
		t.Fatalf("StopHost = %v, %v", stopped, err)
	}
	if !slices.Equal(kernel.killed, []string{group}) {
		t.Fatalf("killed %v", kernel.killed)
	}
	if _, ok := kernel.groups[group]; ok {
		t.Fatal("the stopped host's group is still there")
	}
	if !slices.Contains(l.seen(), "teardown tenant-a") {
		t.Fatalf("no teardown: %v", l.seen())
	}
	// Stopping again finds nothing, and still tears down (idempotent).
	stopped, err = c.StopHost(callCtx(t), &rootdpb.StopHostRequest{Kind: workerd, Id: "tenant-a"})
	if err != nil || stopped.GetHad() {
		t.Fatalf("second StopHost = %v, %v", stopped, err)
	}
	// Limits for a host that does not run are not written.
	if _, err := c.SetHostLimits(callCtx(t), &rootdpb.SetHostLimitsRequest{Kind: workerd, Id: "tenant-a",
		Limits: &rootdpb.HostLimits{MemoryMb: 64}}); status.Code(err) != codes.NotFound {
		t.Fatalf("SetHostLimits on a stopped host: %v", err)
	}
	if list, err := c.ListHosts(callCtx(t), &rootdpb.ListHostsRequest{Kind: workerd}); err != nil || len(list.GetHosts()) != 2 {
		// tenant-a's jail is still "present" in this fake; both listed with no pid.
		t.Fatalf("ListHosts after stop = %v, %v", list, err)
	}
}

func TestHostsPrepareKeepsARunningHost(t *testing.T) {
	r, _, l := hostsRig(t)
	c := hostClient(r)
	if _, err := c.SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareHost(callCtx(t), &rootdpb.PrepareHostRequest{Kind: workerd, Id: "g1"}); err != nil {
		t.Fatal(err)
	}
	if calls := l.seen(); !slices.Contains(calls, "prepare g1 running=true") {
		t.Fatalf("prepare did not hear the host runs: %v", calls)
	}
}

func TestHostsFailures(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name  string
		setup func(*fakeHostKernel, *fakeLauncher)
		call  func(rootdpb.RootHelperClient, context.Context) error
		code  codes.Code
	}{
		{"group not made", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["EnsureGroup"] = boom },
			spawnG, codes.Internal},
		{"limits not written", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["SetLimits"] = boom },
			spawnG, codes.Internal},
		{"command not built", func(_ *fakeHostKernel, l *fakeLauncher) { l.fail["command"] = boom },
			spawnG, codes.Internal},
		{"not started", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Start"] = boom },
			spawnG, codes.Internal},
		{"exited as it started", func(k *fakeHostKernel, _ *fakeLauncher) { k.exitAtStart = true },
			spawnG, codes.Internal},
		{"never served", func(_ *fakeHostKernel, l *fakeLauncher) { l.startedFn = func() error { return boom } },
			spawnG, codes.Internal},
		{"procs unreadable on spawn", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Procs"] = boom },
			spawnG, codes.Internal},
		{"procs unreadable on prepare", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Procs"] = boom },
			func(c rootdpb.RootHelperClient, ctx context.Context) error {
				_, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: workerd, Id: "g"})
				return err
			}, codes.Internal},
		{"prepare fails", func(_ *fakeHostKernel, l *fakeLauncher) { l.fail["prepare"] = boom },
			func(c rootdpb.RootHelperClient, ctx context.Context) error {
				_, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: workerd, Id: "g"})
				return err
			}, codes.Internal},
		{"procs unreadable on stop", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Procs"] = boom },
			stopG, codes.Internal},
		{"teardown fails", func(_ *fakeHostKernel, l *fakeLauncher) { l.fail["teardown"] = boom },
			stopG, codes.Internal},
		{"groups unreadable on stop", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Groups"] = boom },
			stopG, codes.Internal},
		{"groups unreadable on list", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Groups"] = boom },
			listAll, codes.Internal},
		{"present unreadable on list", func(_ *fakeHostKernel, l *fakeLauncher) { l.fail["present"] = boom },
			listAll, codes.Internal},
		{"procs unreadable on list", func(k *fakeHostKernel, l *fakeLauncher) { l.leftovers = []string{"g"}; k.fail["Procs"] = boom },
			listAll, codes.Internal},
		{"procs unreadable on limits", func(k *fakeHostKernel, _ *fakeLauncher) { k.fail["Procs"] = boom },
			limitsG, codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, kernel, l := hostsRig(t)
			tc.setup(kernel, l)
			if err := tc.call(hostClient(r), callCtx(t)); status.Code(err) != tc.code {
				t.Fatalf("got %v, want %v", err, tc.code)
			}
		})
	}
	t.Run("kill fails", func(t *testing.T) {
		r, kernel, _ := hostsRig(t)
		if err := spawnG(hostClient(r), callCtx(t)); err != nil {
			t.Fatal(err)
		}
		kernel.fail["Kill"] = boom
		if err := stopG(hostClient(r), callCtx(t)); status.Code(err) != codes.Internal {
			t.Fatalf("got %v", err)
		}
		delete(kernel.fail, "Kill")
		kernel.fail["RemoveGroup"] = boom
		if err := stopG(hostClient(r), callCtx(t)); status.Code(err) != codes.Internal {
			t.Fatalf("got %v", err)
		}
		delete(kernel.fail, "RemoveGroup")
		if err := spawnG(hostClient(r), callCtx(t)); err != nil {
			t.Fatal(err)
		}
		kernel.fail["SetLimits"] = boom
		if err := limitsG(hostClient(r), callCtx(t)); status.Code(err) != codes.Internal {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a kind that takes no limits", func(t *testing.T) {
		r, _, l := hostsRig(t)
		l.noLimits = true
		_, err := hostClient(r).SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g", Limits: &rootdpb.HostLimits{}})
		if reason, _ := rootdpb.RefusalReason(err); reason != ReasonBadRequest {
			t.Fatalf("got %v", err)
		}
		if err := limitsG(hostClient(r), callCtx(t)); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("got %v", err)
		}
	})
}

func spawnG(c rootdpb.RootHelperClient, ctx context.Context) error {
	_, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g"})
	return err
}

func stopG(c rootdpb.RootHelperClient, ctx context.Context) error {
	_, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: workerd, Id: "g"})
	return err
}

func listAll(c rootdpb.RootHelperClient, ctx context.Context) error {
	_, err := c.ListHosts(ctx, &rootdpb.ListHostsRequest{})
	return err
}

func limitsG(c rootdpb.RootHelperClient, ctx context.Context) error {
	_, err := c.SetHostLimits(ctx, &rootdpb.SetHostLimitsRequest{Kind: workerd, Id: "g", Limits: &rootdpb.HostLimits{MemoryMb: 64}})
	return err
}

// TestCgroupHostKernelFiles drives the kernel's cgroup files on a plain
// folder: groups made under the kind's, limits written as the kernel takes
// them, procs read, a kill that needs no fallback, and removal.
func TestCgroupHostKernelFiles(t *testing.T) {
	root := t.TempDir()
	k := cgroupHostKernel{root: root}
	group := rootpolicy.HostGroup(rootpolicy.HostWorkerd, "g")
	if err := k.EnsureGroup(group); err != nil {
		t.Fatal(err)
	}
	kindDir, dir := filepath.Join(root, rootpolicy.WorkerdHostsGroup), filepath.Join(root, filepath.FromSlash(group))
	// A real cgroup has its interface files; a plain folder needs them made.
	for _, f := range []string{filepath.Join(kindDir, "cgroup.subtree_control"), filepath.Join(dir, "cpu.max"),
		filepath.Join(dir, "memory.max"), filepath.Join(dir, "pids.max"), filepath.Join(dir, "cgroup.kill"), filepath.Join(dir, "cgroup.procs")} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		l              rootpolicy.HostLimits
		cpu, mem, pids string
	}{
		{rootpolicy.HostLimits{CPUMillis: 1500, MemoryMB: 64, Pids: 32}, "150000 100000", "67108864", "32"},
		{rootpolicy.HostLimits{}, "max 100000", "max", "max"},
	} {
		if err := k.SetLimits(group, tc.l); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]string{"cpu.max": tc.cpu, "memory.max": tc.mem, "pids.max": tc.pids} {
			if got, _ := os.ReadFile(filepath.Join(dir, name)); string(got) != want {
				t.Fatalf("%s = %q, want %q", name, got, want)
			}
		}
	}
	if got, _ := os.ReadFile(filepath.Join(kindDir, "cgroup.subtree_control")); string(got) != "+cpu +memory +pids" {
		t.Fatalf("subtree_control = %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("12\n34\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if procs, err := k.Procs(group); err != nil || !slices.Equal(procs, []int{12, 34}) {
		t.Fatalf("Procs = %v, %v", procs, err)
	}
	if names, err := k.Groups(rootpolicy.WorkerdHostsGroup); err != nil || !slices.Equal(names, []string{"g"}) {
		t.Fatalf("Groups = %v, %v", names, err)
	}
	if names, err := k.Groups("aerolvm-none"); err != nil || names != nil {
		t.Fatalf("Groups of a missing parent = %v, %v", names, err)
	}
	// cgroup.kill took the write; the group empties (here, by hand).
	old := hostKillWait
	hostKillWait = 50 * time.Millisecond
	t.Cleanup(func() { hostKillWait = old })
	if err := k.Kill(context.Background(), group); err == nil {
		t.Fatal("Kill of a group that never empties succeeded")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "cgroup.kill")); string(got) != "1" {
		t.Fatalf("cgroup.kill = %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := k.Kill(context.Background(), group); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := k.Kill(ctx, group); !errors.Is(err, context.Canceled) {
		t.Fatalf("Kill with a cancelled call: %v", err)
	}
	// A plain folder with files is not empty; a real cgroup would be.
	for _, f := range []string{"cpu.max", "memory.max", "pids.max", "cgroup.kill", "cgroup.procs"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	if err := k.RemoveGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := k.RemoveGroup(group); err != nil {
		t.Fatal("removing a missing group:", err)
	}
	if _, err := k.Procs(group); err != nil {
		t.Fatal("procs of a missing group:", err)
	}
	// A group name that leaves the parent is refused before any file.
	for _, bad := range []string{"", "/abs", "../up", "a/../../b"} {
		if k.EnsureGroup(bad) == nil || k.SetLimits(bad, rootpolicy.HostLimits{}) == nil || k.RemoveGroup(bad) == nil ||
			k.Kill(context.Background(), bad) == nil || k.Start(exec.Command("/bin/true"), bad) == nil {
			t.Fatalf("group %q was used", bad)
		}
		if _, err := k.Procs(bad); err == nil {
			t.Fatalf("group %q was read", bad)
		}
		if _, err := k.Groups(bad); err == nil {
			t.Fatalf("group %q was listed", bad)
		}
	}
	// A missing parent is a clear error, not a group made at the root.
	if err := (cgroupHostKernel{root: filepath.Join(root, "missing")}).EnsureGroup(group); err == nil {
		t.Fatal("a group was made under a missing parent")
	}
	// A limit file that is not there fails the write.
	if err := k.SetLimits(group, rootpolicy.HostLimits{}); err == nil {
		t.Fatal("limits written to a group that is gone")
	}
}

func TestHostKindNames(t *testing.T) {
	for _, k := range rootdpb.HostKinds() {
		if kindOfName(hostKindOf(k)) != k {
			t.Errorf("%v does not survive its name", k)
		}
	}
	if hostKindOf(0) != "" || kindOfName("nope") != rootdpb.HostKind_HOST_KIND_UNSPECIFIED {
		t.Fatal("an unknown kind has a name")
	}
	var h *hostCalls
	if h.servedKinds() != nil {
		t.Fatal("a helper with no host calls serves kinds")
	}
}

// TestHostsRefusalMakesNoGroup: a request the kind's own checks refuse (a
// WASM cache up the tree, a setting off the list) leaves no group behind:
// the kind checks before the helper makes anything.
func TestHostsRefusalMakesNoGroup(t *testing.T) {
	r, kernel, l := hostsRig(t)
	l.fail["command"] = badRequest("root helper: refused by the kind")
	if _, err := hostClient(r).SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: workerd, Id: "g"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("spawn = %v", err)
	}
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	if len(kernel.groups) != 0 || len(kernel.started) != 0 {
		t.Fatalf("a refused request made groups %v, started %v", kernel.groups, kernel.started)
	}
}
