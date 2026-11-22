package rootd

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/version"
)

// The host-process calls (M1 PR 9; plans/security-gaps-m1-m4.md §3.3
// "Host processes"): PrepareHost, SpawnHost, StopHost, ListHosts and
// SetHostLimits. In privilege mode single sandboxd starts its V8 group
// hosts (and WASM workers) as root and confines them itself; in split the
// helper does, as sandboxd would, from its own settings.
//
// Each host runs in a cgroup of its own, <parent>/<kind's group>/<id>
// (rootpolicy.HostGroup), outside the helper's own group, so it outlives
// the helper (a swap waits only for the helper's group to empty) and the
// agent. The kernel is the record: the helper keeps no table of hosts, and
// a helper that starts after a swap finds every host, and stops it, by its
// group alone. A process the helper started it also reaps.
//
// The agent names a host by kind and id (rootpolicy.CheckHostID). The
// binary, the user, every folder and the limits' bounds are the helper's.

// hostFeatures are the calls the helper lists when it serves a host kind.
var hostFeatures = []string{rootdpb.FeaturePrepareHost, rootdpb.FeatureSpawnHost, rootdpb.FeatureStopHost,
	rootdpb.FeatureListHosts, rootdpb.FeatureSetHostLimits}

// Refusal reasons of the host calls beyond the rules' own.
const (
	// ReasonHostKind: a kind this helper does not serve.
	ReasonHostKind = "host_kind"
)

// HostKernel does a host's kernel work: its cgroup and its processes. Groups
// are named relative to the helper's host-process cgroup parent
// (rootpolicy.HostGroup). Tests stand in a fake.
type HostKernel interface {
	// EnsureGroup makes group, and its kind's group above it, with the
	// cpu, memory and pids controllers on for the host's group.
	EnsureGroup(group string) error
	// SetLimits writes a group's limits.
	SetLimits(group string, l rootpolicy.HostLimits) error
	// Start starts cmd inside group, never anywhere else for an instant.
	Start(cmd *exec.Cmd, group string) error
	// Procs lists the processes in group; none, and no error, when the
	// group does not exist.
	Procs(group string) ([]int, error)
	// Kill kills every process in group and waits until it is empty.
	Kill(ctx context.Context, group string) error
	// RemoveGroup removes an empty group; a missing one is no error.
	RemoveGroup(group string) error
	// Groups lists the groups directly under parent.
	Groups(parent string) ([]string, error)
	// StartTicks is when pid started (hostproc.StartTicks).
	StartTicks(pid int) (uint64, error)
}

// hostLauncher is one kind's own part.
type hostLauncher interface {
	// prepare does PrepareHost's work, under the host's lock. running says
	// whether the host's group still holds a process.
	prepare(id string, running bool, req *rootdpb.PrepareHostRequest) (*rootdpb.PrepareHostResponse, error)
	// command builds the host's process. done runs once it has started,
	// or failed to (closing what the command was handed).
	command(ctx context.Context, id string, req *rootdpb.SpawnHostRequest) (cmd *exec.Cmd, done func(), err error)
	// socket is the socket the host serves, "" for a kind that serves none
	// the agent dials by an answer.
	socket(id string) string
	// limits bounds the limits a spawn or SetHostLimits asks for by the
	// kind's own settings; ok false: the kind takes none.
	limits(l rootpolicy.HostLimits) (rootpolicy.HostLimits, bool)
	// started waits, when the kind has a way to tell, until the started
	// host serves.
	started(ctx context.Context, cmd *exec.Cmd) error
	// teardown removes what prepare and command made, once the host's
	// processes are gone.
	teardown(id string) error
	// present lists the hosts whose leftovers the kind keeps outside their
	// groups (a V8 group's jail), so ListHosts names them for a sweep.
	present() ([]string, error)
}

// hostCalls serves the host calls; nil when the helper serves no kind.
type hostCalls struct {
	kernel   HostKernel
	locks    *keyedLocks
	log      *slog.Logger
	node     rootpolicy.Limits
	launcher map[rootpolicy.HostKind]hostLauncher

	// reaping counts the started processes whose Wait runs, for tests.
	reaping sync.WaitGroup
	// fence is the WASM worker user's fence; nil without WASM hosts.
	fence *wasmFence
}

// close stops what the host calls run in the background.
func (h *hostCalls) close() {
	if h != nil {
		h.fence.close()
	}
}

// firecracker is the Firecracker launcher, nil when the helper runs none.
func (h *hostCalls) firecracker() *firecrackerHosts {
	if h == nil {
		return nil
	}
	f, _ := h.launcher[rootpolicy.HostFirecracker].(*firecrackerHosts)
	return f
}

// hostKindOf maps the wire's kind onto the rules', "" for one this build
// does not know.
func hostKindOf(k rootdpb.HostKind) rootpolicy.HostKind {
	return rootpolicy.HostKind(rootdpb.HostKindName(k))
}

func hostKey(kind rootpolicy.HostKind, id string) string { return "host/" + string(kind) + "/" + id }

// servedKinds lists the kinds this helper serves, in rootdpb's order.
func (h *hostCalls) servedKinds() []string {
	if h == nil {
		return nil
	}
	var out []string
	for _, k := range rootdpb.HostKinds() {
		if _, ok := h.launcher[hostKindOf(k)]; ok {
			out = append(out, rootdpb.HostKindName(k))
		}
	}
	return out
}

// check refuses a kind this helper does not serve and an id the kind's rule
// refuses, and answers the kind's launcher.
func (h *hostCalls) check(k rootdpb.HostKind, id string) (rootpolicy.HostKind, hostLauncher, error) {
	kind := hostKindOf(k)
	l, ok := h.launcher[kind]
	if !ok {
		if kind == "" {
			return "", nil, &fileError{code: codes.InvalidArgument, reason: ReasonHostKind, msg: fmt.Sprintf("root helper: host kind %v is not one this helper knows", k)}
		}
		return "", nil, errSkew("root helper: this helper does not serve %s hosts; its settings do not name one", kind)
	}
	if err := rootpolicy.CheckHostID(kind, id); err != nil {
		return "", nil, refusedRule(codes.InvalidArgument, err)
	}
	return kind, l, nil
}

// limitsOf checks a request's limits against the node and bounds them by
// the kind's settings.
func (h *hostCalls) limitsOf(l hostLauncher, req *rootdpb.HostLimits) (rootpolicy.HostLimits, bool, error) {
	want := rootpolicy.HostLimits{CPUMillis: req.GetCpuMillis(), MemoryMB: req.GetMemoryMb(), Pids: req.GetPids()}
	if err := rootpolicy.CheckHostLimits(want, h.node); err != nil {
		return want, false, refusedRule(codes.InvalidArgument, err)
	}
	got, ok := l.limits(want)
	return got, ok, nil
}

// running answers the first process in a host's group, 0 when it holds
// none. A pid is at most pid_max (2^22), so a number past MaxInt32 in
// cgroup.procs is not one and is skipped; the bound also lets the wire's
// uint32 take it without a wrap.
func (h *hostCalls) running(group string) (pid uint32, ticks uint64, err error) {
	procs, err := h.kernel.Procs(group)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range procs {
		if p <= 0 || p > math.MaxInt32 {
			continue
		}
		if t, err := h.kernel.StartTicks(p); err == nil {
			return uint32(p), t, nil
		}
	}
	return 0, 0, nil
}

func (h *hostCalls) prepareHost(ctx context.Context, req *rootdpb.PrepareHostRequest) (*rootdpb.PrepareHostResponse, error) {
	kind, l, err := h.check(req.GetKind(), req.GetId())
	if err != nil {
		return nil, err
	}
	if req.GetFirecracker() != nil && kind != rootpolicy.HostFirecracker {
		return nil, badRequest("root helper: a Firecracker spec for a %s host", kind)
	}
	unlock, err := h.locks.lock(ctx, hostKey(kind, req.GetId()))
	if err != nil {
		return nil, err
	}
	defer unlock()
	pid, _, err := h.running(rootpolicy.HostGroup(kind, req.GetId()))
	if err != nil {
		return nil, err
	}
	return l.prepare(req.GetId(), pid > 0, req)
}

func (h *hostCalls) spawnHost(ctx context.Context, req *rootdpb.SpawnHostRequest) (*rootdpb.SpawnHostResponse, error) {
	kind, l, err := h.check(req.GetKind(), req.GetId())
	if err != nil {
		return nil, err
	}
	limits, hasLimits, err := h.limitsOf(l, req.GetLimits())
	if err != nil {
		return nil, err
	}
	if !hasLimits && req.GetLimits() != nil {
		return nil, badRequest("root helper: %s hosts take no limits", kind)
	}
	if req.GetWasm() != nil && kind != rootpolicy.HostWasmWorker && kind != rootpolicy.HostWasmResident {
		return nil, badRequest("root helper: a WASM spec for a %s host", kind)
	}
	id := req.GetId()
	unlock, err := h.locks.lock(ctx, hostKey(kind, id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	group := rootpolicy.HostGroup(kind, id)
	if pid, ticks, err := h.running(group); err != nil {
		return nil, err
	} else if pid > 0 {
		return &rootdpb.SpawnHostResponse{Pid: pid, StartTicks: ticks, Already: true, Socket: l.socket(id)}, nil
	}
	// The kind's own checks come first, so a refused request leaves no
	// group behind.
	cmd, done, err := l.command(ctx, id, req)
	if err != nil {
		return nil, err
	}
	// started also lets go of what command kept for it (a ready pipe).
	release := func() { done(); _ = l.started(ctx, cmd) }
	if err := h.kernel.EnsureGroup(group); err != nil {
		release()
		return nil, fmt.Errorf("root helper: host group %s: %w", group, err)
	}
	if hasLimits {
		if err := h.kernel.SetLimits(group, limits); err != nil {
			release()
			return nil, fmt.Errorf("root helper: host group %s: limits: %w", group, err)
		}
	}
	err = h.kernel.Start(cmd, group)
	done()
	if err != nil {
		_ = l.started(ctx, cmd)
		return nil, fmt.Errorf("root helper: start %s host %s: %w", kind, id, err)
	}
	h.reaping.Add(1)
	go func() {
		defer h.reaping.Done()
		// The helper started it, so the helper reaps it; a later helper
		// has it reaped by whoever inherits it.
		_ = cmd.Wait()
	}()
	pid := cmd.Process.Pid
	ticks, err := h.kernel.StartTicks(pid)
	if err != nil {
		return nil, fmt.Errorf("root helper: %s host %s exited as it started: %w", kind, id, err)
	}
	if err := l.started(ctx, cmd); err != nil {
		_ = h.kernel.Kill(context.WithoutCancel(ctx), group)
		return nil, err
	}
	h.log.Info("root helper: host started", "kind", kind, "id", id, "pid", pid)
	return &rootdpb.SpawnHostResponse{Pid: uint32(pid), StartTicks: ticks, Socket: l.socket(id)}, nil
}

func (h *hostCalls) stopHost(ctx context.Context, req *rootdpb.StopHostRequest) (*rootdpb.StopHostResponse, error) {
	kind, l, err := h.check(req.GetKind(), req.GetId())
	if err != nil {
		return nil, err
	}
	unlock, err := h.locks.lock(ctx, hostKey(kind, req.GetId()))
	if err != nil {
		return nil, err
	}
	defer unlock()
	group := rootpolicy.HostGroup(kind, req.GetId())
	procs, err := h.kernel.Procs(group)
	if err != nil {
		return nil, err
	}
	had := len(procs) > 0
	if had {
		if err := h.kernel.Kill(ctx, group); err != nil {
			return nil, fmt.Errorf("root helper: stop %s host %s: %w", kind, req.GetId(), err)
		}
	}
	if err := l.teardown(req.GetId()); err != nil {
		return nil, fmt.Errorf("root helper: stop %s host %s: %w", kind, req.GetId(), err)
	}
	groups, err := h.kernel.Groups(path.Dir(group))
	if err != nil {
		return nil, err
	}
	if slices.Contains(groups, path.Base(group)) {
		had = true
		if err := h.kernel.RemoveGroup(group); err != nil {
			return nil, fmt.Errorf("root helper: stop %s host %s: remove its group: %w", kind, req.GetId(), err)
		}
	}
	return &rootdpb.StopHostResponse{Had: had}, nil
}

// kindGroups are the groups each kind's hosts sit in.
var kindGroups = map[rootpolicy.HostKind]string{
	rootpolicy.HostWorkerd:      rootpolicy.WorkerdHostsGroup,
	rootpolicy.HostWasmWorker:   rootpolicy.WasmHostsGroup,
	rootpolicy.HostWasmResident: rootpolicy.WasmHostsGroup,
	rootpolicy.HostFirecracker:  rootpolicy.FirecrackerHostsGroup,
}

func (h *hostCalls) listHosts(req *rootdpb.ListHostsRequest) (*rootdpb.ListHostsResponse, error) {
	want := hostKindOf(req.GetKind())
	if req.GetKind() != rootdpb.HostKind_HOST_KIND_UNSPECIFIED {
		if _, ok := h.launcher[want]; !ok {
			if want == "" {
				return nil, &fileError{code: codes.InvalidArgument, reason: ReasonHostKind, msg: fmt.Sprintf("root helper: host kind %v is not one this helper knows", req.GetKind())}
			}
			return nil, errSkew("root helper: this helper does not serve %s hosts", want)
		}
	}
	// Every host the helper holds anything for: a group under its kind's,
	// and what a kind keeps besides (a V8 group's jail), each once.
	type host struct {
		kind rootpolicy.HostKind
		id   string
	}
	var hosts []host
	seen := map[host]bool{}
	note := func(k rootpolicy.HostKind, id string) {
		if hk := (host{k, id}); !seen[hk] && (want == "" || k == want) && rootpolicy.CheckHostID(k, id) == nil {
			seen[hk] = true
			hosts = append(hosts, hk)
		}
	}
	read := map[string]bool{}
	for _, k := range rootdpb.HostKinds() {
		kind := hostKindOf(k)
		l, ok := h.launcher[kind]
		if !ok || (want != "" && kind != want) {
			continue
		}
		if parent := kindGroups[kind]; !read[parent] {
			read[parent] = true
			names, err := h.kernel.Groups(parent)
			if err != nil {
				return nil, err
			}
			for _, n := range names {
				if gk, id, ok := rootpolicy.HostOfGroup(parent + "/" + n); ok {
					if _, served := h.launcher[gk]; served {
						note(gk, id)
					}
				}
			}
		}
		ids, err := l.present()
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			note(kind, id)
		}
	}
	resp := &rootdpb.ListHostsResponse{}
	for _, hk := range hosts {
		pid, ticks, err := h.running(rootpolicy.HostGroup(hk.kind, hk.id))
		if err != nil {
			return nil, err
		}
		resp.Hosts = append(resp.Hosts, &rootdpb.RunningHost{Kind: kindOfName(hk.kind), Id: hk.id, Pid: pid, StartTicks: ticks})
	}
	return resp, nil
}

// kindOfName maps the rules' kind onto the wire's.
func kindOfName(k rootpolicy.HostKind) rootdpb.HostKind {
	for _, w := range rootdpb.HostKinds() {
		if rootdpb.HostKindName(w) == string(k) {
			return w
		}
	}
	return rootdpb.HostKind_HOST_KIND_UNSPECIFIED
}

func (h *hostCalls) setHostLimits(ctx context.Context, req *rootdpb.SetHostLimitsRequest) (*rootdpb.SetHostLimitsResponse, error) {
	kind, l, err := h.check(req.GetKind(), req.GetId())
	if err != nil {
		return nil, err
	}
	limits, ok, err := h.limitsOf(l, req.GetLimits())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, badRequest("root helper: %s hosts take no limits", kind)
	}
	unlock, err := h.locks.lock(ctx, hostKey(kind, req.GetId()))
	if err != nil {
		return nil, err
	}
	defer unlock()
	group := rootpolicy.HostGroup(kind, req.GetId())
	if pid, _, err := h.running(group); err != nil {
		return nil, err
	} else if pid == 0 {
		return nil, &fileError{code: codes.NotFound, msg: fmt.Sprintf("root helper: %s host %s does not run", kind, req.GetId())}
	}
	if err := h.kernel.SetLimits(group, limits); err != nil {
		return nil, fmt.Errorf("root helper: %s host %s: limits: %w", kind, req.GetId(), err)
	}
	return &rootdpb.SetHostLimitsResponse{}, nil
}

// hostLog opens the file host processes write to: appended, 0600, in a
// folder of the helper's. Never the helper's own output, which a host
// would keep after the helper exits.
func hostLog(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

// newHostCalls is the host calls of a helper whose settings name a host
// kind; nil otherwise.
func newHostCalls(cfg Config, opts Options, locks *keyedLocks, log *slog.Logger) *hostCalls {
	if !cfg.Hosts.any() {
		return nil
	}
	kernel := opts.HostKernel
	if kernel == nil {
		root := defaultCgroupRoot
		if opts.CgroupRoot != "" {
			root = opts.CgroupRoot
		}
		kernel = cgroupHostKernel{root: filepath.Join(root, filepath.FromSlash(cfg.Hosts.CgroupParent))}
	}
	h := &hostCalls{kernel: kernel, locks: locks, log: log, node: cfg.Policy.Limits, launcher: map[rootpolicy.HostKind]hostLauncher{}}
	if w := cfg.Hosts.Workerd; w != nil {
		h.launcher[rootpolicy.HostWorkerd] = newWorkerdHosts(w, cfg.Hosts.LogPath)
	}
	if w := cfg.Hosts.Wasm; w != nil {
		be := opts.WorkerFence
		if be == nil {
			be = workerfence.NewBackend()
		}
		h.fence = newWasmFence(w, be, log)
		h.launcher[rootpolicy.HostWasmWorker] = newWasmHosts(w, rootpolicy.HostWasmWorker, h.fence, cfg.Hosts.LogPath)
		h.launcher[rootpolicy.HostWasmResident] = newWasmHosts(w, rootpolicy.HostWasmResident, h.fence, cfg.Hosts.LogPath)
	}
	if fc := cfg.Hosts.Firecracker; fc != nil {
		h.launcher[rootpolicy.HostFirecracker] = newFirecrackerHosts(fc, cfg.Hosts.LogPath, cfg.SocketGID)
	}
	for kind, l := range opts.hostLaunchers {
		h.launcher[kind] = l
	}
	return h
}

// noHosts answers a host call on a helper that serves no host kind, as one
// it lacks, which is what Version told the agent.
func noHosts(call string) error {
	return status.Errorf(codes.Unimplemented, "root helper %s: %s needs a host kind this helper's settings do not name", version.Version, call)
}
