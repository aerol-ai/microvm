package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"

	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/hostproc"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// Host processes in privilege mode split (M1 PR 9): the root helper starts
// and holds the hosts sandboxd starts as root in single mode. This file is
// the runtimes' side of it: each adapter turns a runtime's own seam into
// the helper's host calls (*rootclient.Client).

// hostHelper is the helper's host calls (*rootclient.Client).
type hostHelper interface {
	PrepareHost(ctx context.Context, kind rootdpb.HostKind, id string) (string, error)
	SpawnHost(ctx context.Context, req *rootdpb.SpawnHostRequest) (*rootdpb.SpawnHostResponse, error)
	StopHost(ctx context.Context, kind rootdpb.HostKind, id string) (bool, error)
	ListHosts(ctx context.Context, kind rootdpb.HostKind) ([]*rootdpb.RunningHost, error)
	SetHostLimits(ctx context.Context, kind rootdpb.HostKind, id string, l *rootdpb.HostLimits) error
	HoldHost(kind rootdpb.HostKind, id string, pid int, ticks uint64) *rootclient.HostProcess
	OpenHost(ctx context.Context, kind rootdpb.HostKind, id string, pid int, ticks uint64) (*rootclient.HostProcess, error)
}

// mountLender is the helper's loan of a WASM sandbox's mount points
// (*rootclient.Client).
type mountLender interface {
	GrantWasmMounts(ctx context.Context, sandboxID string, kind rootdpb.HostKind, hostID string) (int, error)
}

// splitWorkerdLauncher is the V8-isolate driver's jail launcher in split
// mode (pkg/isolate JailLauncher): the helper builds each group's jail and
// runs its workerd; sandboxd keeps the group's servers and config in the
// run folder the helper makes for it.
type splitWorkerdLauncher struct{ h hostHelper }

const workerdKind = rootdpb.HostKind_HOST_KIND_WORKERD

func (l splitWorkerdLauncher) Prepare(ctx context.Context, group string) (string, error) {
	run, err := l.h.PrepareHost(ctx, workerdKind, group)
	if errors.Is(err, rootclient.ErrBusy) {
		// The helper keeps as many V8 jails as it may
		// (SB_ROOTD_ISOLATE_MAX_JAILS): the node is full for V8 groups, as
		// for a full slot pool, so the caller gets a capacity answer (503,
		// retry), not the client's text for a busy helper.
		msg := "the root helper keeps as many V8 jails as it may"
		var gs interface{ GRPCStatus() *status.Status }
		if errors.As(err, &gs) {
			msg = gs.GRPCStatus().Message()
		}
		return "", fmt.Errorf("%w: %s", capacity.NewSlotPoolExhausted("V8 jails"), msg)
	}
	return run, err
}

func (l splitWorkerdLauncher) Start(ctx context.Context, group string, lim pkgisolate.Limits) (hostproc.Process, error) {
	resp, err := l.h.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerdKind, Id: group, Limits: hostLimits(lim)})
	if err != nil {
		return nil, err
	}
	if resp.GetPid() == 0 {
		return nil, errors.New("root helper answered a V8 group host with no process")
	}
	return l.h.HoldHost(workerdKind, group, int(resp.GetPid()), resp.GetStartTicks()), nil
}

func (l splitWorkerdLauncher) SetLimits(ctx context.Context, group string, lim pkgisolate.Limits) error {
	return l.h.SetHostLimits(ctx, workerdKind, group, hostLimits(lim))
}

func (l splitWorkerdLauncher) Stop(ctx context.Context, group string) error {
	_, err := l.h.StopHost(ctx, workerdKind, group)
	return err
}

func (l splitWorkerdLauncher) Open(ctx context.Context, group string, pid int, ticks uint64) (hostproc.Process, error) {
	p, err := l.h.OpenHost(ctx, workerdKind, group, pid, ticks)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (l splitWorkerdLauncher) Groups(ctx context.Context) ([]string, error) {
	hosts, err := l.h.ListHosts(ctx, workerdKind)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.GetId())
	}
	return out, nil
}

// hostLimits is a V8 group's caps on the wire: CPU in thousandths, rounded
// up so a small cap never becomes none. A negative value, which the jail
// spec refuses, is no limit here too.
func hostLimits(l pkgisolate.Limits) *rootdpb.HostLimits {
	out := &rootdpb.HostLimits{}
	if l.CPU > 0 {
		out.CpuMillis = uint32(min(math.Ceil(l.CPU*1000), math.MaxUint32))
	}
	if l.MemoryMB > 0 {
		out.MemoryMb = uint64(l.MemoryMB)
	}
	if l.Pids > 0 {
		out.Pids = uint32(min(int64(l.Pids), math.MaxUint32))
	}
	return out
}

// splitWasmLauncher is a WASM supervisor's launcher in split mode
// (pkg/wasm/worker HostLauncher): the helper starts the worker or resident
// host as the worker user and holds it; sandboxd dials it on the socket
// the helper made for its group.
type splitWasmLauncher struct {
	h    hostHelper
	kind rootdpb.HostKind
	// cacheRoot is sandboxd's compile cache root: a worker's cache goes to
	// the helper by its name under it (wasmruntime.CacheName).
	cacheRoot string
}

// wasmWorkerEnv are the worker settings sandboxd computes at run time,
// which the helper takes from it (rootd wasmAgentEnv): none is a path.
var wasmWorkerEnv = []string{"SB_AUDIT_INGEST_PORT", "SB_EGRESS_ATTRIBUTION_ENABLED", "SB_NODE_ID",
	worker.ListenFallbackEnv, egresspolicy.NodePortsEnv, egresspolicy.BlockPrivateEnv, egresspolicy.DenyFloorEnv,
	egresspolicy.PrivateRangesEnv}

func (l splitWasmLauncher) Launch(ctx context.Context, key, socketPath, cacheDir string) (hostproc.Process, error) {
	spec := &rootdpb.WasmHostSpec{Cache: wasmruntime.CacheName(l.cacheRoot, cacheDir)}
	for _, name := range wasmWorkerEnv {
		if v := os.Getenv(name); v != "" {
			spec.Env = append(spec.Env, name+"="+v)
		}
	}
	resp, err := l.h.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: l.kind, Id: key, Wasm: spec})
	if err != nil {
		return nil, err
	}
	if resp.GetPid() == 0 {
		return nil, errors.New("root helper answered a WASM host with no process")
	}
	if resp.GetSocket() != socketPath {
		_, _ = l.h.StopHost(context.WithoutCancel(ctx), l.kind, key)
		return nil, fmt.Errorf("root helper serves WASM host %s on %s, this sandboxd dials %s: set the same SB_ROOTD_WASM_SOCKET_DIR for both",
			key, resp.GetSocket(), socketPath)
	}
	return l.h.HoldHost(l.kind, key, int(resp.GetPid()), resp.GetStartTicks()), nil
}

// splitMountLender has the helper lend a WASM sandbox's mount points to the
// host that serves it (GrantWasmMounts, M1 PR 15), which sandboxd names by
// the socket the helper serves it on in socketDir (worker.GrantPolicy
// Lend): sandboxd cannot reach the helper's mount points to pass them.
func splitMountLender(h mountLender, socketDir string) func(ctx context.Context, sandboxID, socket string) error {
	return func(ctx context.Context, sandboxID, socket string) error {
		kind, id, ok := rootpolicy.WasmHostOfSocket(socketDir, socket)
		if !ok {
			return fmt.Errorf("%s is not a socket the root helper serves a WASM host on (%s)", socket, socketDir)
		}
		wire := rootdpb.HostKind_HOST_KIND_WASM_WORKER
		if kind == rootpolicy.HostWasmResident {
			wire = rootdpb.HostKind_HOST_KIND_WASM_RESIDENT
		}
		_, err := h.GrantWasmMounts(ctx, sandboxID, wire, id)
		return err
	}
}

// splitSlotSocket is the socket of a WASM warm-pool slot's worker in split
// mode: a WASM worker host of the helper's, named by the slot's id, which
// the helper serves in socketDir (rootpolicy.WasmHostSocket).
func splitSlotSocket(socketDir string) func(slotID string) (string, error) {
	return func(slotID string) (string, error) {
		return rootpolicy.WasmHostSocket(socketDir, rootpolicy.HostWasmWorker, slotID)
	}
}

// splitWasmWorkers lists the WASM hosts the helper holds, for boot adoption
// (wasmruntime Driver.SetWorkerLister): each running one held, by the
// socket the helper serves it on. One whose process is gone is removed.
func splitWasmWorkers(h hostHelper, socketDir string, log *slog.Logger) func(context.Context) ([]worker.FoundWorker, error) {
	return func(ctx context.Context) ([]worker.FoundWorker, error) {
		hosts, err := h.ListHosts(ctx, rootdpb.HostKind_HOST_KIND_UNSPECIFIED)
		if err != nil {
			return nil, err
		}
		var out []worker.FoundWorker
		for _, host := range hosts {
			kind := host.GetKind()
			var rk rootpolicy.HostKind
			switch kind {
			case rootdpb.HostKind_HOST_KIND_WASM_WORKER:
				rk = rootpolicy.HostWasmWorker
			case rootdpb.HostKind_HOST_KIND_WASM_RESIDENT:
				rk = rootpolicy.HostWasmResident
			default:
				continue
			}
			if host.GetPid() == 0 {
				if _, err := h.StopHost(ctx, kind, host.GetId()); err != nil {
					log.Warn("wasm adopt: a stopped host's leftovers were not removed", "id", host.GetId(), "error", err)
				}
				continue
			}
			sock, err := rootpolicy.WasmHostSocket(socketDir, rk, host.GetId())
			if err != nil {
				continue
			}
			out = append(out, worker.FoundWorker{PID: int(host.GetPid()), Socket: sock, Resident: rk == rootpolicy.HostWasmResident,
				Proc: h.HoldHost(kind, host.GetId(), int(host.GetPid()), host.GetStartTicks())})
		}
		return out, nil
	}
}
