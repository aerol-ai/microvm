package rootclient

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// hostsHelper serves the host calls for the kinds it lists, from a table of
// running hosts a test changes.
type hostsHelper struct {
	rootdpb.UnimplementedRootHelperServer
	kinds []string

	mu      sync.Mutex
	running map[string]*rootdpb.RunningHost // by id
	calls   []string
	stopErr error
	lists   int
}

func newHostsHelper(kinds ...string) *hostsHelper {
	return &hostsHelper{kinds: kinds, running: map[string]*rootdpb.RunningHost{}}
}

func (h *hostsHelper) note(c string) {
	h.mu.Lock()
	h.calls = append(h.calls, c)
	h.mu.Unlock()
}

func (h *hostsHelper) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

func (h *hostsHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "n", Api: rootdpb.APIVersion, Features: rootdpb.Features(), Hosts: h.kinds}, nil
}

func (h *hostsHelper) PrepareHost(_ context.Context, req *rootdpb.PrepareHostRequest) (*rootdpb.PrepareHostResponse, error) {
	h.note("prepare " + req.GetId())
	return &rootdpb.PrepareHostResponse{RunDir: "/jail/" + req.GetId() + "/run"}, nil
}

func (h *hostsHelper) SpawnHost(_ context.Context, req *rootdpb.SpawnHostRequest) (*rootdpb.SpawnHostResponse, error) {
	h.note("spawn " + req.GetId())
	h.mu.Lock()
	defer h.mu.Unlock()
	r := &rootdpb.RunningHost{Kind: req.GetKind(), Id: req.GetId(), Pid: 100 + uint32(len(h.running)), StartTicks: 7}
	h.running[req.GetId()] = r
	return &rootdpb.SpawnHostResponse{Pid: r.GetPid(), StartTicks: r.GetStartTicks(), Socket: "/s/" + req.GetId()}, nil
}

func (h *hostsHelper) StopHost(_ context.Context, req *rootdpb.StopHostRequest) (*rootdpb.StopHostResponse, error) {
	h.note("stop " + req.GetId())
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopErr != nil {
		return nil, h.stopErr
	}
	_, had := h.running[req.GetId()]
	delete(h.running, req.GetId())
	return &rootdpb.StopHostResponse{Had: had}, nil
}

func (h *hostsHelper) ListHosts(_ context.Context, req *rootdpb.ListHostsRequest) (*rootdpb.ListHostsResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lists++
	resp := &rootdpb.ListHostsResponse{}
	for _, r := range h.running {
		if req.GetKind() == rootdpb.HostKind_HOST_KIND_UNSPECIFIED || r.GetKind() == req.GetKind() {
			resp.Hosts = append(resp.Hosts, r)
		}
	}
	// A leftover with no process: never alive, whatever its id.
	resp.Hosts = append(resp.Hosts, &rootdpb.RunningHost{Kind: rootdpb.HostKind_HOST_KIND_WORKERD, Id: "left"})
	return resp, nil
}

func (h *hostsHelper) SetHostLimits(_ context.Context, req *rootdpb.SetHostLimitsRequest) (*rootdpb.SetHostLimitsResponse, error) {
	h.note("limits " + req.GetId())
	return &rootdpb.SetHostLimitsResponse{}, nil
}

// gone drops a host from the table, as its process exiting would.
func (h *hostsHelper) gone(id string) {
	h.mu.Lock()
	delete(h.running, id)
	h.mu.Unlock()
}

// hostsClient is a client of h that watches its hosts every 10ms.
func hostsClient(t *testing.T, h *hostsHelper) *Client {
	t.Helper()
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid()), HostWatchInterval: 10 * time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

const workerdKind = rootdpb.HostKind_HOST_KIND_WORKERD

func TestHostCalls(t *testing.T) {
	h := newHostsHelper("workerd")
	c := hostsClient(t, h)
	ctx := ctxT(t)
	if ok, err := c.HasHost(ctx, workerdKind); err != nil || !ok {
		t.Fatalf("HasHost = %v, %v", ok, err)
	}
	if ok, _ := c.HasHost(ctx, rootdpb.HostKind_HOST_KIND_WASM_WORKER); ok {
		t.Fatal("an unlisted kind is served")
	}
	run, err := c.PrepareHost(ctx, workerdKind, "g")
	if err != nil || run != "/jail/g/run" {
		t.Fatalf("PrepareHost = %q, %v", run, err)
	}
	resp, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerdKind, Id: "g"})
	if err != nil || resp.GetPid() != 100 {
		t.Fatalf("SpawnHost = %v, %v", resp, err)
	}
	if err := c.SetHostLimits(ctx, workerdKind, "g", &rootdpb.HostLimits{MemoryMb: 1}); err != nil {
		t.Fatal(err)
	}
	hosts, err := c.ListHosts(ctx, workerdKind)
	if err != nil || len(hosts) != 2 {
		t.Fatalf("ListHosts = %v, %v", hosts, err)
	}
	had, err := c.StopHost(ctx, workerdKind, "g")
	if err != nil || !had {
		t.Fatalf("StopHost = %v, %v", had, err)
	}
	if got := h.seen(); !slices.Equal(got, []string{"prepare g", "spawn g", "limits g", "stop g"}) {
		t.Fatalf("calls %v", got)
	}
}

// TestHostKindTheHelperLacks: a kind the handshake did not list is refused
// before anything is sent, as a helper too old for it (503), never sent
// for the helper to refuse.
func TestHostKindTheHelperLacks(t *testing.T) {
	h := newHostsHelper("workerd")
	c := hostsClient(t, h)
	ctx := ctxT(t)
	wasm := rootdpb.HostKind_HOST_KIND_WASM_WORKER
	for name, call := range map[string]func() error{
		"PrepareHost": func() error { _, err := c.PrepareHost(ctx, wasm, "sb-1"); return err },
		"SpawnHost": func() error {
			_, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: wasm, Id: "sb-1"})
			return err
		},
		"StopHost":      func() error { _, err := c.StopHost(ctx, wasm, "sb-1"); return err },
		"ListHosts":     func() error { _, err := c.ListHosts(ctx, wasm); return err },
		"SetHostLimits": func() error { return c.SetHostLimits(ctx, wasm, "sb-1", nil) },
		"OpenHost":      func() error { _, err := c.OpenHost(ctx, wasm, "sb-1", 1, 1); return err },
	} {
		err := call()
		var ue *UnsupportedError
		if !errors.As(err, &ue) || !errors.Is(err, ErrUnsupported) || ue.Feature == "" {
			t.Errorf("%s: %v, want an UnsupportedError", name, err)
		}
	}
	if got := h.seen(); len(got) != 0 {
		t.Fatalf("a call for an unlisted kind was sent: %v", got)
	}
}

// TestHostProcessFollowsTheHelper: a held host's Done closes once the
// helper no longer lists its process, and at once after a stop through
// it; a kill is a stop through the helper, never a signal from the agent.
func TestHostProcessFollowsTheHelper(t *testing.T) {
	h := newHostsHelper("workerd")
	c := hostsClient(t, h)
	ctx := ctxT(t)
	resp, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerdKind, Id: "a"})
	if err != nil {
		t.Fatal(err)
	}
	a := c.HoldHost(workerdKind, "a", int(resp.GetPid()), resp.GetStartTicks())
	if a.Pid() != 100 || a.StartTicks() != 7 {
		t.Fatalf("held %d %d", a.Pid(), a.StartTicks())
	}
	var _ hostproc.Process = a
	select {
	case <-a.Done():
		t.Fatal("a running host was taken for gone")
	case <-time.After(50 * time.Millisecond):
	}
	// Its process exits: the watch sees it go.
	h.gone("a")
	select {
	case <-a.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a host that exited was never seen to")
	}
	if err := a.Signal(syscall.SIGKILL); !errors.Is(err, hostproc.ErrGone) {
		t.Fatalf("Signal of a gone host = %v", err)
	}

	// A kill stops it through the helper, and Done closes at once.
	resp, _ = c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerdKind, Id: "b"})
	b := c.HoldHost(workerdKind, "b", int(resp.GetPid()), resp.GetStartTicks())
	if err := b.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.Done():
	default:
		t.Fatal("Done still open after a stop")
	}
	if !slices.Contains(h.seen(), "stop b") {
		t.Fatalf("no stop through the helper: %v", h.seen())
	}
	// A stop that fails keeps the host held.
	resp, _ = c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerdKind, Id: "c"})
	cp := c.HoldHost(workerdKind, "c", int(resp.GetPid()), resp.GetStartTicks())
	h.mu.Lock()
	h.stopErr = status.Error(codes.Internal, "kill failed")
	h.mu.Unlock()
	if err := cp.Signal(syscall.SIGKILL); err == nil {
		t.Fatal("a failed stop was taken for a kill")
	}
	select {
	case <-cp.Done():
		t.Fatal("Done closed after a failed stop")
	default:
	}
	// Close stops the watch for it; the host keeps running.
	if err := cp.Close(); err != nil {
		t.Fatal(err)
	}
	h.gone("c")
	time.Sleep(50 * time.Millisecond)
	select {
	case <-cp.Done():
		t.Fatal("a released host is still watched")
	default:
	}
}

// TestHostWatchJudgesOnlyWhatItHeldBeforeTheCall: a host held after the
// helper's list was taken is never taken for gone by that list, and a
// list that fails judges nothing.
func TestHostWatchJudgesOnlyWhatItHeldBeforeTheCall(t *testing.T) {
	h := newHostsHelper("workerd")
	c := hostsClient(t, h)
	// Held but never listed: a host the helper has not reported yet is
	// gone by the next list, as its process is.
	p := c.HoldHost(workerdKind, "never", 9, 9)
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("an unlisted host stayed held")
	}
	// The watch stops once nothing is held, and starts again for the next.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.hosts.mu.Lock()
		running := c.hosts.running
		c.hosts.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the watch kept running with nothing held")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A helper that cannot be reached judges nothing.
	c2 := New(Config{Socket: "/nonexistent/root.sock", HelperUID: uint32(os.Getuid()), Timeout: 50 * time.Millisecond,
		HostWatchInterval: 10 * time.Millisecond})
	t.Cleanup(func() { _ = c2.Close() })
	q := c2.HoldHost(workerdKind, "q", 1, 1)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-q.Done():
		t.Fatal("a host was taken for gone on a failed list")
	default:
	}
	_ = q.Close()
}

func TestOpenHost(t *testing.T) {
	h := newHostsHelper("workerd")
	c := hostsClient(t, h)
	ctx := ctxT(t)
	resp, _ := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: workerdKind, Id: "g"})
	p, err := c.OpenHost(ctx, workerdKind, "g", int(resp.GetPid()), resp.GetStartTicks())
	if err != nil || p.Pid() != int(resp.GetPid()) {
		t.Fatalf("OpenHost = %v, %v", p, err)
	}
	_ = p.Close()
	// Another start time is another process: gone, as hostproc.Open says.
	for name, args := range map[string]struct {
		id    string
		pid   int
		ticks uint64
	}{
		"another start":    {"g", int(resp.GetPid()), 8},
		"another pid":      {"g", 1, 7},
		"a leftover":       {"left", 0, 0},
		"a host not there": {"none", 100, 7},
	} {
		if _, err := c.OpenHost(ctx, workerdKind, args.id, args.pid, args.ticks); !errors.Is(err, hostproc.ErrGone) {
			t.Errorf("%s: %v, want ErrGone", name, err)
		}
	}
}
