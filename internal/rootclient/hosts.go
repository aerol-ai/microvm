package rootclient

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// The host-process calls (M1 PR 9): in privilege mode split the helper
// starts the V8 group hosts (and WASM hosts) that sandboxd starts as root
// in single mode, and holds them. sandboxd names a host by kind and id and
// holds what the helper started as a HostProcess.

// PrepareHost has the helper make what a host needs before it starts (a V8
// group's jail) and answers its run folder.
func (c *Client) PrepareHost(ctx context.Context, kind rootdpb.HostKind, id string) (string, error) {
	if err := c.requireHost(ctx, rootdpb.FeaturePrepareHost, kind); err != nil {
		return "", err
	}
	resp, err := call(ctx, c, rootdpb.FeaturePrepareHost, &rootdpb.PrepareHostRequest{Kind: kind, Id: id}, rootdpb.RootHelperClient.PrepareHost)
	return resp.GetRunDir(), err
}

// SpawnHost has the helper make sure a host runs.
func (c *Client) SpawnHost(ctx context.Context, req *rootdpb.SpawnHostRequest) (*rootdpb.SpawnHostResponse, error) {
	if err := c.requireHost(ctx, rootdpb.FeatureSpawnHost, req.GetKind()); err != nil {
		return nil, err
	}
	return call(ctx, c, rootdpb.FeatureSpawnHost, req, rootdpb.RootHelperClient.SpawnHost)
}

// StopHost has the helper make sure a host is gone, and says whether there
// was anything to stop.
func (c *Client) StopHost(ctx context.Context, kind rootdpb.HostKind, id string) (bool, error) {
	if err := c.requireHost(ctx, rootdpb.FeatureStopHost, kind); err != nil {
		return false, err
	}
	resp, err := call(ctx, c, rootdpb.FeatureStopHost, &rootdpb.StopHostRequest{Kind: kind, Id: id}, rootdpb.RootHelperClient.StopHost)
	if err == nil {
		c.hosts.gone(kind, id)
	}
	return resp.GetHad(), err
}

// ListHosts lists a kind's hosts (UNSPECIFIED: every kind the helper
// serves): those that run, and those left behind with no process (Pid 0).
func (c *Client) ListHosts(ctx context.Context, kind rootdpb.HostKind) ([]*rootdpb.RunningHost, error) {
	feature := rootdpb.FeatureListHosts
	var err error
	if kind == rootdpb.HostKind_HOST_KIND_UNSPECIFIED {
		err = c.Require(ctx, feature)
	} else {
		err = c.requireHost(ctx, feature, kind)
	}
	if err != nil {
		return nil, err
	}
	resp, err := call(ctx, c, feature, &rootdpb.ListHostsRequest{Kind: kind}, rootdpb.RootHelperClient.ListHosts)
	return resp.GetHosts(), err
}

// SetHostLimits changes a running host's limits.
func (c *Client) SetHostLimits(ctx context.Context, kind rootdpb.HostKind, id string, l *rootdpb.HostLimits) error {
	if err := c.requireHost(ctx, rootdpb.FeatureSetHostLimits, kind); err != nil {
		return err
	}
	_, err := call(ctx, c, rootdpb.FeatureSetHostLimits, &rootdpb.SetHostLimitsRequest{Kind: kind, Id: id, Limits: l}, rootdpb.RootHelperClient.SetHostLimits)
	return err
}

// HasHost says whether the helper serves host kind k, connecting first if
// needed.
func (c *Client) HasHost(ctx context.Context, k rootdpb.HostKind) (bool, error) {
	s, err := c.require(ctx, rootdpb.FeatureSpawnHost)
	if err != nil {
		return false, err
	}
	return s.info.HasHost(k), nil
}

// requireHost checks the helper serves feature and host kind k. A helper
// that lacks the kind is asked again once per connection, as require does
// for a call.
func (c *Client) requireHost(ctx context.Context, feature string, k rootdpb.HostKind) error {
	s, err := c.require(ctx, feature)
	if err != nil {
		return err
	}
	if s.info.HasHost(k) {
		return nil
	}
	if s.gen != c.dials.Load() || s.stale.Load() {
		if err := c.handshake(ctx, s); err != nil {
			return err
		}
		if s = c.sess.Load(); s != nil && s.info.HasHost(k) {
			return nil
		}
	}
	info, _ := c.Info()
	return &UnsupportedError{Feature: feature + "(" + rootdpb.HostKindName(k) + ")", Helper: info}
}

// HostProcess is a host the helper started, held by its kind, id, pid and
// start time. It is a hostproc.Process, so the runtimes hold it as they
// hold a process a previous sandboxd started, with two differences:
//
//   - Signal stops the host through the helper (StopHost): its processes
//     killed, its jail removed. sandboxd may not signal a process of
//     another user, and the runtimes only ever kill.
//   - Done closes once the helper no longer lists the host's process, or
//     once a StopHost for it succeeded. The client asks the helper every
//     Config.HostWatchInterval while it holds any host; sandboxd need not
//     see the host's pid at all (its own process namespace may differ).
type HostProcess struct {
	c     *Client
	kind  rootdpb.HostKind
	id    string
	pid   int
	ticks uint64

	done chan struct{}
	once sync.Once
}

// HoldHost holds a host the helper answered for (SpawnHost) or listed.
func (c *Client) HoldHost(kind rootdpb.HostKind, id string, pid int, ticks uint64) *HostProcess {
	p := &HostProcess{c: c, kind: kind, id: id, pid: pid, ticks: ticks, done: make(chan struct{})}
	c.hosts.add(c, p)
	return p
}

// OpenHost holds a running host when the helper lists it with this pid and
// start time, as hostproc.Open holds a process: a host that exited, or is
// another process now, is hostproc.ErrGone.
func (c *Client) OpenHost(ctx context.Context, kind rootdpb.HostKind, id string, pid int, ticks uint64) (*HostProcess, error) {
	hosts, err := c.ListHosts(ctx, kind)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.GetKind() == kind && h.GetId() == id && int(h.GetPid()) == pid && h.GetStartTicks() == ticks && pid > 0 {
			return c.HoldHost(kind, id, pid, ticks), nil
		}
	}
	return nil, fmt.Errorf("%s host %s pid %d: %w", rootdpb.HostKindName(kind), id, pid, hostproc.ErrGone)
}

// Pid is the host's process in the helper's view.
func (p *HostProcess) Pid() int { return p.pid }

// StartTicks is when the host's process started.
func (p *HostProcess) StartTicks() uint64 { return p.ticks }

// Signal stops the host through the helper, whatever the signal (the
// runtimes send only SIGTERM and SIGKILL, and both mean "end it"). A host
// already gone is ErrGone.
func (p *HostProcess) Signal(syscall.Signal) error {
	select {
	case <-p.done:
		return hostproc.ErrGone
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.c.netTimeout)
	defer cancel()
	if _, err := p.c.StopHost(ctx, p.kind, p.id); err != nil {
		return err
	}
	p.exited()
	return nil
}

// Done is closed once the host's process has exited.
func (p *HostProcess) Done() <-chan struct{} { return p.done }

// Close stops watching the host; the host itself keeps running.
func (p *HostProcess) Close() error {
	p.c.hosts.remove(p)
	return nil
}

func (p *HostProcess) exited() {
	p.once.Do(func() { close(p.done) })
	p.c.hosts.remove(p)
}

// DefaultHostWatchInterval is how often the client asks the helper which
// held hosts still run (Config.HostWatchInterval).
const DefaultHostWatchInterval = 500 * time.Millisecond

// hostWatch asks the helper, while the client holds any host, which of
// them still run, and closes Done of each that does not. One call a tick
// for every host, whatever their number; none when nothing is held.
type hostWatch struct {
	mu      sync.Mutex
	procs   map[*HostProcess]struct{}
	running bool
}

func (w *hostWatch) add(c *Client, p *HostProcess) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.procs == nil {
		w.procs = map[*HostProcess]struct{}{}
	}
	w.procs[p] = struct{}{}
	if !w.running {
		w.running = true
		go w.loop(c)
	}
}

func (w *hostWatch) remove(p *HostProcess) {
	w.mu.Lock()
	delete(w.procs, p)
	w.mu.Unlock()
}

// gone closes Done of every held process of a host StopHost removed.
func (w *hostWatch) gone(kind rootdpb.HostKind, id string) {
	w.mu.Lock()
	var hit []*HostProcess
	for p := range w.procs {
		if p.kind == kind && p.id == id {
			hit = append(hit, p)
		}
	}
	w.mu.Unlock()
	for _, p := range hit {
		p.exited()
	}
}

// loop ends when nothing is held or the client closed. The set it judges
// is taken before each call, so a host held after the helper read the
// kernel is never taken for gone; a call that fails judges nothing.
func (w *hostWatch) loop(c *Client) {
	for {
		time.Sleep(c.hostEvery)
		w.mu.Lock()
		if len(w.procs) == 0 || c.isClosed() {
			w.running = false
			w.mu.Unlock()
			return
		}
		held := make([]*HostProcess, 0, len(w.procs))
		for p := range w.procs {
			held = append(held, p)
		}
		w.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		hosts, err := c.ListHosts(ctx, rootdpb.HostKind_HOST_KIND_UNSPECIFIED)
		cancel()
		if err != nil {
			continue
		}
		type key struct {
			kind  rootdpb.HostKind
			id    string
			pid   int
			ticks uint64
		}
		alive := make(map[key]bool, len(hosts))
		for _, h := range hosts {
			if h.GetPid() > 0 {
				alive[key{h.GetKind(), h.GetId(), int(h.GetPid()), h.GetStartTicks()}] = true
			}
		}
		for _, p := range held {
			if !alive[key{p.kind, p.id, p.pid, p.ticks}] {
				p.exited()
			}
		}
	}
}
