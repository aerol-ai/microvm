package containerd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/dialer"
	"google.golang.org/grpc"
)

// A Kubernetes worker's runtime container restarted (privilege mode single).
//
// The sandboxes' cgroup parent is a group inside the runtime container's own
// cgroup (internal/supervisor cgroup.go), and that cgroup is new each time
// the container starts. sandboxd, in the agent container, reads the parent
// once, at its own start (SB_CONTAINERD_CGROUP_PARENT, from the file the
// supervisor writes). After a restart of the runtime container alone, every
// new sandbox would name the old parent: runc makes that path again, outside
// the runtime container. The sandbox then escapes the memory cap that keeps
// the machinery's reserve (F10) and the supervisor's ownership-lease freeze,
// which looks only under the current parent (C19), and the next restart of
// the runtime container does not end it.
//
// Split mode learns of it from its root helper's handshake
// (rootclient.ParentMovedError). Single mode has no helper, so it reads the
// supervisor's file again on each new connection to containerd, once the
// connection is made: a new containerd means a new connection, and the
// supervisor writes the file before it starts containerd, so a connection
// that reached a new containerd always finds the new parent there. (Read
// before dialing instead, it could see the old one: containerd's dialer
// waits for a missing socket to appear.) When the file names another
// parent, the connection is closed unused, so nothing reaches the new
// containerd with the old parent, and sandboxd is told once
// (OnCgroupParentMoved). It then stops, and the kubelet starts it again,
// with the new parent.

// CgroupParentMovedError says the runtime container now names another
// cgroup parent than the one this sandboxd started with.
type CgroupParentMovedError struct {
	// File is where the runtime container publishes the parent.
	File string
	// Started is the parent this sandboxd puts sandboxes under; Now is the
	// one the file names.
	Started, Now string
}

func (e *CgroupParentMovedError) Error() string {
	return fmt.Sprintf("the runtime container puts sandboxes under cgroup %s now (%s), not under %s, where this sandboxd started: "+
		"it started again, and sandboxd must start again to follow it", e.Now, e.File, e.Started)
}

// cgroupParentWatch remembers the first move seen and tells its listener
// once, whichever comes first: the move, or the listener.
type cgroupParentWatch struct {
	mu       sync.Mutex
	moved    error
	notify   func(error)
	notified bool
}

// report records a move and tells the listener, if there is one yet.
func (w *cgroupParentWatch) report(err error) {
	w.mu.Lock()
	if w.moved == nil {
		w.moved = err
	}
	fire := w.take()
	w.mu.Unlock()
	fire()
}

// listen sets the listener, and tells it at once of a move already seen.
func (w *cgroupParentWatch) listen(fn func(error)) {
	w.mu.Lock()
	w.notify = fn
	fire := w.take()
	w.mu.Unlock()
	fire()
}

// take returns the one call owed to the listener, or a no-op. The caller
// holds mu and makes the call after releasing it.
func (w *cgroupParentWatch) take() func() {
	if w.moved == nil || w.notify == nil || w.notified {
		return func() {}
	}
	w.notified = true
	fn, err := w.notify, w.moved
	return func() { fn(err) }
}

// OnCgroupParentMoved sets what hears, once, that the runtime container
// names another cgroup parent (a *CgroupParentMovedError). A move seen
// before the call is told at once. Only privilege mode single with
// Config.CgroupParentFile set checks.
func (d *Driver) OnCgroupParentMoved(fn func(error)) { d.parentMoved.listen(fn) }

// readParentFileFn reads the runtime container's parent file; tests replace
// it.
var readParentFileFn = os.ReadFile

// checkCgroupParent says whether a new connection to containerd may be
// used: the file the runtime container writes at each start still names
// the parent this sandboxd started with. A file it cannot read, or an empty
// one, refuses the connection too: a sandbox must never go under a parent
// that cannot be confirmed. That is a retry, not a restart.
func (d *Driver) checkCgroupParent() error {
	file := d.cfg.CgroupParentFile
	raw, err := readParentFileFn(file)
	if err != nil {
		return fmt.Errorf("containerd: read the runtime container's cgroup parent from %s: %w", file, err)
	}
	now := strings.TrimSpace(string(raw))
	if now == "" {
		return fmt.Errorf("containerd: the runtime container's cgroup parent file %s is empty", file)
	}
	started := path.Clean(d.cfg.CgroupParent)
	if path.Clean(now) == started {
		return nil
	}
	moved := &CgroupParentMovedError{File: file, Started: started, Now: now}
	d.parentMoved.report(moved)
	return moved
}

// dialContainerdFn dials containerd's socket; tests replace it.
var dialContainerdFn = dialer.ContextDialer

// checkedDialer is containerd's own dialer, with check run on each
// connection it makes before the connection is handed over.
func checkedDialer(check func() error) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := dialContainerdFn(ctx, addr)
		if err != nil {
			return nil, err
		}
		if err := check(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// connectCheckedFn connects to containerd's own socket, as Connect does,
// through a dialer that runs check on every connection, the first and each
// one after containerd went away; tests replace it.
var connectCheckedFn = func(socket, namespace string, check func() error) (*Client, error) {
	return connectVia(socket, namespace, func(socket, ns string) (rawAPI, error) {
		raw, err := cntr.New(socket, cntr.WithDefaultNamespace(ns),
			cntr.WithExtraDialOpts([]grpc.DialOption{grpc.WithContextDialer(checkedDialer(check))}))
		if err != nil {
			return nil, err
		}
		return cntrClientRaw{raw}, nil
	})
}
