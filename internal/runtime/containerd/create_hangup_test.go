package containerd

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/errdefs"

	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A create's client can hang up while the create is still in containerd: an
// SDK whose request timed out, a proxy that closed the connection. That
// cancels the create's context, and the create stops at its next containerd
// call. The failed create must still undo itself, or its container outlives
// it under the sandbox ID, and the client's retry, which an Idempotency-Key
// create sends under the same ID, meets it as AlreadyExists: the service
// answers 409 "sandbox already exists" (UC-450).

// hangUpPoint is the step a create is in when its client hangs up.
type hangUpPoint string

const (
	// hangUpInNewContainer is inside NewContainer, after cntr.WithNewSnapshot
	// prepared the snapshot and before the container was written: the step
	// the UC-450 live run of 2026-11-08 hung up in ("create container:
	// context canceled").
	hangUpInNewContainer hangUpPoint = "new container"
	hangUpInNewTask      hangUpPoint = "new task"
	hangUpInStart        hangUpPoint = "task start"
	hangUpInReadiness    hangUpPoint = "readiness wait"
)

// hangUpHarness is a fake containerd for these tests. Its calls fail with the
// context's error once the context is done, as containerd's gRPC calls do; a
// container it deletes is gone, and one whose task was never deleted cannot
// be. So what a failed create leaves behind is still there for the next
// create of the same ID, as it is on a real node.
type hangUpHarness struct {
	d      *Driver
	tr     *fakeTransport
	at     hangUpPoint
	mu     sync.Mutex
	hangUp context.CancelFunc
	netns  map[string]bool // sandbox ID → holds a netns slot
	leases map[string]bool // live image leases
	// snapshots holds each prepared snapshot by key. NewContainer prepares a
	// container's snapshot under the container's own ID before it writes the
	// container, and deleting the container with WithSnapshotCleanup removes it.
	snapshots map[string]bool
}

func newHangUpHarness(t *testing.T, at hangUpPoint) *hangUpHarness {
	t.Helper()
	stubToolboxProbe(t)
	h := &hangUpHarness{at: at, tr: newFakeTransport(), netns: map[string]bool{}, leases: map[string]bool{}, snapshots: map[string]bool{}}
	h.tr.image = digestImage()
	h.tr.newContainerFn = h.newContainer

	origProbe := pollToolboxHealthFn
	pollToolboxHealthFn = func(ctx context.Context, _ string, _ int) error {
		if h.fire(hangUpInReadiness) {
			return ctx.Err()
		}
		return nil
	}
	origLeases := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return hangUpLeases{h} }
	origSnapshots := snapshotsFn
	snapshotsFn = func(*Client) snapshotRemover { return hangUpSnapshots{h} }
	t.Cleanup(func() {
		pollToolboxHealthFn = origProbe
		leasesServiceFn = origLeases
		snapshotsFn = origSnapshots
	})

	h.d = newTestDriver(t)
	h.d.SetClient(NewTestClient("aerolvm", h.tr))
	h.d.SetNetnsHandoff(hangUpNetns{h})
	return h
}

// arm makes the next create's client hang up, with cancel, at h.at.
func (h *hangUpHarness) arm(cancel context.CancelFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hangUp = cancel
}

// fire hangs the armed client up if the create has reached p, once.
func (h *hangUpHarness) fire(p hangUpPoint) bool {
	h.mu.Lock()
	cancel := h.hangUp
	if p != h.at || cancel == nil {
		h.mu.Unlock()
		return false
	}
	h.hangUp = nil
	h.mu.Unlock()
	cancel()
	return true
}

func (h *hangUpHarness) hasContainer(id string) bool {
	h.tr.mu.Lock()
	defer h.tr.mu.Unlock()
	_, ok := h.tr.containers[id]
	return ok
}

func (h *hangUpHarness) holdsNetns(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.netns[id]
}

func (h *hangUpHarness) liveLeases() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.leases)
}

func (h *hangUpHarness) hasSnapshot(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshots[key]
}

// prepareSnapshot is cntr.WithNewSnapshot's Prepare: false (AlreadyExists)
// when a snapshot holds the key.
func (h *hangUpHarness) prepareSnapshot(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.snapshots[key] {
		return false
	}
	h.snapshots[key] = true
	return true
}

// newContainer is containerd's NewContainer: the snapshot first, under the
// container's ID, then the container. A client that hangs up in between
// leaves the snapshot and no container, as containerd does: the call's own
// lease, which pins the snapshot, is deleted on the cancelled context too.
func (h *hangUpHarness) newContainer(ctx context.Context, id string, _ ...cntr.NewContainerOpts) (cntr.Container, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !h.prepareSnapshot(id) {
		return nil, errdefs.ErrAlreadyExists
	}
	if h.fire(hangUpInNewContainer) {
		return nil, ctx.Err()
	}
	h.tr.mu.Lock()
	defer h.tr.mu.Unlock()
	if _, ok := h.tr.containers[id]; ok {
		return nil, errdefs.ErrAlreadyExists
	}
	c := &hangUpContainer{fakeContainer: &fakeContainer{id: id}, h: h}
	h.tr.containers[id] = c.fakeContainer
	return c, nil
}

type hangUpContainer struct {
	*fakeContainer
	h    *hangUpHarness
	task *hangUpTask
}

func (c *hangUpContainer) NewTask(ctx context.Context, ioc cio.Creator, opts ...cntr.NewTaskOpts) (cntr.Task, error) {
	if c.h.fire(hangUpInNewTask) {
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	task, err := c.fakeContainer.NewTask(ctx, ioc, opts...)
	if err != nil {
		return nil, err
	}
	c.task = &hangUpTask{fakeTask: task.(*fakeTask), h: c.h}
	return c.task, nil
}

func (c *hangUpContainer) Delete(ctx context.Context, _ ...cntr.DeleteOpts) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.task != nil && !c.task.deleted {
		return errdefs.ErrFailedPrecondition
	}
	c.h.tr.mu.Lock()
	delete(c.h.tr.containers, c.id)
	c.h.tr.mu.Unlock()
	// The driver deletes with WithSnapshotCleanup: the snapshot goes too.
	c.h.mu.Lock()
	delete(c.h.snapshots, c.id)
	c.h.mu.Unlock()
	return nil
}

type hangUpTask struct {
	*fakeTask
	h       *hangUpHarness
	deleted bool
}

func (t *hangUpTask) Start(ctx context.Context) error {
	if t.h.fire(hangUpInStart) {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.fakeTask.Start(ctx)
}

func (t *hangUpTask) Kill(ctx context.Context, sig syscall.Signal, opts ...cntr.KillOpts) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.fakeTask.Kill(ctx, sig, opts...)
}

func (t *hangUpTask) Delete(ctx context.Context, opts ...cntr.ProcessDeleteOpts) (*cntr.ExitStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.deleted = true
	return t.fakeTask.Delete(ctx, opts...)
}

type hangUpNetns struct{ h *hangUpHarness }

func (n hangUpNetns) Provision(ctx context.Context, id string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	n.h.mu.Lock()
	defer n.h.mu.Unlock()
	n.h.netns[id] = true
	return "/run/netns/" + id, "10.88.0.9", nil
}

func (n hangUpNetns) Release(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.h.mu.Lock()
	defer n.h.mu.Unlock()
	delete(n.h.netns, id)
	return nil
}

func (hangUpNetns) ReassignOwner(context.Context, string, string) error { return nil }

type hangUpLeases struct{ h *hangUpHarness }

func (l hangUpLeases) Create(ctx context.Context, opts ...leases.Opt) (leases.Lease, error) {
	if err := ctx.Err(); err != nil {
		return leases.Lease{}, err
	}
	var lease leases.Lease
	for _, opt := range opts {
		_ = opt(&lease)
	}
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	l.h.leases[lease.ID] = true
	return lease, nil
}

func (l hangUpLeases) Delete(ctx context.Context, lease leases.Lease, _ ...leases.DeleteOpt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	delete(l.h.leases, lease.ID)
	return nil
}

func (hangUpLeases) AddResource(ctx context.Context, _ leases.Lease, _ leases.Resource) error {
	return ctx.Err()
}

// hangUpSnapshots is the default snapshotter. Like containerd's, its Remove
// does not look at containers: the driver checks for one first.
type hangUpSnapshots struct{ h *hangUpHarness }

func (s hangUpSnapshots) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	if !s.h.snapshots[key] {
		return errdefs.ErrNotFound
	}
	delete(s.h.snapshots, key)
	return nil
}

// TestUndoContextOutlivesTheRequestWithinItsBudget pins what the undo of a
// failed create runs on: not cancelled with the request, still carrying the
// request's values (the address observer), and bounded.
func TestUndoContextOutlivesTheRequestWithinItsBudget(t *testing.T) {
	type key struct{}
	req, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "observer"))
	cancel()
	undo, release := undoContext(req)
	defer release()
	if err := undo.Err(); err != nil {
		t.Fatalf("undo context done with the request: %v", err)
	}
	if undo.Value(key{}) != "observer" {
		t.Fatal("undo context lost the request's values")
	}
	deadline, ok := undo.Deadline()
	if !ok || time.Until(deadline) > createUndoTimeout {
		t.Fatalf("undo deadline = %v (set=%v), want within %v", deadline, ok, createUndoTimeout)
	}
}

// TestCreateClientHangUpUndoesSoTheRetryCreates is the UC-450 regression. A
// create whose client hangs up mid-create fails, and must leave nothing under
// its sandbox ID: no container, no snapshot (even one NewContainer prepared
// for a container it never wrote), no netns slot, no image lease. Then the
// retry of the same ID creates the sandbox instead of failing with
// ErrSandboxContainerExists.
func TestCreateClientHangUpUndoesSoTheRetryCreates(t *testing.T) {
	const id = "sb-uc450"
	req := models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}}
	for _, at := range []hangUpPoint{hangUpInNewContainer, hangUpInNewTask, hangUpInStart, hangUpInReadiness} {
		t.Run(string(at), func(t *testing.T) {
			h := newHangUpHarness(t, at)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.arm(cancel)
			if _, err := h.d.Create(ctx, req, id, "tok", nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("create the client hung up on: err = %v, want context.Canceled", err)
			}
			if h.hasContainer(id) {
				t.Errorf("the failed create left its container %s behind", id)
			}
			if h.hasSnapshot(id) {
				t.Errorf("the failed create left its snapshot %s behind", id)
			}
			if h.holdsNetns(id) {
				t.Errorf("the failed create kept its netns slot")
			}
			if n := h.liveLeases(); n != 0 {
				t.Errorf("the failed create kept %d image lease(s)", n)
			}

			state, err := h.d.Create(context.Background(), req, id, "tok", nil)
			if errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
				t.Fatalf("retry of %s after the client hung up met the failed create's container: %v (the service answers this 409 %q), want the sandbox",
					id, err, models.ErrSandboxExists)
			}
			if err != nil {
				t.Fatalf("retry of %s after the client hung up: %v, want the sandbox", id, err)
			}
			if state.SandboxID != id {
				t.Fatalf("retry made %q, want %q", state.SandboxID, id)
			}
			if !h.hasContainer(id) || h.liveLeases() != 1 {
				t.Fatalf("retry: container=%v leases=%d, want its container and its one lease", h.hasContainer(id), h.liveLeases())
			}
		})
	}
}

// TestDestroyRemovesTheSnapshotOfAMissingContainer: Destroy of an ID with no
// container still removes the snapshot named after it. That is the leftover
// a create cancelled inside NewContainer leaves when containerd prepares the
// snapshot after the create's undo has looked, and the service's leftover
// removal (create_leftover.go) relies on Destroy to clear it before it
// creates the ID again. It used to find no container, return nil, and leave
// the snapshot for the second create to meet as AlreadyExists (UC-450 live,
// 2026-11-08).
func TestDestroyRemovesTheSnapshotOfAMissingContainer(t *testing.T) {
	const id = "sb-uc450"
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name         string
		snapshot     bool
		ctx          context.Context
		wantErr      error
		wantSnapshot bool
	}{
		{name: "snapshot without its container is removed", snapshot: true, ctx: context.Background()},
		{name: "nothing under the id is already gone", ctx: context.Background()},
		{name: "a failed removal is reported and keeps the snapshot", snapshot: true, ctx: cancelled, wantErr: context.Canceled, wantSnapshot: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHangUpHarness(t, "")
			h.snapshots[id] = tc.snapshot
			err := h.d.Destroy(tc.ctx, &models.Sandbox{ID: id, ContainerID: id})
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("Destroy = %v, want %v", err, tc.wantErr)
			}
			if got := h.hasSnapshot(id); got != tc.wantSnapshot {
				t.Fatalf("snapshot after Destroy = %v, want %v", got, tc.wantSnapshot)
			}
			if tc.wantSnapshot {
				return
			}
			req := models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}}
			if _, err := h.d.Create(context.Background(), req, id, "tok", nil); err != nil {
				t.Fatalf("create of %s after Destroy: %v", id, err)
			}
		})
	}
}

// TestCreateUndoRemovesOnlyAnOrphanSnapshot pins the guard on the failed
// create's snapshot removal: it removes the snapshot named after the sandbox
// ID only when containerd says no container holds the ID. A container's
// snapshot is its rootfs, and containerd's Remove does not check for one.
func TestCreateUndoRemovesOnlyAnOrphanSnapshot(t *testing.T) {
	const id = "sb-uc450"
	req := models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}}
	cases := []struct {
		name         string
		container    bool  // a container holds the ID
		loadErr      error // containerd cannot answer for the ID
		wantSnapshot bool
	}{
		{name: "no container: the snapshot goes"},
		{name: "a container holds the id: its snapshot stays", container: true, wantSnapshot: true},
		{name: "containerd cannot say: the snapshot stays", loadErr: errors.New("connection refused"), wantSnapshot: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHangUpHarness(t, "")
			h.snapshots[id] = true
			if tc.container {
				h.tr.containers[id] = &fakeContainer{id: id}
			}
			if tc.loadErr != nil {
				h.tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) { return nil, tc.loadErr }
			}
			// A NewContainer that fails for a reason other than AlreadyExists.
			h.tr.newContainerFn = func(context.Context, string, ...cntr.NewContainerOpts) (cntr.Container, error) {
				return nil, errors.New("transport is closing")
			}
			_, err := h.d.Create(context.Background(), req, id, "tok", nil)
			if err == nil || errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
				t.Fatalf("create = %v, want the NewContainer failure", err)
			}
			if got := h.hasSnapshot(id); got != tc.wantSnapshot {
				t.Fatalf("snapshot after the failed create = %v, want %v", got, tc.wantSnapshot)
			}
			if tc.container && !h.hasContainer(id) {
				t.Fatal("the failed create removed a container it never made")
			}
		})
	}
}
