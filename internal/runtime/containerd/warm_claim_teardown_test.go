package containerd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

// teardownNetns writes the netns owner moves and releases into the rig's
// one ordered log, so a test reads them in order with the relabel, the
// rules and the delete.
type teardownNetns struct {
	harnessNetns
	rec func(format string, args ...any) error
	// backErr fails moving the owner back to the park; backHang makes
	// that write hang until its context ends.
	backErr  error
	backHang bool
}

func (n *teardownNetns) ReassignOwner(ctx context.Context, from, to string) error {
	_ = n.rec("owner %s>%s", from, to)
	if !IsParkedSandboxID(to) {
		return nil
	}
	if n.backHang {
		<-ctx.Done()
		return ctx.Err()
	}
	return n.backErr
}

func (n *teardownNetns) Release(_ context.Context, id string) error {
	return n.rec("release %s", id)
}

// teardownRig is a claim rig whose slot sits in a real pool, whose netns
// moves go to the ordered log, and whose transport answers a load as
// containerd does: an error once the call's context has ended, or busy
// while the test says so. It records the deadline of each load made
// after the create gave up.
type teardownRig struct {
	*claimRig
	netns    *teardownNetns
	pool     *containerdpool.Pool
	released []string
	busy     atomic.Bool

	mu        sync.Mutex
	deadlines []time.Duration
}

func newTeardownRig(t *testing.T, split bool) *teardownRig {
	t.Helper()
	r := &teardownRig{claimRig: newClaimRig(t, split), pool: containerdpool.New(nil)}
	r.netns = &teardownNetns{harnessNetns: harnessNetns{path: "/run/netns/sb", ip: claimIP}, rec: r.fw.rec}
	r.d.SetNetnsHandoff(r.netns)
	inner := r.c.onDelete
	r.c.onDelete = func() {
		_ = r.fw.rec("delete park-a")
		inner()
	}
	r.tr.loadContainerFn = func(ctx context.Context, id string) (cntr.Container, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			r.mu.Lock()
			r.deadlines = append(r.deadlines, time.Until(dl))
			r.mu.Unlock()
		}
		if r.busy.Load() {
			return nil, errors.New("containerd busy")
		}
		r.tr.mu.Lock()
		defer r.tr.mu.Unlock()
		if c, ok := r.tr.containers[id]; ok {
			return c, nil
		}
		return nil, errdefs.ErrNotFound
	}
	r.pool.SetSpawner(&PoolSpawner{Driver: r.d})
	r.pool.SetParkReleaser(func(id string) { r.released = append(r.released, id) })
	r.pool.NoteTarget(r.slot.Key)
	r.pool.RecordLoaded(r.slot)
	r.d.SetWarmPool(r.pool)
	return r
}

func (r *teardownRig) claim(ctx context.Context, t *testing.T) {
	t.Helper()
	_, err := r.d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
	if err == nil || !strings.Contains(err.Error(), "warm adopt failed") {
		t.Fatalf("claim err %v, want a failed claim", err)
	}
}

func (r *teardownRig) slotLeft() bool {
	r.tr.mu.Lock()
	defer r.tr.mu.Unlock()
	_, ok := r.tr.containers["park-a"]
	return ok
}

// TestFailedClaimTeardownOutlivesTheCreate: a client that hangs up mid-claim
// cancels the create's context. The failed claim's teardown still removes
// the slot, on a context of its own with a bound, in both modes and
// whichever step the hang-up broke. The netns owner goes back to the park
// before the delete, so the slot is freed under the park id; the
// reservation is released once, and nothing is left for the pool to retry.
func TestFailedClaimTeardownOutlivesTheCreate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		split bool
		// hangUp breaks the claim at one step, cancelling the create.
		hangUp func(r *teardownRig, cancel context.CancelFunc)
		moved  bool
	}{
		{name: "single mode, during the lift", hangUp: func(r *teardownRig, cancel context.CancelFunc) {
			r.fw.onLift, r.fw.liftErr = cancel, context.Canceled
		}, moved: true},
		{name: "split mode, during the lift", split: true, hangUp: func(r *teardownRig, cancel context.CancelFunc) {
			r.fw.onLift, r.fw.liftErr = cancel, context.Canceled
		}, moved: true},
		{name: "split mode, during the relabel", split: true, hangUp: func(r *teardownRig, cancel context.CancelFunc) {
			inner := r.c.onSetLabels
			r.c.onSetLabels = func() { inner(); cancel() }
			r.c.setLabelsErr = context.Canceled
		}},
		{name: "single mode, during the relabel", hangUp: func(r *teardownRig, cancel context.CancelFunc) {
			inner := r.c.onSetLabels
			r.c.onSetLabels = func() { inner(); cancel() }
			r.c.setLabelsErr = context.Canceled
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTeardownRig(t, tc.split)
			if !tc.split {
				// Single mode: the slot's release clears nothing, so the
				// driver clears the rules itself, before the release.
				r.d.SetHostFirewall(plainFirewall{r.fw})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.hangUp(r, cancel)
			r.claim(ctx, t)

			if r.slotLeft() {
				t.Fatal("the slot's container was left behind: its teardown ran on the create's cancelled context")
			}
			if !slices.Equal(r.released, []string{"park-a"}) {
				t.Fatalf("reservations released %v, want park-a once", r.released)
			}
			if n, _ := r.pool.PendingDestroys(); n != 0 {
				t.Fatalf("%d teardowns left for the pool after a teardown that worked", n)
			}
			r.mu.Lock()
			deadlines := slices.Clone(r.deadlines)
			r.mu.Unlock()
			if len(deadlines) == 0 || deadlines[len(deadlines)-1] > createUndoTimeout {
				t.Fatalf("teardown load deadlines %v, want one within %v", deadlines, createUndoTimeout)
			}
			got := r.fw.recorded()
			back, del := slices.Index(got, "owner sb-a>park-a"), slices.Index(got, "delete park-a")
			if back < 0 || del < back {
				t.Fatalf("calls %v: want the owner moved back to the park before the delete", got)
			}
			if moved := slices.Contains(got, "owner park-a>sb-a"); moved != tc.moved {
				t.Fatalf("calls %v: claim moved the owner = %v, want %v", got, moved, tc.moved)
			}
			// The netns slot is freed under the park id after the delete
			// (destroyParked). In single mode the rules are cleared while it
			// still holds the address; in split its release clears them.
			requireClearThenRelease(t, got[del:], tc.split, "release park-a")
		})
	}
}

// TestFailedClaimTeardownFailureIsRetriedByThePool: when the failed claim's
// teardown fails too, the slot goes to the pool's retry list, still
// charged. Until the container is confirmed gone it keeps its block, its
// rules and its netns slot; the pool's retry then removes it, clears the
// rules, frees the slot under the park id and releases the reservation,
// each once. Single mode and split mode alike.
func TestFailedClaimTeardownFailureIsRetriedByThePool(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "single mode"
		if split {
			name = "split mode"
		}
		t.Run(name, func(t *testing.T) {
			r := newTeardownRig(t, split)
			if !split {
				r.d.SetHostFirewall(plainFirewall{r.fw})
			}
			// The claim's read is done when the lift runs; from there
			// containerd refuses every load, so the teardown fails.
			r.fw.onLift = func() { r.busy.Store(true) }
			r.fw.liftErr = errors.New("helper unavailable")
			r.claim(context.Background(), t)

			if !r.slotLeft() {
				t.Fatal("setup: the teardown was meant to fail")
			}
			if len(r.released) != 0 {
				t.Fatalf("reservation released %v while the container may still run", r.released)
			}
			if n, _ := r.pool.PendingDestroys(); n != 1 {
				t.Fatalf("pending teardowns %d, want the failed claim's slot", n)
			}
			if got := r.pool.Metrics().Stats().DestroyFailures; got < 1 {
				t.Fatalf("destroy failures metric %d, want the failed teardown counted", got)
			}
			got := r.fw.recorded()
			for _, c := range got {
				if strings.HasPrefix(c, "clear-") || strings.HasPrefix(c, "release ") {
					t.Fatalf("calls %v: %q while the container may still run", got, c)
				}
			}
			if got[len(got)-1] != "owner sb-a>park-a" {
				t.Fatalf("calls %v: want the owner moved back last, and nothing torn down after it", got)
			}

			r.busy.Store(false)
			r.pool.Close() // tries each kept teardown once more, now
			if r.slotLeft() {
				t.Fatal("the pool's retry did not remove the container")
			}
			if !slices.Equal(r.released, []string{"park-a"}) {
				t.Fatalf("reservations released %v, want park-a once", r.released)
			}
			if n, _ := r.pool.PendingDestroys(); n != 0 {
				t.Fatalf("pending teardowns %d after the retry", n)
			}
			after := r.fw.recorded()[len(got):]
			del := slices.Index(after, "delete park-a")
			if del < 0 || slices.Contains(after, "release sb-a") {
				t.Fatalf("retry calls %v: want the delete, then the slot freed under the park id only", after)
			}
			requireClearThenRelease(t, after[del:], split, "release park-a")
		})
	}
}

// TestFailedClaimTeardownWhenTheOwnerCannotMoveBack: moving the netns owner
// back is a store write; when it fails the teardown still runs, and the
// sandbox id's slot is freed once the container is gone. When the delete
// fails too, the slot still goes to the pool's retry list, without its
// address, nothing is freed while the container may run, and the create
// is refused instead of going cold (warm_claim_double_failure_test.go has
// this over the real store).
func TestFailedClaimTeardownWhenTheOwnerCannotMoveBack(t *testing.T) {
	r := newTeardownRig(t, false)
	r.netns.backErr = errors.New("database is locked")
	r.fw.liftErr = errors.New("helper unavailable")
	r.claim(context.Background(), t)
	if r.slotLeft() || !slices.Equal(r.released, []string{"park-a"}) {
		t.Fatalf("slot left %v, released %v", r.slotLeft(), r.released)
	}
	if got := r.fw.recorded(); !slices.Contains(got, "release sb-a") {
		t.Fatalf("calls %v: the sandbox id's slot was not freed after the delete", got)
	}

	r = newTeardownRig(t, false)
	r.netns.backErr = errors.New("database is locked")
	r.fw.onLift = func() { r.busy.Store(true) }
	r.fw.liftErr = errors.New("helper unavailable")
	_, err := r.d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, errClaimLeftover) {
		t.Fatalf("claim err %v, want errClaimLeftover", err)
	}
	if !r.slotLeft() || len(r.released) != 0 {
		t.Fatalf("slot left %v, released %v: want it kept for the retry", r.slotLeft(), r.released)
	}
	if n, _ := r.pool.PendingDestroys(); n != 1 {
		t.Fatalf("pending teardowns %d, want 1", n)
	}
	for _, c := range r.fw.recorded() {
		if strings.HasPrefix(c, "release ") || strings.HasPrefix(c, "clear-") {
			t.Fatalf("calls %v: %q while the container may still run", r.fw.recorded(), c)
		}
	}
	mark := len(r.fw.recorded())
	r.busy.Store(false)
	r.pool.Close()
	if r.slotLeft() || !slices.Equal(r.released, []string{"park-a"}) {
		t.Fatalf("slot left %v, released %v after the retry", r.slotLeft(), r.released)
	}
	for _, c := range r.fw.recorded()[mark:] {
		if strings.HasPrefix(c, "clear-") || c == "release sb-a" {
			t.Fatalf("retry calls %v: %q on what may be the sandbox id's", r.fw.recorded()[mark:], c)
		}
	}
}

// requireClearThenRelease checks calls, which start at a container's
// delete: in single mode the address's rules are cleared, then release
// frees the slot; in split the release alone, which clears them itself
// (give_back.go), with no clear of the driver's.
func requireClearThenRelease(t *testing.T, calls []string, split bool, release string) {
	t.Helper()
	rel := slices.Index(calls, release)
	if rel < 0 {
		t.Fatalf("calls %v: want %q", calls, release)
	}
	clear := slices.Index(calls, "clear-block "+claimIP)
	if split {
		if clear >= 0 {
			t.Fatalf("calls %v: the driver cleared rules itself in split", calls)
		}
		return
	}
	if clear < 0 || clear > rel {
		t.Fatalf("calls %v: want the rules cleared, then %q", calls, release)
	}
}
