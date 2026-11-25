package containerd

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// storeNetns is the real netns handoff (SQLite store and netns pool, fake
// host) with one fault: moving the owner back to a park id fails, as a
// store write that meets a full disk or a stalled writer would. Its calls
// go to the rig's ordered log.
type storeNetns struct {
	*netns.RuntimeHandoff
	rec     func(format string, args ...any) error
	backErr error
}

func (n *storeNetns) Provision(ctx context.Context, id string) (string, string, error) {
	_ = n.rec("provision %s", id)
	return n.RuntimeHandoff.Provision(ctx, id)
}

func (n *storeNetns) ReassignOwner(ctx context.Context, from, to string) error {
	_ = n.rec("owner %s>%s", from, to)
	if IsParkedSandboxID(to) && n.backErr != nil {
		return n.backErr
	}
	return n.RuntimeHandoff.ReassignOwner(ctx, from, to)
}

func (n *storeNetns) Release(ctx context.Context, id string) error {
	_ = n.rec("release %s", id)
	return n.RuntimeHandoff.Release(ctx, id)
}

// doubleFailureRig is a teardown rig over the real netns store, set up for
// the double failure: the claim moves the owner park-a > sb-a and then
// fails (the lift is refused), moving the owner back fails, and
// containerd refuses the delete. park-a's slot holds parkIP.
type doubleFailureRig struct {
	*teardownRig
	np               *netns.Pool
	h                *netns.RuntimeHandoff
	parkPath, parkIP string
}

func newDoubleFailureRig(t *testing.T, split bool) *doubleFailureRig {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	for _, id := range []string{"slot-1", "slot-2", "slot-3"} {
		if err := st.SeedContainerNetnsSlot(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	r := &doubleFailureRig{teardownRig: newTeardownRig(t, split), np: netns.New(st)}
	r.h = netns.NewRuntimeHandoff(r.np, netns.NewFakeHost())
	if r.parkPath, r.parkIP, err = r.h.Provision(ctx, "park-a"); err != nil {
		t.Fatal(err)
	}
	r.d.SetNetnsHandoff(&storeNetns{RuntimeHandoff: r.h, rec: r.fw.rec, backErr: errors.New("database or disk is full")})
	r.slot.ContainerIP = r.parkIP
	r.fw.onLift = func() { r.busy.Store(true) } // containerd refuses the delete from here
	r.fw.liftErr = errors.New("helper unavailable")
	return r
}

// owner is the sandbox id the store says holds the slot with ip, "" for none.
func (r *doubleFailureRig) owner(t *testing.T, ip string) string {
	t.Helper()
	for _, id := range []string{"park-a", "sb-a"} {
		s, err := r.np.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if s != nil && s.ContainerIP == ip {
			return id
		}
	}
	return ""
}

func eachMode(t *testing.T, run func(t *testing.T, split bool)) {
	for _, split := range []bool{false, true} {
		name := "single mode"
		if split {
			name = "split mode"
		}
		t.Run(name, func(t *testing.T) { run(t, split) })
	}
}

// TestClaimDoubleFailureRetryLeavesTheSandboxAddressAlone (#1438 review):
// the claim moved the netns owner to sb-a and failed; moving it back and
// the delete both failed, so the park container still runs in a namespace
// sb-a now holds. The pool's retry then removes the container and the
// park's files only. It clears no rules on the address (by then sb-a's
// own, or another sandbox's), and, with sb-a running in it again, it frees
// no netns slot: sb-a keeps the slot for its own release
// (claim_leftovers_test.go covers the empty namespace).
func TestClaimDoubleFailureRetryLeavesTheSandboxAddressAlone(t *testing.T) {
	eachMode(t, func(t *testing.T, split bool) {
		r := newDoubleFailureRig(t, split)
		ctx := context.Background()
		_, err := r.d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
		if !errors.Is(err, errClaimLeftover) {
			t.Fatalf("claim err %v, want errClaimLeftover", err)
		}
		if !r.slotLeft() || r.owner(t, r.parkIP) != "sb-a" {
			t.Fatalf("setup: slot left %v, owner of %s %q; want the container left and sb-a holding the slot", r.slotLeft(), r.parkIP, r.owner(t, r.parkIP))
		}
		if n, _ := r.pool.PendingDestroys(); n != 1 || len(r.released) != 0 {
			t.Fatalf("pending %d, released %v: want the slot kept for retry, still charged", n, r.released)
		}

		// A later create of sb-a holds that address with its own rules,
		// and runs there; containerd answers again and the pool retries the
		// teardown.
		if _, ip, err := r.h.Provision(ctx, "sb-a"); err != nil || ip != r.parkIP {
			t.Fatalf("sb-a's namespace %s, %v; want %s", ip, err, r.parkIP)
		}
		r.tr.mu.Lock()
		r.tr.containers["sb-a"] = &fakeContainer{id: "sb-a", labels: map[string]string{sandboxIDLabelKey: "sb-a"}}
		r.tr.mu.Unlock()
		mark := len(r.fw.recorded())
		r.busy.Store(false)
		r.pool.Close()
		if r.slotLeft() {
			t.Fatal("the pool's retry did not remove the container")
		}
		after := r.fw.recorded()[mark:]
		for _, c := range after {
			if strings.HasPrefix(c, "clear-") && strings.HasSuffix(c, " "+r.parkIP) {
				t.Fatalf("retry calls %v: %q on an address sb-a holds", after, c)
			}
		}
		if got := r.owner(t, r.parkIP); got != "sb-a" {
			t.Fatalf("after the retry %s is held by %q, want sb-a", r.parkIP, got)
		}
		if !slices.Equal(r.released, []string{"park-a"}) {
			t.Fatalf("reservations released %v, want park-a once", r.released)
		}
	})
}

// TestClaimDoubleFailureRefusesTheColdFallback: in the double failure the
// create fails instead of going cold, so it is never handed the namespace
// the claim's container still runs in. It fails as a capacity refusal,
// which the API answers 503 with Retry-After. Without the double failure
// the same claim failure still goes cold.
func TestClaimDoubleFailureRefusesTheColdFallback(t *testing.T) {
	eachMode(t, func(t *testing.T, split bool) {
		stubToolboxProbe(t)
		r := newDoubleFailureRig(t, split)
		r.d.cfg.NativeNetnsPool = true // a cold create would ask the pool for sb-a's namespace
		if split {
			r.d.SetRootHelper(newPartsHelper(t)) // a split create needs the helper's container parts
		}
		_, err := r.d.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker}, "sb-a", "tok", nil)
		if !errors.Is(err, errClaimLeftover) || !errors.Is(err, capacity.ErrCapacityExceeded) {
			t.Fatalf("create err %v, want the capacity refusal errClaimLeftover", err)
		}
		got := r.fw.recorded()
		if slices.Contains(got, "provision sb-a") {
			t.Fatalf("calls %v: the cold fallback asked for sb-a's namespace", got)
		}
		r.tr.mu.Lock()
		_, cold := r.tr.containers["sb-a"]
		r.tr.mu.Unlock()
		if cold {
			t.Fatal("the cold fallback made a container")
		}
	})

	// Moving the owner back works: the claim failure goes cold as before.
	r := newDoubleFailureRig(t, false)
	r.d.SetNetnsHandoff(&storeNetns{RuntimeHandoff: r.h, rec: r.fw.rec})
	_, err := r.d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
	if err == nil || errors.Is(err, errClaimLeftover) || !strings.Contains(err.Error(), "warm adopt failed") {
		t.Fatalf("claim err %v, want a plain failed claim the create falls back from", err)
	}
	if got := r.owner(t, r.parkIP); got != "park-a" {
		t.Fatalf("%s is held by %q, want the park again", r.parkIP, got)
	}
}

// TestClaimOwnerMoveBackHasItsOwnBound: a store write that hangs while the
// owner moves back uses up only its own bound; the delete still gets the
// teardown's whole budget and removes the container.
func TestClaimOwnerMoveBackHasItsOwnBound(t *testing.T) {
	prev := claimOwnerBackTimeout
	claimOwnerBackTimeout = 50 * time.Millisecond
	t.Cleanup(func() { claimOwnerBackTimeout = prev })
	r := newTeardownRig(t, false)
	r.netns.backHang = true
	r.fw.liftErr = errors.New("helper unavailable")
	start := time.Now()
	r.claim(context.Background(), t)
	if waited := time.Since(start); waited > 10*time.Second {
		t.Fatalf("the claim's teardown took %v", waited)
	}
	if r.slotLeft() || !slices.Equal(r.released, []string{"park-a"}) {
		t.Fatalf("slot left %v, released %v: the delete must not share the hung write's bound", r.slotLeft(), r.released)
	}
	r.mu.Lock()
	deadlines := slices.Clone(r.deadlines)
	r.mu.Unlock()
	if len(deadlines) == 0 || deadlines[len(deadlines)-1] < createUndoTimeout-5*time.Second {
		t.Fatalf("delete deadlines %v, want about %v left", deadlines, createUndoTimeout)
	}
}
