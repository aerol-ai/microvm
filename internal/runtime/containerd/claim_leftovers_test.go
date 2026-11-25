package containerd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for a failed warm claim's leftover (claim_leftovers.go,
// #1438 review): the claim moved the netns owner to sb-a and failed, and
// moving it back and removing the container both failed.

// coldCreate is a create of sb-a when the pool has no free slot.
func (r *doubleFailureRig) coldCreate(t *testing.T, split bool) error {
	t.Helper()
	r.d.cfg.NativeNetnsPool = true
	if split && r.d.parts == nil {
		r.d.SetRootHelper(newPartsHelper(t)) // a split create needs the helper's container parts
	}
	_, err := r.d.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker}, "sb-a", "tok", nil)
	return err
}

// retry runs the pool's retry of the failed teardown, as its refill tick
// does once containerd answers again.
func (r *doubleFailureRig) retry(t *testing.T) error {
	t.Helper()
	return (&PoolSpawner{Driver: r.d}).DestroyParked(context.Background(),
		&containerdpool.ParkedSlot{ID: "park-a", ContainerID: "park-a", TeardownRetry: true})
}

// failClaim makes the double failure and checks where it leaves things.
func (r *doubleFailureRig) failClaim(t *testing.T) {
	t.Helper()
	_, err := r.d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, errClaimLeftover) {
		t.Fatalf("claim err %v, want errClaimLeftover", err)
	}
	if !r.slotLeft() || r.owner(t, r.parkIP) != "sb-a" || !r.d.refusesClaimLeftover("sb-a") {
		t.Fatalf("setup: slot left %v, owner of %s %q, remembered %v", r.slotLeft(), r.parkIP, r.owner(t, r.parkIP), r.d.refusesClaimLeftover("sb-a"))
	}
}

// A retried create of sb-a that finds no free warm slot is refused while
// the claim's container may still run in sb-a's namespace: before, it went
// cold and its netns step handed it that namespace. Once the pool's retry
// has removed the container, the same create goes cold as usual.
func TestClaimLeftoverRefusesAColdRetryUntilThePoolRemovesIt(t *testing.T) {
	eachMode(t, func(t *testing.T, split bool) {
		stubToolboxProbe(t)
		r := newDoubleFailureRig(t, split)
		r.failClaim(t)

		mark := len(r.fw.recorded())
		err := r.coldCreate(t, split)
		if !errors.Is(err, errClaimLeftover) {
			t.Fatalf("retried create err %v, want errClaimLeftover", err)
		}
		if got := r.fw.recorded()[mark:]; slices.Contains(got, "provision sb-a") {
			t.Fatalf("calls %v: the retried create asked for sb-a's namespace", got)
		}
		r.tr.mu.Lock()
		_, cold := r.tr.containers["sb-a"]
		r.tr.mu.Unlock()
		if cold {
			t.Fatal("the retried create made a container")
		}

		r.busy.Store(false)
		r.pool.Close()
		if r.slotLeft() || r.d.refusesClaimLeftover("sb-a") {
			t.Fatalf("after the pool's retry: slot left %v, remembered %v", r.slotLeft(), r.d.refusesClaimLeftover("sb-a"))
		}
		mark = len(r.fw.recorded())
		err = r.coldCreate(t, split)
		if errors.Is(err, errClaimLeftover) {
			t.Fatalf("create after the retry still refused: %v", err)
		}
		if got := r.fw.recorded()[mark:]; !slices.Contains(got, "provision sb-a") {
			t.Fatalf("calls %v: the create did not go cold", got)
		}
	})
}

// When the pool's retry removes the container, the namespace sb-a still
// holds is freed too, in Destroy's order: the container is gone first, then
// the address's rules (single mode; in split mode the release clears
// them), then the slot. Before, it stayed allocated until a restart.
func TestClaimLeftoverNetnsIsFreedWhenThePoolRemovesTheContainer(t *testing.T) {
	eachMode(t, func(t *testing.T, split bool) {
		r := newDoubleFailureRig(t, split)
		r.failClaim(t)
		r.busy.Store(false)
		mark := len(r.fw.recorded())
		r.pool.Close()
		if r.slotLeft() {
			t.Fatal("the pool's retry did not remove the container")
		}
		if got := r.owner(t, r.parkIP); got != "" {
			t.Fatalf("after the retry %s is held by %q, want it free", r.parkIP, got)
		}
		if r.d.refusesClaimLeftover("sb-a") {
			t.Fatal("sb-a still remembered after its namespace was freed")
		}
		after := r.fw.recorded()[mark:]
		del, rel := slices.Index(after, "delete park-a"), slices.Index(after, "release sb-a")
		if del < 0 || rel < 0 || rel < del {
			t.Fatalf("retry calls %v: want the container deleted, then sb-a's slot released", after)
		}
		if !r.d.clearsOnRelease() {
			clr := slices.Index(after, "clear-block "+r.parkIP)
			if clr < del || clr > rel {
				t.Fatalf("retry calls %v: want the address's rules cleared between the delete and the release", after)
			}
		}
		if !slices.Equal(r.released, []string{"park-a"}) {
			t.Fatalf("reservations released %v, want park-a once", r.released)
		}
	})
}

// The namespace is freed only when it is empty and still the one the claim
// left. A sandbox sb-a that runs again (a retried create removed the
// leftover and claimed another slot) keeps its slot; a slot sb-a no longer
// holds is not touched. Either way sb-a is forgotten.
func TestClaimLeftoverNetnsIsFreedOnlyWhenEmpty(t *testing.T) {
	ctx := context.Background()
	t.Run("sb-a runs again in the namespace", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		r.tr.mu.Lock()
		r.tr.containers["sb-a"] = &fakeContainer{id: "sb-a", labels: map[string]string{sandboxIDLabelKey: "sb-a"}}
		r.tr.mu.Unlock()
		r.busy.Store(false)
		if err := r.retry(t); err != nil {
			t.Fatal(err)
		}
		if got := r.owner(t, r.parkIP); got != "sb-a" || r.d.refusesClaimLeftover("sb-a") {
			t.Fatalf("owner %q, remembered %v: want sb-a to keep its slot and be forgotten", got, r.d.refusesClaimLeftover("sb-a"))
		}
	})
	t.Run("sb-a released the namespace already", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		if err := r.h.Release(ctx, "sb-a"); err != nil {
			t.Fatal(err)
		}
		if _, ip, err := r.h.Provision(ctx, "sb-b"); err != nil || ip != r.parkIP {
			t.Fatalf("sb-b got %s, %v; want the freed %s", ip, err, r.parkIP)
		}
		r.busy.Store(false)
		mark := len(r.fw.recorded())
		if err := r.retry(t); err != nil {
			t.Fatal(err)
		}
		for _, c := range r.fw.recorded()[mark:] {
			if strings.HasSuffix(c, " "+r.parkIP) || c == "release sb-a" {
				t.Fatalf("retry call %q touched an address sb-b holds now", c)
			}
		}
		if r.d.refusesClaimLeftover("sb-a") {
			t.Fatal("sb-a still remembered")
		}
	})
}

// A check the driver cannot make (containerd does not answer the list)
// keeps sb-a remembered and the slot on the pool's retry list; the next
// retry finishes it.
func TestClaimLeftoverCheckFailureIsRetried(t *testing.T) {
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	r.busy.Store(false)
	r.tr.mu.Lock()
	r.tr.listErr = errors.New("containerd busy")
	r.tr.mu.Unlock()
	if err := r.retry(t); err == nil || !strings.Contains(err.Error(), "sb-a") {
		t.Fatalf("retry err %v, want the failed check", err)
	}
	if !r.d.refusesClaimLeftover("sb-a") || r.owner(t, r.parkIP) != "sb-a" {
		t.Fatalf("remembered %v, owner %q: want both kept for the next retry", r.d.refusesClaimLeftover("sb-a"), r.owner(t, r.parkIP))
	}
	r.tr.mu.Lock()
	r.tr.listErr = nil
	r.tr.mu.Unlock()
	if err := r.retry(t); err != nil {
		t.Fatal(err)
	}
	if r.d.refusesClaimLeftover("sb-a") || r.owner(t, r.parkIP) != "" {
		t.Fatalf("remembered %v, owner %q after the second retry", r.d.refusesClaimLeftover("sb-a"), r.owner(t, r.parkIP))
	}
}

// The set: empty costs one atomic load, a slot counts once, and only the
// slot that was remembered clears it. A remember/holds race is safe.
func TestClaimLeftoversSet(t *testing.T) {
	var l claimLeftovers
	if l.holds("sb-a") {
		t.Fatal("an empty set holds sb-a")
	}
	if _, ok := l.of("park-a"); ok {
		t.Fatal("an empty set knows park-a")
	}
	l.remember("park-a", "sb-a", "10.0.0.1")
	l.remember("park-a", "sb-a", "10.0.0.1")
	l.forget("park-b")
	if !l.holds("sb-a") || l.holds("sb-b") || l.n.Load() != 1 {
		t.Fatalf("holds sb-a %v, sb-b %v, n %d", l.holds("sb-a"), l.holds("sb-b"), l.n.Load())
	}
	if c, ok := l.of("park-a"); !ok || c.sandboxID != "sb-a" || c.address != "10.0.0.1" {
		t.Fatalf("of park-a = %+v %v", c, ok)
	}
	l.forget("park-a")
	if l.holds("sb-a") || l.n.Load() != 0 {
		t.Fatalf("after forget: holds %v, n %d", l.holds("sb-a"), l.n.Load())
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slot := "park-" + string(rune('a'+i))
			l.remember(slot, "sb-x", "")
			_ = l.holds("sb-x")
			l.forget(slot)
		}()
	}
	wg.Wait()
	if l.n.Load() != 0 || l.holds("sb-x") {
		t.Fatalf("after the race: n %d", l.n.Load())
	}
}

// Without a netns handoff that can name a slot's address, nothing is freed:
// the driver cannot tell whose slot it would be.
func TestClaimLeftoverNeedsTheSlotsAddress(t *testing.T) {
	d := newTestDriver(t)
	d.claimLeftovers.remember("park-a", "sb-a", claimIP)
	n := &teardownNetns{harnessNetns: harnessNetns{path: "/run/netns/sb", ip: claimIP}, rec: func(string, ...any) error { return nil }}
	d.SetNetnsHandoff(n)
	if err := d.finishClaimLeftover(context.Background(), "park-a"); err != nil {
		t.Fatal(err)
	}
	if d.refusesClaimLeftover("sb-a") {
		t.Fatal("sb-a still remembered")
	}
}
