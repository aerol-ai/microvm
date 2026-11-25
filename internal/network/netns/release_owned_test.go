package netns

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// ReleaseOwned is the one way an address is given back: under the slot's
// lock it checks the holder, clears the address's rules, then frees the
// slot. These pin each part of that step.

// clearLog records the addresses a ReleaseOwned clear ran on, and checks
// that each clear ran while the slot still held its address.
type clearLog struct {
	mu   sync.Mutex
	ips  []string
	held func(ip string) bool
	t    *testing.T
}

func (c *clearLog) clear(ip string) {
	if c.held != nil && !c.held(ip) {
		c.t.Errorf("cleared %s after its slot was freed", ip)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ips = append(c.ips, ip)
}

func (c *clearLog) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.ips)
}

// A release clears the holder's address while the slot still holds it,
// then frees the slot; a second release finds nothing, and clears nothing.
func TestReleaseOwnedClearsThenFreesOnce(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 1)
	host := NewFakeHost()
	h := NewRuntimeHandoff(p, host)
	_, ip, err := h.Provision(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	log := &clearLog{t: t, held: func(addr string) bool {
		got, _ := h.Address(ctx, "sb-1")
		return got == addr
	}}
	got, err := h.ReleaseOwned(ctx, "sb-1", "", log.clear)
	if err != nil || got != ip {
		t.Fatalf("ReleaseOwned = %q, %v; want %s", got, err, ip)
	}
	if again, err := h.ReleaseOwned(ctx, "sb-1", "", log.clear); err != nil || again != "" {
		t.Fatalf("second ReleaseOwned = %q, %v; want nothing to do", again, err)
	}
	if !slices.Equal(log.got(), []string{ip}) || host.RemovedCount() != 1 {
		t.Fatalf("clears %v, teardowns %d; want one of each", log.got(), host.RemovedCount())
	}
	if held, _ := h.Address(ctx, "sb-1"); held != "" {
		t.Fatalf("sb-1 still holds %s", held)
	}
}

// A release that names an address gives back only a slot with it.
func TestReleaseOwnedMatchesTheAddress(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 1)
	h := NewRuntimeHandoff(p, NewFakeHost())
	_, ip, err := h.Provision(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	log := &clearLog{t: t}
	if got, err := h.ReleaseOwned(ctx, "sb-1", "10.99.0.1", log.clear); err != nil || got != "" || len(log.got()) != 0 {
		t.Fatalf("ReleaseOwned at another address = %q, %v, clears %v; want nothing", got, err, log.got())
	}
	if got, _ := h.ReleaseOwned(ctx, "sb-1", ip, log.clear); got != ip {
		t.Fatalf("ReleaseOwned at its address = %q, want %s", got, ip)
	}
	if got, _ := h.ReleaseOwned(ctx, "sb-none", "", log.clear); got != "" {
		t.Fatalf("ReleaseOwned of an id with no slot = %q", got)
	}
}

// The race the lock closes: a release read the slot, then, before it took
// the lock, another release gave it back and the pool handed the slot (and
// its address) to a new sandbox, which put its rules on. The late release
// must not clear the new sandbox's address, nor free its slot.
func TestReleaseOwnedNeverClearsAnAddressHandedOn(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 1)
	host := NewFakeHost()
	h := NewRuntimeHandoff(p, host)
	_, ip, err := h.Provision(ctx, "sb-old")
	if err != nil {
		t.Fatal(err)
	}
	log := &clearLog{t: t}
	once := false
	releaseAfterGet = func(string) {
		if once {
			return
		}
		once = true
		if got, err := h.ReleaseOwned(ctx, "sb-old", "", log.clear); err != nil || got != ip {
			t.Errorf("the first release = %q, %v", got, err)
		}
		if _, again, err := h.Provision(ctx, "sb-new"); err != nil || again != ip {
			t.Errorf("sb-new got %q, %v; want the same address %s", again, err, ip)
		}
	}
	t.Cleanup(func() { releaseAfterGet = nil })
	if got, err := h.ReleaseOwned(ctx, "sb-old", "", log.clear); err != nil || got != "" {
		t.Fatalf("the late release = %q, %v; want nothing to do", got, err)
	}
	if !slices.Equal(log.got(), []string{ip}) {
		t.Fatalf("clears %v: the late release cleared sb-new's address", log.got())
	}
	if held, _ := h.Address(ctx, "sb-new"); held != ip {
		t.Fatalf("sb-new holds %q, want %s", held, ip)
	}
}

// AddressInPool tells an address the pool has (held or warm) from one it
// never had or has freed.
func TestAddressInPool(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 2)
	h := NewRuntimeHandoff(p, NewFakeHost())
	if in, err := (*RuntimeHandoff)(nil).AddressInPool(ctx, "10.0.0.1"); in || err != nil {
		t.Fatalf("nil handoff: %v %v", in, err)
	}
	_, ip, err := h.Provision(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if in, err := h.AddressInPool(ctx, ip); !in || err != nil {
		t.Fatalf("held address: %v %v", in, err)
	}
	if in, _ := h.AddressInPool(ctx, "10.250.0.9"); in {
		t.Fatal("an address the pool never had is in the pool")
	}
	if in, _ := h.AddressInPool(ctx, ""); in {
		t.Fatal("an empty address is in the pool")
	}
	if err := h.Release(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	if in, _ := h.AddressInPool(ctx, ip); in {
		t.Fatal("a freed address is still in the pool")
	}
}

// Boot reconcile gives a dead holder's address back as the driver does:
// its rules first (SetAddressClearer), under the lock, then the slot. A
// live holder's is kept, and a warm slot nobody held has nothing to clear.
func TestReconcileClearsADeadHoldersAddress(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(400, 0).UTC()
	p := testPool(t, 3)
	host := NewFakeHost()
	h := NewRuntimeHandoff(p, host)
	_, dead, err := h.Provision(ctx, "sb-dead")
	if err != nil {
		t.Fatal(err)
	}
	_, live, err := h.Provision(ctx, "sb-live")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prewarm(ctx, host, now); err != nil {
		t.Fatal(err)
	}
	log := &clearLog{t: t}
	p.SetAddressClearer(log.clear)
	isLive := func(_ context.Context, id string) bool { return id == "sb-live" }
	// The warm slot's netns is gone too: it is reaped, with nothing to clear.
	exists := func(string) bool { return false }
	reaped, err := p.Reconcile(ctx, host, isLive, exists, now)
	if err != nil || reaped != 2 {
		t.Fatalf("reaped %d, %v; want the dead holder and the warm slot", reaped, err)
	}
	if !slices.Equal(log.got(), []string{dead}) {
		t.Fatalf("clears %v, want only %s (not %s)", log.got(), dead, live)
	}
	var nilPool *Pool
	nilPool.SetAddressClearer(log.clear) // no panic
}
