package netns

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
)

// Plan PR #1000 item L5. The refiller used to top the warm queue up only on
// its ticker (2 s by default), so above about 2 creates a second per node
// creates found the queue empty and built their namespace inline. A claim
// now wakes the refiller. These tests pin that, plus the allocator rules the
// extra refills must keep: no slot handed out twice, never more than depth
// warm slots, no half-made namespace left by a failed refill, and a clean
// stop.

// refillTick is long enough that no test here ever sees a tick: every refill
// after the first pass must come from a claim.
const refillTick = time.Hour

func pooled(t *testing.T, p *Pool) int {
	t.Helper()
	stats, err := p.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return stats.Pooled
}

// waitPooled waits until the warm queue holds want slots. 2 s is far past a
// refill with a fake host (well under 10 ms) and still short of a 2 s tick,
// which is the old refill pace.
func waitPooled(t *testing.T, p *Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := pooled(t, p)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("warm queue holds %d slots, want %d (no refill before the next tick)", got, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func startRefiller(t *testing.T, p *Pool, host HostManager, depth int) *Refiller {
	t.Helper()
	r := NewRefiller(p, host, depth, refillTick)
	go r.Run(context.Background())
	t.Cleanup(r.Stop)
	return r
}

// TestClaimWakesRefillerBeforeNextTick: a create that takes a warm slot, and
// one that finds the queue empty and builds inline, both get the queue
// refilled long before the next tick. Fails on main: the queue stays short
// until the tick.
func TestClaimWakesRefillerBeforeNextTick(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(200, 0).UTC()

	t.Run("hit", func(t *testing.T) {
		p := testPool(t, 16)
		startRefiller(t, p, NewFakeHost(), 2)
		waitPooled(t, p, 2)
		slot, hit, err := p.ClaimPooled(ctx, "sb-hit", now)
		if err != nil || !hit || slot == nil {
			t.Fatalf("claim: slot=%+v hit=%v err=%v", slot, hit, err)
		}
		waitPooled(t, p, 2)
	})

	t.Run("miss", func(t *testing.T) {
		p := testPool(t, 16)
		host := NewFakeHost()
		// The first pass fails, so the queue starts empty and the next
		// create misses it.
		host.SetRealizeError(errors.New("cni not ready yet"))
		startRefiller(t, p, host, 2)
		waitFailedPass(t, p, func() bool { return host.RemovedCount() > 0 })
		host.SetRealizeError(nil)
		path, _, err := NewRuntimeHandoff(p, host).Provision(ctx, "sb-miss")
		if err != nil || filepath.Base(path) != "sb-miss" {
			t.Fatalf("create on an empty queue: path=%q err=%v, want an inline build", path, err)
		}
		waitPooled(t, p, 2)
	})
}

// waitFailedPass waits until a refill pass whose prewarm failed has
// finished cleaning up: failed() reports the failure was seen, and no slot
// is still reserved by the prewarm (teardown reset it to free last).
func waitFailedPass(t *testing.T, p *Pool, failed func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats, err := p.Stats(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if failed() && stats.Reserved == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no failed refill pass finished: %+v", stats)
		}
		time.Sleep(time.Millisecond)
	}
}

// depthSpyHost fails the test's invariant check if a prewarm starts while
// the warm queue is already at depth: that prewarm would push it past.
type depthSpyHost struct {
	*FakeHost
	pool       *Pool
	depth      int
	violations atomic.Int32
	prewarms   atomic.Int32
}

func (h *depthSpyHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	if slot.SandboxID == slot.SlotID { // a prewarm, not a create's own build
		h.prewarms.Add(1)
		if stats, err := h.pool.Stats(ctx); err == nil && stats.Pooled >= h.depth {
			h.violations.Add(1)
		}
	}
	return h.FakeHost.Realize(ctx, slot)
}

// TestRefillOnClaimNeverExceedsDepth: a storm of claims (each one a wake)
// while the refiller runs never builds past depth. One sandbox claims 200
// times: the first takes a slot, the other 199 are idempotent re-claims that
// still wake the refiller. The queue ends at depth, and the host built
// exactly depth+1 namespaces (the claimed one and depth warm ones).
func TestRefillOnClaimNeverExceedsDepth(t *testing.T) {
	ctx := context.Background()
	const depth = 3
	p := testPool(t, 32)
	host := &depthSpyHost{FakeHost: NewFakeHost(), pool: p, depth: depth}
	r := startRefiller(t, p, host, depth)
	waitPooled(t, p, depth)

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, _, err := p.ClaimPooled(ctx, "sb-dup", time.Unix(300, 0).UTC()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	waitPooled(t, p, depth)
	r.Stop() // let any pass still running finish before counting

	if v := host.violations.Load(); v != 0 {
		t.Fatalf("%d prewarms started with the warm queue already at depth %d", v, depth)
	}
	if got := pooled(t, p); got != depth {
		t.Fatalf("warm queue = %d, want %d", got, depth)
	}
	if got := host.RealizedCount(); got != depth+1 {
		t.Fatalf("host built %d namespaces, want %d (one claimed + %d warm)", got, depth+1, depth)
	}
}

// TestConcurrentCreatesAndRefillsNeverShareASlot: 40 creates at once, some
// served from the queue and some building inline, race the refiller that
// each of them wakes. Every create gets its own slot, its own namespace and
// its own address, and nothing the host built is owned twice.
func TestConcurrentCreatesAndRefillsNeverShareASlot(t *testing.T) {
	ctx := context.Background()
	const (
		creates = 40
		depth   = 4
	)
	p := testPool(t, 64)
	host := NewFakeHost()
	r := startRefiller(t, p, host, depth)
	waitPooled(t, p, depth)
	h := NewRuntimeHandoff(p, host)

	type result struct {
		path, ip string
		err      error
	}
	results := make([]result, creates)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < creates; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			path, ip, err := h.Provision(ctx, fmt.Sprintf("sb-%02d", i))
			results[i] = result{path, ip, err}
		}(i)
	}
	close(start)
	wg.Wait()
	r.Stop()

	slots, paths, ips := map[string]string{}, map[string]string{}, map[string]string{}
	for i, res := range results {
		sb := fmt.Sprintf("sb-%02d", i)
		if res.err != nil {
			t.Fatalf("%s: %v", sb, res.err)
		}
		slot, err := p.Get(ctx, sb)
		if err != nil || slot == nil {
			t.Fatalf("%s owns no slot: %v", sb, err)
		}
		for _, k := range []struct {
			seen map[string]string
			key  string
			what string
		}{{slots, slot.SlotID, "slot"}, {paths, res.path, "netns"}, {ips, res.ip, "address"}} {
			if other, dup := k.seen[k.key]; dup {
				t.Fatalf("%s %s handed to both %s and %s", k.what, k.key, other, sb)
			}
			k.seen[k.key] = sb
		}
	}
	stats, err := p.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Adopted != creates {
		t.Fatalf("adopted slots = %d, want %d: %+v", stats.Adopted, creates, stats)
	}
	if stats.Pooled > depth {
		t.Fatalf("warm queue = %d, past depth %d", stats.Pooled, depth)
	}
	// FakeHost keys namespaces by name: a name realized twice would count
	// once, so this also catches two slots sharing one namespace.
	if got, want := host.RealizedCount(), stats.Adopted+stats.Pooled; got != want {
		t.Fatalf("host holds %d namespaces, want %d (adopted %d + warm %d)", got, want, stats.Adopted, stats.Pooled)
	}
}

// TestFailedRefillOnClaimLeavesNoHalfMadeNamespace: a refill a claim
// started fails after the namespace exists (CNI ADD fails). The namespace is
// deleted, the slot goes back to free, and nothing is parked or left warm.
// Runs the real Host with its namespace seams recording what is on the node.
func TestFailedRefillOnClaimLeavesNoHalfMadeNamespace(t *testing.T) {
	ctx := context.Background()
	const size = 8
	var (
		mu   sync.Mutex
		live = map[string]bool{}
		// prewarms counts the refiller's builds only (named after their
		// slot); the create's own build is named after the sandbox.
		prewarms atomic.Int32
	)
	runner := cni.NewFakeRunner()
	runner.SetAddError(errors.New("cni add: bridge busy"))
	host := &Host{
		Runner:    runner,
		NetnsRoot: t.TempDir(),
		addNetns: func(_ context.Context, name string) error {
			if strings.HasPrefix(name, slotNamePrefix) {
				prewarms.Add(1)
			}
			mu.Lock()
			live[name] = true
			mu.Unlock()
			return nil
		},
		delNetns: func(_ context.Context, name string) error {
			mu.Lock()
			delete(live, name)
			mu.Unlock()
			return nil
		},
		loopbackUp: func(context.Context, string) error { return nil },
	}
	p := testPool(t, size)
	r := startRefiller(t, p, host, 2)
	waitFailedPass(t, p, func() bool { return prewarms.Load() > 0 })
	before := prewarms.Load()

	// The queue is empty, so this create misses it and builds inline. Its
	// build fails too, but its reservation wakes the refiller, whose next
	// prewarm fails the same way.
	if _, _, err := NewRuntimeHandoff(p, host).Provision(ctx, "sb-1"); err == nil {
		t.Fatal("create with a failing CNI ADD: want an error")
	}
	deadline := time.Now().Add(2 * time.Second)
	for prewarms.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("the claim did not start a refill")
		}
		time.Sleep(time.Millisecond)
	}
	r.Stop() // waits for the failing pass to finish its cleanup

	mu.Lock()
	defer mu.Unlock()
	if len(live) != 0 {
		t.Fatalf("namespaces left on the node after failed refills: %v", live)
	}
	stats, err := p.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Free != size || stats.Pooled != 0 || stats.Reserved != 0 || stats.Releasing != 0 {
		t.Fatalf("pool after failed refills = %+v, want all %d slots free", stats, size)
	}
}

// gateHost blocks every prewarm in Realize until release is closed, and
// says when one has entered.
type gateHost struct {
	*FakeHost
	entered chan struct{}
	release chan struct{}
}

func (h *gateHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
	return h.FakeHost.Realize(ctx, slot)
}

// TestRefillerStopEndsAPassEarlyWithoutLeaks: Stop during a long refill pass
// (one prewarm in flight, a claim's wake queued) lets the in-flight prewarm
// finish, starts no more, and leaves no goroutine behind. A claim after Stop
// does not block.
func TestRefillerStopEndsAPassEarlyWithoutLeaks(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 16) // before the baseline: the store has goroutines of its own
	before := runtime.NumGoroutine()
	host := &gateHost{FakeHost: NewFakeHost(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	r := NewRefiller(p, host, 4, refillTick)
	go r.Run(ctx)
	<-host.entered // the first pass is building its first warm slot

	stopped := make(chan struct{})
	go func() {
		r.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned while a prewarm was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(host.release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the in-flight prewarm finished")
	}
	if got := host.RealizedCount(); got != 1 {
		t.Fatalf("host built %d namespaces after Stop, want only the 1 in flight", got)
	}

	claimed := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			_, _, _ = p.ClaimPooled(ctx, fmt.Sprintf("sb-after-%d", i), time.Unix(500, 0).UTC())
		}
		close(claimed)
	}()
	select {
	case <-claimed:
	case <-time.After(2 * time.Second):
		t.Fatal("a claim after Stop blocked")
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+1 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines: before %d, after Stop %d", before, runtime.NumGoroutine())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
