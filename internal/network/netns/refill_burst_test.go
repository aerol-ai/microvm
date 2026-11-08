package netns

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A burst of creates against the warm queue, with a fake host whose
// namespace build takes a fixed time. Measured with:
//
//	go test -run '^$' -bench RefillUnderBurst -benchtime 5x ./internal/network/netns/
//
// "tick_only" is main's refiller (no wake on claim); "refill_on_claim" is
// this one. The defaults are production's: 4 warm slots, a 2 s tick.

const (
	burstDepth  = 4
	burstClaims = 20
	burstTick   = 2 * time.Second
	// burstRealize stands in for one namespace build: netns create,
	// loopback, two IPv6 writes and the CNI ADD. 40 ms is the middle of
	// the plan's 30-50 ms estimate for an inline build on a node.
	burstRealize = 40 * time.Millisecond
)

// delayHost makes every build, a prewarm's or a create's own, take delay.
// The sleep is outside FakeHost's lock so builds overlap, as on a node.
type delayHost struct {
	*FakeHost
	delay time.Duration
}

func (h delayHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	time.Sleep(h.delay)
	return h.FakeHost.Realize(ctx, slot)
}

type burst struct {
	perSecond     float64
	claims        int
	tick, realize time.Duration
	refillOnClaim bool
}

// run fires the claims at an even pace, each on its own goroutine like a
// create, and returns how many missed the queue. A miss is a create whose
// namespace is named after itself: it built one inline instead of taking a
// warm slot (named after the slot).
func (c burst) run(tb testing.TB) (misses int) {
	tb.Helper()
	ctx := context.Background()
	p := testPool(tb, 64)
	if !c.refillOnClaim {
		p.claimed = nil // main's refiller: nothing wakes it but the tick
	}
	host := delayHost{FakeHost: NewFakeHost(), delay: c.realize}
	r := NewRefiller(p, host, burstDepth, c.tick)
	go r.Run(ctx)
	defer r.Stop()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		stats, err := p.Stats(ctx)
		if err != nil {
			tb.Fatal(err)
		}
		if stats.Pooled == burstDepth {
			break
		}
		if time.Now().After(deadline) {
			tb.Fatalf("queue never filled: %+v", stats)
		}
	}

	h := NewRuntimeHandoff(p, host)
	gap := time.Duration(float64(time.Second) / c.perSecond)
	var (
		wg     sync.WaitGroup
		missed atomic.Int32
	)
	start := time.Now()
	for i := 0; i < c.claims; i++ {
		time.Sleep(time.Until(start.Add(time.Duration(i) * gap)))
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path, _, err := h.Provision(ctx, fmt.Sprintf("burst-%02d", i))
			if err != nil {
				tb.Error(err)
				return
			}
			if !strings.HasPrefix(filepath.Base(path), slotNamePrefix) {
				missed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	return int(missed.Load())
}

func BenchmarkRefillUnderBurst(b *testing.B) {
	for _, perSecond := range []float64{5, 10, 30} {
		for _, mode := range []struct {
			name    string
			onClaim bool
		}{{"tick_only", false}, {"refill_on_claim", true}} {
			b.Run(fmt.Sprintf("%gps/%s", perSecond, mode.name), func(b *testing.B) {
				c := burst{perSecond: perSecond, claims: burstClaims, tick: burstTick, realize: burstRealize, refillOnClaim: mode.onClaim}
				total := 0
				for i := 0; i < b.N; i++ {
					total += c.run(b)
				}
				b.ReportMetric(float64(total)/float64(b.N), "misses/burst")
				b.ReportMetric(100*float64(total)/float64(b.N*burstClaims), "miss%")
			})
		}
	}
}

// TestBurstIsServedFromTheWarmQueue is the burst at a tenth of the time
// scale, so it runs in make test: 20 creates 15 ms apart against a 1 ms
// build and no tick at all. Main serves the first 4 from the queue and
// builds the other 16 inline. With refill on claim the queue keeps up; the
// bound leaves room for a few scheduler stalls on a loaded CI box.
func TestBurstIsServedFromTheWarmQueue(t *testing.T) {
	c := burst{perSecond: 1000.0 / 15, claims: burstClaims, tick: refillTick, realize: time.Millisecond, refillOnClaim: true}
	if misses := c.run(t); misses > burstClaims/4 {
		t.Fatalf("%d of %d creates built their namespace inline; want at most %d", misses, burstClaims, burstClaims/4)
	}
}

// TestRefillWakeNeverBlocksAndFolds: slot takes with no refiller running
// return at once, and however many there are, they leave one pending pass.
// A Pool built without New (no wake channel) takes slots without blocking
// too.
func TestRefillWakeNeverBlocksAndFolds(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(600, 0).UTC()
	p := testPool(t, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			if _, err := p.Reserve(ctx, fmt.Sprintf("sb-%d", i), now); err != nil {
				t.Errorf("reserve %d: %v", i, err)
			}
		}
		bare := &Pool{st: p.st}
		_, _ = bare.Reserve(ctx, "sb-bare", now)
		_, _, _ = bare.ClaimPooled(ctx, "sb-bare-2", now)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slot takes blocked with no refiller running")
	}
	if got := len(p.claimed); got != 1 {
		t.Fatalf("pending refill passes = %d, want 1", got)
	}
}

// TestMissWakesRefillOnlyOnceTheCreateHoldsItsSlot: a warm queue miss does
// not wake the refiller; the create's Reserve for its inline build does,
// after the slot is the create's. Woken at the miss, the refill could take
// the last free slot first and fail a create that fits. The end-to-end half
// runs that edge with a live refiller: one slot free, queue empty, and the
// create that misses still gets it.
func TestMissWakesRefillOnlyOnceTheCreateHoldsItsSlot(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(700, 0).UTC()

	p := testPool(t, 1)
	if _, hit, err := p.ClaimPooled(ctx, "sb-miss", now); err != nil || hit {
		t.Fatalf("claim on an empty queue: hit=%v err=%v, want a miss", hit, err)
	}
	if got := len(p.claimed); got != 0 {
		t.Fatalf("a miss left %d pending refill passes, want 0 until the create reserves", got)
	}
	slot, err := p.Reserve(ctx, "sb-miss", now)
	if err != nil || slot.SandboxID != "sb-miss" {
		t.Fatalf("reserve: %+v %v", slot, err)
	}
	if got := len(p.claimed); got != 1 {
		t.Fatalf("pending refill passes after the reserve = %d, want 1", got)
	}

	for i := 0; i < 10; i++ {
		p := testPool(t, 2)
		host := NewFakeHost()
		h := NewRuntimeHandoff(p, host)
		if _, _, err := h.Provision(ctx, "sb-held"); err != nil {
			t.Fatal(err)
		}
		<-p.claimed // sb-held's wake: no refiller is running yet
		host.SetRealizeError(errors.New("cni not ready yet"))
		r := NewRefiller(p, host, 1, refillTick)
		go r.Run(ctx)
		waitFailedPass(t, p, func() bool { return host.RemovedCount() > 0 })
		host.SetRealizeError(nil)
		path, _, err := h.Provision(ctx, "sb-last")
		r.Stop()
		if err != nil {
			t.Fatalf("round %d: create with the last free slot: %v", i, err)
		}
		if filepath.Base(path) != "sb-last" {
			t.Fatalf("round %d: create got %s, want its own inline build", i, path)
		}
	}
}
