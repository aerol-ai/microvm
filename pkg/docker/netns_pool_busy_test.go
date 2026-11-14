package docker

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// createAny runs a create through the rig's fail-closed checks when it is
// restricted; a plain create that joins a slot reports its address with no
// rules on it, which those checks are not about (as in
// TestOwnPauseOnlyForRestrictedRuncCreates).
func (rig *ownPauseRig) createAny(ctx context.Context, req models.CreateSandboxRequest, id string) (*SandboxRuntime, error) {
	if hasCreateNetRules(req) {
		return rig.create(ctx, req, id)
	}
	return rig.c.Create(ctx, req, id, "tok", nil)
}

func (rig *ownPauseRig) destroyAny(st *SandboxRuntime, req models.CreateSandboxRequest) error {
	if hasCreateNetRules(req) {
		return rig.destroy(st, req)
	}
	return rig.c.Destroy(context.Background(), &models.Sandbox{ID: st.SandboxID, ContainerID: st.ContainerID, ContainerIP: st.ContainerIP})
}

// TestNetnsPoolSkippedWhileAnotherCreateRuns: a create that overlaps another
// create on the node takes Docker's own path and leaves the pool's slot
// alone, so a busy node doesn't pay a second container per sandbox. A
// restricted create still adopts the slot: it needs a pause either way and
// the slot is cheaper than starting its own. Fails on the base: every create
// adopts.
func TestNetnsPoolSkippedWhileAnotherCreateRuns(t *testing.T) {
	plain := models.CreateSandboxRequest{Image: "img"}
	blockAll := models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}
	cases := []struct {
		name     string
		running  int64 // other creates already past the warm pool
		req      models.CreateSandboxRequest
		wantDesc string
		wantSlot bool // the workload joined the pool's slot
	}{
		{"alone", 0, plain, "hit", true},
		{"overlapping", 1, plain, "busy", false},
		{"overlapping three", 3, plain, "busy", false},
		{"overlapping restricted", 1, blockAll, "hit", true},
		{"alone restricted", 0, blockAll, "hit", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newOwnPauseRig(t, true)
			rig.c.netnsPool.refill(context.Background())
			if got := rig.c.netnsPool.size(); got != 1 {
				t.Fatalf("pool size after refill = %d, want 1", got)
			}
			slot := rig.c.netnsPool.free[0].containerID
			slotName := rig.d.byRef(slot).name
			rig.c.coldCreates.Store(tc.running)
			skips := netnsPoolBusySkips.Value()

			ctx, timing := WithCreateTiming(context.Background())
			st, err := rig.createAny(ctx, tc.req, "sb-busy")
			if err != nil {
				t.Fatal(err)
			}
			rig.assertClean(t)
			if desc, ok := stage(timing, "docker_netns"); !ok || desc != tc.wantDesc {
				t.Fatalf("docker_netns stage %q (present %v), want %q", desc, ok, tc.wantDesc)
			}
			workload := rig.d.byRef("sb-busy")
			if joined := workload.netMode == "container:"+slot; joined != tc.wantSlot {
				t.Fatalf("workload netMode %q: joined the slot %v, want %v", workload.netMode, joined, tc.wantSlot)
			}
			if _, own := stage(timing, "docker_pause"); own {
				t.Fatal("the create started a pause of its own; it should have taken the slot or no pause")
			}
			wantFree := 1
			if tc.wantSlot {
				wantFree = 0
			}
			if got := rig.c.netnsPool.size(); got != wantFree {
				t.Fatalf("pool size = %d, want %d", got, wantFree)
			}
			wantSkips := int64(0)
			if tc.wantDesc == "busy" {
				wantSkips = 1
			}
			if got := netnsPoolBusySkips.Value() - skips; got != wantSkips {
				t.Fatalf("busy skips counted %d, want %d", got, wantSkips)
			}
			if got := rig.c.coldCreates.Load(); got != tc.running {
				t.Fatalf("cold creates after the create = %d, want %d (its own count given back)", got, tc.running)
			}

			if err := rig.destroyAny(st, tc.req); err != nil {
				t.Fatal(err)
			}
			rig.assertClean(t)
			if tc.wantSlot {
				rig.assertNothingLeft(t)
			} else {
				rig.assertNothingLeft(t, slotName)
			}
		})
	}
}

// TestColdCreatesGivenBackOnFailure: a failed create gives its count back
// too. A leaked count would mark the node busy for good and switch the pool
// off without anyone noticing.
func TestColdCreatesGivenBackOnFailure(t *testing.T) {
	rig := newOwnPauseRig(t, true)
	rig.c.netnsPool.refill(context.Background())
	rig.toolboxDown.Store(true)
	rig.c.toolboxWaitTimeout = 50 * time.Millisecond
	if _, err := rig.createAny(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-fail"); err == nil {
		t.Fatal("create should fail: the toolbox never gets ready")
	}
	if got := rig.c.coldCreates.Load(); got != 0 {
		t.Fatalf("cold creates after a failed create = %d, want 0", got)
	}
	rig.assertClean(t)
}

// TestColdCreatesSeeEachOther: two creates that overlap count each other, so
// the one that finds the other running reports busy.
func TestColdCreatesSeeEachOther(t *testing.T) {
	rig := newOwnPauseRig(t, true)
	rig.c.netnsPool.refill(context.Background())
	slotIP := rig.c.netnsPool.free[0].ip
	// The first create adopts the slot and is held in its readiness wait,
	// the dial to the slot's address, until the second has run.
	gated := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	inner := rig.c.toolboxClient.Transport.(*http.Transport)
	dial := inner.DialContext
	inner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, _ := net.SplitHostPort(addr); host == slotIP {
			once.Do(func() { close(gated) })
			<-release
		}
		return dial(ctx, network, addr)
	}
	first := make(chan error, 1)
	go func() {
		_, err := rig.createAny(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-first")
		first <- err
	}()
	<-gated
	ctx, timing := WithCreateTiming(context.Background())
	_, err := rig.createAny(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-second")
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if desc, _ := stage(timing, "docker_netns"); desc != "busy" {
		t.Fatalf("second create's docker_netns = %q, want busy", desc)
	}
	if got := rig.c.coldCreates.Load(); got != 0 {
		t.Fatalf("cold creates after both = %d, want 0", got)
	}
	rig.assertClean(t)
}

// TestNetnsPoolRefillsOnlyBetweenCreates: the refill starts no pause while
// a create runs (it would compete with it for dockerd and the disk) and
// fills the pool once the node is idle.
func TestNetnsPoolRefillsOnlyBetweenCreates(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	pool := newTestNetnsPool(c, 3)
	c.netnsPool = pool

	c.coldCreates.Store(1)
	pool.refill(context.Background())
	if got := pool.size(); got != 0 {
		t.Fatalf("pool refilled to %d while a create ran, want 0", got)
	}
	if got := d.countWithPrefix(netnsFreePrefix); got != 0 {
		t.Fatalf("%d pause containers started while a create ran", got)
	}

	c.coldCreates.Store(0)
	pool.refill(context.Background())
	if got := pool.size(); got != 3 {
		t.Fatalf("pool size after an idle refill = %d, want 3", got)
	}
}

// TestNetnsPoolRefillWakesWhenCreatesEnd: the refill runs as soon as the
// node's last running create ends, not at the next tick, so a node creating
// one sandbox at a time keeps its slots; while another create still runs it
// stays asleep.
func TestNetnsPoolRefillWakesWhenCreatesEnd(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	// A tick that never fires within the test: only a wake refills.
	pool := c.StartNetnsPool(context.Background(), slog.Default(), 2, "pause:test", time.Hour)
	t.Cleanup(func() { pool.Stop(context.Background()) })
	waitSize := func(want int) bool {
		deadline := time.Now().Add(3 * time.Second)
		for pool.size() != want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		return pool.size() == want
	}
	if !waitSize(2) {
		t.Fatalf("pool never filled at start: size = %d", pool.size())
	}
	for _, id := range []string{"sb-1", "sb-2"} {
		if _, ok := pool.Adopt(context.Background(), id); !ok {
			t.Fatalf("adopt %s missed", id)
		}
	}

	c.coldCreates.Store(2)
	c.endColdCreate() // one create still runs
	time.Sleep(100 * time.Millisecond)
	if got := pool.size(); got != 0 {
		t.Fatalf("pool refilled to %d while a create still ran", got)
	}
	c.endColdCreate() // the last one ends
	if !waitSize(2) {
		t.Fatalf("pool not refilled after the last create ended: size = %d", pool.size())
	}
	if got := c.coldCreates.Load(); got != 0 {
		t.Fatalf("cold creates = %d, want 0", got)
	}
}

// TestEndColdCreateWithoutPool: a node without the netns pool just counts.
func TestEndColdCreateWithoutPool(t *testing.T) {
	c := &Client{}
	c.coldCreates.Store(1)
	c.endColdCreate()
	if got := c.coldCreates.Load(); got != 0 {
		t.Fatalf("cold creates = %d, want 0", got)
	}
}
