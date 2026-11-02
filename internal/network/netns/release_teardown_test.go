package netns

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/store"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLogs(p *Pool) *syncBuffer {
	buf := &syncBuffer{}
	p.SetLogger(slog.New(slog.NewTextHandler(buf, nil)))
	return buf
}

func TestSlotNetnsName(t *testing.T) {
	for _, tc := range []struct {
		name string
		slot Slot
		want string
	}{
		{"claimed prewarmed slot keeps its realize name", Slot{SlotID: "aerol-netns-3", SandboxID: "sb-a", NetnsPath: "/run/netns/aerol-netns-3"}, "aerol-netns-3"},
		{"reassigned park slot keeps the park name", Slot{SlotID: "aerol-netns-1", SandboxID: "sb-b", NetnsPath: "/run/netns/park-9"}, "park-9"},
		{"cold slot", Slot{SlotID: "aerol-netns-2", SandboxID: "sb-c", NetnsPath: "/run/netns/sb-c"}, "sb-c"},
		{"crash before the path was recorded", Slot{SlotID: "aerol-netns-2", SandboxID: "sb-d"}, "sb-d"},
		{"refill crash window", Slot{SlotID: "aerol-netns-4", SandboxID: "aerol-netns-4"}, "aerol-netns-4"},
		{"no owner, no path", Slot{SlotID: "aerol-netns-5"}, "aerol-netns-5"},
		{"blank", Slot{NetnsPath: "  ", SandboxID: " "}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.slot.netnsName(); got != tc.want {
				t.Fatalf("netnsName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A failed teardown is logged with the slot, the netns name and the sandbox,
// parked as releasing, retried by RetryReleasing under the same identity, and
// only then freed.
func TestReleaseRemoveFailureIsLoggedParkedAndRetried(t *testing.T) {
	p := testPool(t, 1)
	logs := captureLogs(p)
	host := NewFakeHost()
	ctx := context.Background()
	h := NewRuntimeHandoff(p, host)
	if _, _, err := h.Provision(ctx, "sb-fail"); err != nil {
		t.Fatal(err)
	}
	host.SetRemoveError(errors.New("cni del: exit status 1"))
	if err := h.Release(ctx, "sb-fail"); err != nil {
		t.Fatalf("Release returns nil once the failure is parked for retry: %v", err)
	}
	out := logs.String()
	for _, want := range []string{"level=WARN", "slot_id=aerol-netns-0", "netns=sb-fail", "sandbox_id=sb-fail", "cni del: exit status 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("warning %q missing from log: %s", want, out)
		}
	}
	stats, _ := p.Stats(ctx)
	if stats.Releasing != 1 || stats.Free != 0 {
		t.Fatalf("stats=%+v, want the slot parked as releasing", stats)
	}

	// Still failing: stays parked.
	if freed, err := p.RetryReleasing(ctx, host, time.Unix(5, 0)); err != nil || freed != 0 {
		t.Fatalf("retry while DEL still fails: freed=%d err=%v", freed, err)
	}
	host.SetRemoveError(nil)
	if freed, err := p.RetryReleasing(ctx, host, time.Unix(6, 0)); err != nil || freed != 1 {
		t.Fatalf("retry after DEL recovers: freed=%d err=%v", freed, err)
	}
	if got := host.Removed(); len(got) != 1 || got[0] != "sb-fail" {
		t.Fatalf("retry tore down %v, want the realize identity sb-fail", got)
	}
	stats, _ = p.Stats(ctx)
	if stats.Free != 1 || stats.Releasing != 0 {
		t.Fatalf("stats=%+v, want the slot free again", stats)
	}
}

// A crash-window row (reserved, path never recorded) whose teardown fails
// must still remember the netns name once its owner is cleared.
func TestTeardownFailureOnUnrecordedPathKeepsIdentity(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	if _, err := p.Reserve(ctx, "sb-crash", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	host := NewFakeHost()
	host.SetRemoveError(errors.New("ip netns del: device busy"))
	if reaped, err := p.Reconcile(ctx, host, nil, nil, time.Unix(2, 0)); err != nil || reaped != 0 {
		t.Fatalf("reaped=%d err=%v, want the slot parked (not counted as reaped)", reaped, err)
	}
	rows, err := p.st.ListContainerNetnsSlotsByState(ctx, store.NetnsSlotStateReleasing)
	if err != nil || len(rows) != 1 {
		t.Fatalf("releasing rows=%+v err=%v", rows, err)
	}
	if rows[0].NetnsPath != "/run/netns/sb-crash" || rows[0].SandboxID != "" {
		t.Fatalf("parked row lost its identity: %+v", rows[0])
	}
	host.SetRemoveError(nil)
	if reaped, err := p.Reconcile(ctx, host, nil, nil, time.Unix(3, 0)); err != nil || reaped != 1 {
		t.Fatalf("boot reconcile must retry releasing rows: reaped=%d err=%v", reaped, err)
	}
	if got := host.Removed(); len(got) != 1 || got[0] != "sb-crash" {
		t.Fatalf("retry tore down %v, want sb-crash", got)
	}
}

// Reconcile no longer frees a slot whose teardown failed.
func TestReconcileRemoveFailureParksInsteadOfFreeing(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	ctx := context.Background()
	if _, _, err := NewRuntimeHandoff(p, host).Provision(ctx, "sb-dead"); err != nil {
		t.Fatal(err)
	}
	host.SetRemoveError(errors.New("cni del failed"))
	if _, err := p.Reconcile(ctx, host, func(context.Context, string) bool { return false }, nil, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	stats, _ := p.Stats(ctx)
	if stats.Releasing != 1 || stats.Free != 1 {
		t.Fatalf("stats=%+v, want the dead owner's slot parked, the other free", stats)
	}
}

// A duplicate Release that lost the race must not tear down a slot that was
// freed and handed to another sandbox while it waited for the slot lock: with
// the identity fix its CNI DEL would now hit the new owner's netns.
func TestReleaseSkipsSlotReownedWhileWaiting(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	ctx := context.Background()
	h := NewRuntimeHandoff(p, host)
	if _, _, err := h.Provision(ctx, "sb-old"); err != nil {
		t.Fatal(err)
	}
	releaseAfterGet = func(string) {
		// The winning Release finished and the slot went to sb-new.
		if err := p.Release(ctx, "sb-old", time.Unix(2, 0)); err != nil {
			t.Error(err)
		}
		if _, err := p.Reserve(ctx, "sb-new", time.Unix(3, 0)); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { releaseAfterGet = nil })
	if err := h.Release(ctx, "sb-old"); err != nil {
		t.Fatal(err)
	}
	if host.RemovedCount() != 0 {
		t.Fatalf("stale Release tore down %v", host.Removed())
	}
	if slot, _ := p.Get(ctx, "sb-new"); slot == nil {
		t.Fatal("the new owner lost its slot")
	}
}

// Same window, but the sandbox id was re-provisioned onto another slot.
func TestReleaseSkipsWhenSandboxMovedToAnotherSlot(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	ctx := context.Background()
	h := NewRuntimeHandoff(p, host)
	if _, _, err := h.Provision(ctx, "sb-x"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(ctx, "sb-hold", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	releaseAfterGet = func(string) {
		// sb-x released and re-created onto the other slot.
		_ = p.Release(ctx, "sb-hold", time.Unix(2, 0))
		_ = p.Release(ctx, "sb-x", time.Unix(2, 0))
		_, _ = p.Reserve(ctx, "sb-other", time.Unix(3, 0))
		_, _ = p.Reserve(ctx, "sb-x", time.Unix(3, 0))
	}
	t.Cleanup(func() { releaseAfterGet = nil })
	if err := h.Release(ctx, "sb-x"); err != nil {
		t.Fatal(err)
	}
	if host.RemovedCount() != 0 {
		t.Fatalf("stale Release tore down %v", host.Removed())
	}
}

// A failed prewarm whose own cleanup also fails parks the slot instead of
// handing it straight back to the next prewarm.
func TestPrewarmCleanupFailureParksSlot(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	host.SetRealizeError(errors.New("cni add: duplicate allocation"))
	host.SetRemoveError(errors.New("cni del: boom"))
	if err := p.Prewarm(context.Background(), host, time.Unix(1, 0)); err == nil {
		t.Fatal("want the realize error")
	}
	stats, _ := p.Stats(context.Background())
	if stats.Releasing != 1 || stats.Free != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

// The refiller retries parked slots on its first tick and then every
// releasingRetryEvery ticks, not on every tick.
func TestRefillerRetriesReleasingOnCadence(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	ctx := context.Background()
	park := func(id string) {
		t.Helper()
		if _, _, err := NewRuntimeHandoff(p, host).Provision(ctx, id); err != nil {
			t.Fatal(err)
		}
		host.SetRemoveError(errors.New("busy"))
		_ = NewRuntimeHandoff(p, host).Release(ctx, id)
		host.SetRemoveError(nil)
	}
	park("sb-1")
	r := NewRefiller(p, host, 1, time.Hour)
	r.refillOnce(ctx) // tick 0 retries
	stats, _ := p.Stats(ctx)
	if stats.Releasing != 0 {
		t.Fatalf("first tick should retry parked slots: %+v", stats)
	}
	park("sb-2")
	for i := 1; i < releasingRetryEvery; i++ {
		r.refillOnce(ctx)
	}
	stats, _ = p.Stats(ctx)
	if stats.Releasing != 1 {
		t.Fatalf("ticks 1..%d must not retry: %+v", releasingRetryEvery-1, stats)
	}
	r.refillOnce(ctx)
	stats, _ = p.Stats(ctx)
	if stats.Releasing != 0 {
		t.Fatalf("tick %d must retry: %+v", releasingRetryEvery, stats)
	}
}

func TestRetryReleasingGuards(t *testing.T) {
	if n, err := (*Pool)(nil).RetryReleasing(context.Background(), NewFakeHost(), time.Now()); n != 0 || err != nil {
		t.Fatalf("nil pool: %d %v", n, err)
	}
	p := testPool(t, 1)
	if n, err := p.RetryReleasing(context.Background(), nil, time.Now()); n != 0 || err != nil {
		t.Fatalf("nil host: %d %v", n, err)
	}
	_ = p.st.Close()
	if _, err := p.RetryReleasing(context.Background(), NewFakeHost(), time.Now()); err == nil {
		t.Fatal("want list error on a closed store")
	}
}

// teardown must not park a row that changed owner while it ran.
func TestTeardownLeavesReownedRowAlone(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	ctx := context.Background()
	if _, _, err := NewRuntimeHandoff(p, host).Provision(ctx, "sb-now"); err != nil {
		t.Fatal(err)
	}
	slot, _ := p.Get(ctx, "sb-now")
	host.SetRemoveError(errors.New("boom"))
	err := p.teardown(ctx, host, *slot, "sb-before", func() error { return nil }, time.Unix(2, 0))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want the remove error back, got %v", err)
	}
	if got, _ := p.Get(ctx, "sb-now"); got == nil || got.State != store.NetnsSlotStateAdopted {
		t.Fatalf("row of the current owner was touched: %+v", got)
	}
}

func TestTeardownSurfacesStoreError(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	ctx := context.Background()
	if _, _, err := NewRuntimeHandoff(p, host).Provision(ctx, "sb-s"); err != nil {
		t.Fatal(err)
	}
	slot, _ := p.Get(ctx, "sb-s")
	host.SetRemoveError(errors.New("boom"))
	_ = p.st.Close()
	if err := p.teardown(ctx, host, *slot, "sb-s", func() error { return nil }, time.Unix(2, 0)); err == nil || !strings.Contains(err.Error(), "releasing") {
		t.Fatalf("want remove + store error, got %v", err)
	}
}

func TestPoolLoggerDefaults(t *testing.T) {
	var nilPool *Pool
	nilPool.SetLogger(nil)
	if nilPool.log() == nil {
		t.Fatal("nil pool must still log to a discard logger")
	}
	p := New(nil)
	p.SetLogger(nil)
	if p.log() != discardLogger {
		t.Fatal("unset logger must be the discard logger")
	}
}

// Host.Remove: CNI DEL, NAT teardown and netns delete all use the identity
// ADD used, and the NAT teardown gets the recorded container IP.
func TestHostRemoveTearsDownUnderAddIdentity(t *testing.T) {
	r := newRecordingHost(t)
	slot := Slot{SlotID: "aerol-netns-3", SandboxID: "sb-claimant", NetnsPath: "/run/netns/aerol-netns-3", ContainerIP: "10.88.0.9"}
	if err := r.Remove(context.Background(), slot); err != nil {
		t.Fatal(err)
	}
	if dels := r.runner.Dels(); len(dels) != 1 || dels[0].ContainerID != "aerol-netns-3" || dels[0].Netns != "/run/netns/aerol-netns-3" {
		t.Fatalf("dels=%+v", dels)
	}
	if masq := r.runner.MasqTeardowns(); len(masq) != 1 || masq[0] != (cni.MasqCall{ContainerID: "aerol-netns-3", ContainerIP: "10.88.0.9"}) {
		t.Fatalf("masq teardowns=%+v", masq)
	}
	if got := r.deletedNames(); len(got) != 1 || got[0] != "aerol-netns-3" {
		t.Fatalf("deleted netns=%v", got)
	}
}

func TestHostRemoveSurfacesIPMasqError(t *testing.T) {
	r := newRecordingHost(t)
	r.runner.SetMasqError(errors.New("iptables: resource busy"))
	err := r.Remove(context.Background(), Slot{SandboxID: "sb-x", NetnsPath: "/run/netns/sb-x", ContainerIP: "10.88.0.4"})
	if err == nil || !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("want the NAT teardown error surfaced, got %v", err)
	}
	if got := r.deletedNames(); len(got) != 1 {
		t.Fatalf("netns delete must still run after a NAT error: %v", got)
	}
}

func TestHostNetnsPathFor(t *testing.T) {
	if got := (&Host{NetnsRoot: "/tmp/ns"}).netnsPathFor("sb-a"); got != "/tmp/ns/sb-a" {
		t.Fatalf("got %q", got)
	}
	if got := (&Host{}).netnsPathFor("sb-a"); got != "/run/netns/sb-a" {
		t.Fatalf("got %q", got)
	}
}

// Build's failure path goes through the same parked teardown.
func TestBuildFailureAfterRealizeParksOnTeardownError(t *testing.T) {
	p := testPool(t, 1)
	host := &adoptFailHost{FakeHost: NewFakeHost()}
	host.SetRemoveError(errors.New("cni del boom"))
	b := NewBuilder(p, host)
	// MarkRealized refuses an empty IP, so Build fails after Realize.
	if _, err := b.Build(context.Background(), "sb-bad"); err == nil {
		t.Fatal("want build failure")
	}
	stats, _ := p.Stats(context.Background())
	if stats.Releasing != 1 {
		t.Fatalf("stats=%+v, want the realized slot parked", stats)
	}
}
