package netns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/store"
)

// TestMain stands a no-op in for the real netns IPv6 write: unit tests run
// unprivileged, with no real namespace at the paths they hand Realize. The
// tests below record the calls instead.
func TestMain(m *testing.M) {
	disableIPv6InNetns = func(string) error { return nil }
	os.Exit(m.Run())
}

// ipv6Recorder records every netns IPv6 write, in order with the CNI calls
// it is interleaved with, and fails the ones whose 1-based call number is
// in fail.
type ipv6Recorder struct {
	mu    sync.Mutex
	calls []string
	fail  map[int]bool
}

func (r *ipv6Recorder) install(t *testing.T) {
	t.Helper()
	orig := disableIPv6InNetns
	disableIPv6InNetns = func(path string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, path)
		if r.fail[len(r.calls)] {
			return errors.New("sysctl boom")
		}
		return nil
	}
	t.Cleanup(func() { disableIPv6InNetns = orig })
}

func (r *ipv6Recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// orderRunner wraps the fake CNI runner so the test can see whether the
// IPv6 write came before the ADD.
type orderRunner struct {
	*cni.FakeRunner
	rec *ipv6Recorder
	log *[]string
}

func (o orderRunner) Add(ctx context.Context, netnsPath, containerID string) (cni.Result, error) {
	*o.log = append(*o.log, "ipv6-writes-before-add="+strconv.Itoa(len(o.rec.got())))
	return o.FakeRunner.Add(ctx, netnsPath, containerID)
}

func ipv6TestHost(t *testing.T, runner cni.Runner, deleted *[]string) *Host {
	t.Helper()
	return &Host{
		Runner:     runner,
		NetnsRoot:  t.TempDir(),
		addNetns:   func(context.Context, string) error { return nil },
		delNetns:   func(_ context.Context, name string) error { *deleted = append(*deleted, name); return nil },
		loopbackUp: func(context.Context, string) error { return nil },
		readIPv4:   runnerAddrs(runner),
	}
}

// runnerAddrs reads a slot's netns the way the kernel would answer for a
// fake CNI runner: it holds the address ADD gave its id until a DEL.
func runnerAddrs(runner cni.Runner) func(path string) ([]string, error) {
	r, ok := runner.(interface{ IPOf(string) (string, bool) })
	if !ok {
		return nil
	}
	return func(path string) ([]string, error) {
		if ip, ok := r.IPOf(filepath.Base(path)); ok {
			return []string{ip}, nil
		}
		return nil, nil
	}
}

// TestRealizeDisablesIPv6BeforeAndAfterCNIAdd is the regression test for
// the live link-local hole: every realized netns gets IPv6 off before the
// CNI ADD creates its interface (so eth0 never gets an fe80 address) and
// again after it (so an IPv6 IPAM range cannot turn it back on).
func TestRealizeDisablesIPv6BeforeAndAfterCNIAdd(t *testing.T) {
	rec := &ipv6Recorder{}
	rec.install(t)
	var order, deleted []string
	runner := orderRunner{FakeRunner: cni.NewFakeRunner(), rec: rec, log: &order}
	h := ipv6TestHost(t, runner, &deleted)
	path, ip, err := h.Realize(context.Background(), Slot{SandboxID: "sb-v6"})
	if err != nil || path == "" || ip == "" {
		t.Fatalf("Realize: path=%q ip=%q err=%v", path, ip, err)
	}
	calls := rec.got()
	if len(calls) != 2 || calls[0] != path || calls[1] != path {
		t.Fatalf("ipv6 writes = %v, want two on %s", calls, path)
	}
	if len(order) != 1 || order[0] != "ipv6-writes-before-add=1" {
		t.Fatalf("CNI ADD ran at %v; the first IPv6 write must come before it", order)
	}
	if len(deleted) != 0 {
		t.Fatalf("netns deleted on success: %v", deleted)
	}
}

// Prewarmed slots come through Realize too: a warm slot is never parked
// with IPv6 on.
func TestPrewarmDisablesIPv6(t *testing.T) {
	rec := &ipv6Recorder{}
	rec.install(t)
	var deleted []string
	p := testPool(t, 2)
	h := ipv6TestHost(t, cni.NewFakeRunner(), &deleted)
	if err := p.Prewarm(context.Background(), h, time.Unix(5, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if calls := rec.got(); len(calls) != 2 || !strings.HasPrefix(calls[0], h.NetnsRoot) {
		t.Fatalf("prewarm ipv6 writes = %v", calls)
	}
}

func TestRealizeIPv6FailureBeforeAddRollsBack(t *testing.T) {
	rec := &ipv6Recorder{fail: map[int]bool{1: true}}
	rec.install(t)
	var deleted []string
	runner := cni.NewFakeRunner()
	h := ipv6TestHost(t, runner, &deleted)
	if _, _, err := h.Realize(context.Background(), Slot{SandboxID: "sb-v6a"}); err == nil || !strings.Contains(err.Error(), "disable ipv6") {
		t.Fatalf("Realize err = %v, want the ipv6 failure", err)
	}
	if len(deleted) != 1 || deleted[0] != "sb-v6a" {
		t.Fatalf("netns not removed after the ipv6 failure: %v", deleted)
	}
	if adds := runner.Adds(); len(adds) != 0 {
		t.Fatalf("CNI ADD ran %d times after the ipv6 write failed", len(adds))
	}
}

// A failure after ADD undoes the attachment the way Remove does: CNI DEL
// under the same identity, then the netns.
func TestRealizeIPv6FailureAfterAddRemovesAttachment(t *testing.T) {
	rec := &ipv6Recorder{fail: map[int]bool{2: true}}
	rec.install(t)
	var deleted []string
	runner := cni.NewFakeRunner()
	h := ipv6TestHost(t, runner, &deleted)
	_, _, err := h.Realize(context.Background(), Slot{SandboxID: "sb-v6b"})
	if err == nil || !strings.Contains(err.Error(), "after cni add") {
		t.Fatalf("Realize err = %v, want the post-ADD ipv6 failure", err)
	}
	dels := runner.Dels()
	if len(dels) != 1 || dels[0].ContainerID != "sb-v6b" {
		t.Fatalf("CNI DEL = %+v, want one for sb-v6b", dels)
	}
	if len(deleted) != 1 || deleted[0] != "sb-v6b" {
		t.Fatalf("netns not removed: %v", deleted)
	}
}

func TestHostDisableIPv6(t *testing.T) {
	rec := &ipv6Recorder{}
	rec.install(t)
	h := &Host{}
	if err := h.DisableIPv6(context.Background(), Slot{SlotID: "s"}); err == nil {
		t.Fatal("a slot with no netns path must fail")
	}
	if err := h.DisableIPv6(context.Background(), Slot{NetnsPath: "/run/netns/aerol-netns-3"}); err != nil {
		t.Fatal(err)
	}
	if calls := rec.got(); len(calls) != 1 || calls[0] != "/run/netns/aerol-netns-3" {
		t.Fatalf("calls = %v", calls)
	}
}

// survivorPool builds one pooled (warm) slot and one adopted slot, as an
// older daemon would have left them, and returns their netns paths.
func survivorPool(t *testing.T) (*Pool, *Host, *[]string, string, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(10, 0).UTC()
	var deleted []string
	p := testPool(t, 3)
	h := ipv6TestHost(t, cni.NewFakeRunner(), &deleted)
	if err := p.Prewarm(ctx, h, now); err != nil {
		t.Fatal(err)
	}
	slot, err := NewBuilder(p, h).Build(ctx, "sb-live")
	if err != nil {
		t.Fatal(err)
	}
	st, err := p.st.ListNonFreeContainerNetnsSlots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pooled := ""
	for _, s := range st {
		if s.State == store.NetnsSlotStatePooled {
			pooled = s.NetnsPath
		}
	}
	if pooled == "" {
		t.Fatalf("no pooled slot in %+v", st)
	}
	return p, h, &deleted, pooled, slot.NetnsPath
}

// TestReconcileDisablesIPv6InSurvivors: on upgrade, the boot reconcile
// turns IPv6 off in every slot that survives, warm or in use.
func TestReconcileDisablesIPv6InSurvivors(t *testing.T) {
	p, h, deleted, pooled, adopted := survivorPool(t)
	rec := &ipv6Recorder{}
	rec.install(t)
	live := func(context.Context, string) bool { return true }
	exists := func(string) bool { return true }
	reaped, err := p.Reconcile(context.Background(), h, live, exists, time.Unix(20, 0).UTC())
	if err != nil || reaped != 0 {
		t.Fatalf("reconcile: reaped=%d err=%v", reaped, err)
	}
	got := map[string]bool{}
	for _, c := range rec.got() {
		got[c] = true
	}
	if !got[pooled] || !got[adopted] || len(got) != 2 {
		t.Fatalf("ipv6 writes = %v, want %s and %s", rec.got(), pooled, adopted)
	}
	if len(*deleted) != 0 {
		t.Fatalf("survivors torn down: %v", *deleted)
	}
}

// A warm slot whose IPv6 cannot be turned off is rebuilt, never handed out;
// a live sandbox's slot is kept (the node fence still holds) and logged.
func TestReconcileSurvivorIPv6Failure(t *testing.T) {
	p, h, deleted, pooled, adopted := survivorPool(t)
	orig := disableIPv6InNetns
	disableIPv6InNetns = func(string) error { return errors.New("sysctl boom") }
	t.Cleanup(func() { disableIPv6InNetns = orig })
	live := func(context.Context, string) bool { return true }
	exists := func(string) bool { return true }
	reaped, err := p.Reconcile(context.Background(), h, live, exists, time.Unix(20, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped = %d, want the warm slot only", reaped)
	}
	pooledName := pooled[strings.LastIndex(pooled, "/")+1:]
	adoptedName := adopted[strings.LastIndex(adopted, "/")+1:]
	if len(*deleted) != 1 || (*deleted)[0] != pooledName {
		t.Fatalf("deleted = %v, want only %s (not the live %s)", *deleted, pooledName, adoptedName)
	}
	if s, _ := p.Get(context.Background(), "sb-live"); s == nil || s.State != store.NetnsSlotStateAdopted {
		t.Fatalf("live slot after reconcile = %+v", s)
	}
}

// A HostManager without the step (the fake) reconciles as before.
func TestReconcileWithoutIPv6Step(t *testing.T) {
	p := testPool(t, 2)
	if _, err := NewBuilder(p, NewFakeHost()).Build(context.Background(), "sb-f"); err != nil {
		t.Fatal(err)
	}
	if !p.disableSurvivorIPv6(context.Background(), NewFakeHost(), &Slot{NetnsPath: "/run/netns/x"}) {
		t.Fatal("a host without the step must not fail the slot")
	}
	if !p.disableSurvivorIPv6(context.Background(), &Host{}, &Slot{}) {
		t.Fatal("a slot with no path has nothing to do")
	}
}
