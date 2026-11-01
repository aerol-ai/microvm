package netns

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/store"
)

// restoredMachine is UC-316's node after its backup was restored onto a
// fresh disk: the fresh install's daemon prewarmed aerol-netns-0 on this
// host (CNI gave it the runner's first address), and the database is the
// backup's, whose pooled row for the same name records the old machine's
// address.
type restoredMachine struct {
	pool     *Pool
	host     *Host
	runner   *cni.FakeRunner
	deleted  *[]string
	exists   NetnsExists
	freshIP  string
	backupIP string
}

func newRestoredMachine(t *testing.T) restoredMachine {
	t.Helper()
	ctx := context.Background()
	runner := cni.NewFakeRunner()
	var deleted []string
	h := ipv6TestHost(t, runner, &deleted)

	fresh := testPool(t, 4)
	if err := fresh.Prewarm(ctx, h, time.Unix(1, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	freshIP, ok := runner.IPOf(slotNamePrefix + "0")
	if !ok {
		t.Fatal("the fresh install did not prewarm aerol-netns-0")
	}

	restored := testPool(t, 4)
	const backupIP = "10.88.2.111"
	slot, err := restored.st.BeginPrewarmContainerNetnsSlot(ctx, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if slot.SlotID != slotNamePrefix+"0" {
		t.Fatalf("restored prewarm took %s", slot.SlotID)
	}
	if err := restored.st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, filepath.Join(h.NetnsRoot, slot.SlotID), backupIP, time.Unix(2, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	exists := func(path string) bool { _, ok := runner.IPOf(filepath.Base(path)); return ok }
	return restoredMachine{pool: restored, host: h, runner: runner, deleted: &deleted, exists: exists, freshIP: freshIP, backupIP: backupIP}
}

// TestReconcileRebuildsRestoredWarmSlotAtAnotherAddress is the regression
// test for UC-316 (single-node-wrapped-kms): after a restore onto a fresh
// machine, the first create failed "sandbox came up at 10.88.0.2, not at
// its prepaid address 10.88.2.111". The boot reconcile kept the backup's
// warm row because a netns of that name existed, and the claim handed out
// the backup's address for a namespace that holds the fresh install's.
// Now the reconcile rebuilds it, and the slot a create is handed holds
// exactly the address it is handed.
func TestReconcileRebuildsRestoredWarmSlotAtAnotherAddress(t *testing.T) {
	ctx := context.Background()
	m := newRestoredMachine(t)
	if m.freshIP == m.backupIP {
		t.Fatalf("precondition: the two addresses must differ (%s)", m.freshIP)
	}

	reaped, err := m.pool.Reconcile(ctx, m.host, nil, m.exists, time.Unix(3, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped = %d, want the restored warm slot rebuilt", reaped)
	}
	// Torn down under the slot's own identity: the fresh install's lease
	// and netns for aerol-netns-0 are gone, not leaked.
	if dels := m.runner.Dels(); len(dels) != 1 || dels[0].ContainerID != slotNamePrefix+"0" {
		t.Fatalf("CNI DEL = %+v, want one for aerol-netns-0", dels)
	}
	if len(*m.deleted) != 1 || (*m.deleted)[0] != slotNamePrefix+"0" {
		t.Fatalf("netns deleted = %v", *m.deleted)
	}
	if stats, _ := m.pool.Stats(ctx); stats.Pooled != 0 {
		t.Fatalf("stats after reconcile = %+v, want no warm slot", stats)
	}

	if err := m.pool.Prewarm(ctx, m.host, time.Unix(4, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	path, ip, err := NewRuntimeHandoff(m.pool, m.host).Provision(ctx, "sb-after-restore")
	if err != nil {
		t.Fatal(err)
	}
	holds, _ := m.host.IPv4Addrs(ctx, Slot{NetnsPath: path})
	if !slices.Contains(holds, ip) {
		t.Fatalf("handed %s at %s, whose netns holds %v", ip, path, holds)
	}
	if ip == m.backupIP {
		t.Fatalf("handed the backup's address %s", ip)
	}
}

// The teardown of a mismatched warm slot can fail like any other: the slot
// is parked as releasing, never handed out, and a create builds its own.
func TestReconcileMismatchedWarmSlotTeardownFailureParks(t *testing.T) {
	ctx := context.Background()
	m := newRestoredMachine(t)
	m.runner.SetDelError(errors.New("cni del boom"))
	reaped, err := m.pool.Reconcile(ctx, m.host, nil, m.exists, time.Unix(3, 0).UTC())
	if err != nil || reaped != 0 {
		t.Fatalf("reaped=%d err=%v, want a failed teardown counted as not reaped", reaped, err)
	}
	stats, _ := m.pool.Stats(ctx)
	if stats.Pooled != 0 || stats.Releasing != 1 {
		t.Fatalf("stats = %+v, want the slot parked as releasing", stats)
	}
	m.runner.SetDelError(nil)
	path, ip, err := NewRuntimeHandoff(m.pool, m.host).Provision(ctx, "sb-cold")
	if err != nil {
		t.Fatal(err)
	}
	if ip == m.backupIP || filepath.Base(path) != "sb-cold" {
		t.Fatalf("provisioned %s at %s, want a cold build of its own", ip, path)
	}
}

// What the reconcile does with a surviving warm slot for each answer the
// host gives about its namespace.
func TestReconcileWarmSlotAddressAnswers(t *testing.T) {
	cases := []struct {
		name     string
		read     func(recorded string) ([]string, error)
		wantKept bool
	}{
		{"holds_its_address", func(ip string) ([]string, error) { return []string{ip}, nil }, true},
		{"holds_it_among_others", func(ip string) ([]string, error) { return []string{"10.88.9.9", ip}, nil }, true},
		{"holds_another", func(string) ([]string, error) { return []string{"10.88.0.2"}, nil }, false},
		{"holds_none", func(string) ([]string, error) { return nil, nil }, false},
		{"unreadable", func(string) ([]string, error) { return nil, errors.New("netlink: permission denied") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p, h, deleted, pooled, _ := survivorPool(t)
			slot := pooledRow(t, p)
			h.readIPv4 = func(path string) ([]string, error) {
				if path != pooled {
					t.Errorf("read %s; only the warm slot %s may be asked", path, pooled)
				}
				return tc.read(slot.ContainerIP)
			}
			live := func(context.Context, string) bool { return true }
			reaped, err := p.Reconcile(ctx, h, live, func(string) bool { return true }, time.Unix(20, 0).UTC())
			if err != nil {
				t.Fatal(err)
			}
			stats, _ := p.Stats(ctx)
			if tc.wantKept {
				if reaped != 0 || stats.Pooled != 1 || len(*deleted) != 0 {
					t.Fatalf("reaped=%d stats=%+v deleted=%v, want the warm slot kept", reaped, stats, *deleted)
				}
				return
			}
			if reaped != 1 || stats.Pooled != 0 || len(*deleted) != 1 || (*deleted)[0] != filepath.Base(pooled) {
				t.Fatalf("reaped=%d stats=%+v deleted=%v, want only the warm slot rebuilt", reaped, stats, *deleted)
			}
			if s, _ := p.Get(ctx, "sb-live"); s == nil || s.State != store.NetnsSlotStateAdopted {
				t.Fatalf("the live sandbox's slot = %+v", s)
			}
		})
	}
}

// A slot with an owner is never asked, even when its namespace would not
// answer: a gVisor task moves the address out of it, and a live sandbox's
// slot is not the pool's to rebuild.
func TestReconcileNeverReadsAnOwnedSlot(t *testing.T) {
	p, h, deleted, pooled, adopted := survivorPool(t)
	var mu sync.Mutex
	var asked []string
	h.readIPv4 = func(path string) ([]string, error) {
		mu.Lock()
		asked = append(asked, path)
		mu.Unlock()
		if path == adopted {
			return nil, errors.New("no address: gVisor holds it")
		}
		return runnerAddrs(h.Runner)(path)
	}
	live := func(context.Context, string) bool { return true }
	reaped, err := p.Reconcile(context.Background(), h, live, func(string) bool { return true }, time.Unix(20, 0).UTC())
	if err != nil || reaped != 0 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
	if len(asked) != 1 || asked[0] != pooled {
		t.Fatalf("asked %v, want only the warm slot %s", asked, pooled)
	}
	if len(*deleted) != 0 {
		t.Fatalf("deleted %v", *deleted)
	}
}

// A HostManager that cannot read addresses (the fake) keeps the earlier
// behaviour; a row with no recorded address cannot be vouched for.
func TestWarmSlotHoldsItsAddressEdges(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	if !p.warmSlotHoldsItsAddress(ctx, NewFakeHost(), &Slot{NetnsPath: "/run/netns/x", ContainerIP: "10.88.0.2"}) {
		t.Fatal("a host without the step must not fail the slot")
	}
	h := &Host{readIPv4: func(string) ([]string, error) { return []string{"10.88.0.2"}, nil }}
	if p.warmSlotHoldsItsAddress(ctx, h, &Slot{NetnsPath: "/run/netns/x"}) {
		t.Fatal("a warm row with no recorded address must be rebuilt")
	}
	if !p.warmSlotHoldsItsAddress(ctx, h, &Slot{NetnsPath: "/run/netns/x", ContainerIP: " 10.88.0.2 "}) {
		t.Fatal("the recorded address is compared trimmed")
	}
}

func TestHostIPv4Addrs(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Host{}).IPv4Addrs(ctx, Slot{SlotID: "s"}); err == nil {
		t.Fatal("a slot with no netns path must fail")
	}
	var got string
	h := &Host{readIPv4: func(path string) ([]string, error) { got = path; return []string{"10.88.0.7"}, nil }}
	addrs, err := h.IPv4Addrs(ctx, Slot{NetnsPath: " /run/netns/aerol-netns-7 "})
	if err != nil || len(addrs) != 1 || addrs[0] != "10.88.0.7" || got != "/run/netns/aerol-netns-7" {
		t.Fatalf("addrs=%v err=%v path=%q", addrs, err, got)
	}
	// Production reads the real namespace: one that is not there is an
	// error on every platform, never an empty "holds nothing".
	if _, err := (&Host{}).IPv4Addrs(ctx, Slot{NetnsPath: filepath.Join(t.TempDir(), "gone")}); err == nil || !strings.Contains(err.Error(), "netns") {
		t.Fatalf("missing netns = %v", err)
	}
}

func pooledRow(t *testing.T, p *Pool) store.ContainerNetnsSlot {
	t.Helper()
	rows, err := p.st.ListContainerNetnsSlotsByState(context.Background(), store.NetnsSlotStatePooled)
	if err != nil || len(rows) != 1 {
		t.Fatalf("pooled rows = %+v err=%v", rows, err)
	}
	return rows[0]
}
