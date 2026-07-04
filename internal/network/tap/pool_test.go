package tap

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// newTestStore opens a fresh SQLite-backed store in a temp dir. Mirrors
// the helper in internal/store/store_test.go but inlined here so the
// tap package's tests don't grow a hidden cross-package dep.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSeed_ValidatesInputs(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("zero pool size", func(t *testing.T) {
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/16", PoolSize: 0}, now); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("pool size cap", func(t *testing.T) {
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "10.0.0.0/8", PoolSize: 10001}, now); err == nil {
			t.Fatal("expected cap rejection")
		}
	})
	t.Run("malformed cidr", func(t *testing.T) {
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "not-a-cidr", PoolSize: 4}, now); err == nil {
			t.Fatal("expected parse error")
		}
	})
	t.Run("cidr too small", func(t *testing.T) {
		// /29 = 8 addresses → at most 2 /30s. Asking for 4 must fail.
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/29", PoolSize: 4}, now); err == nil {
			t.Fatal("expected too-small CIDR rejection")
		}
	})
	t.Run("ipv6 rejected", func(t *testing.T) {
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "fd00::/64", PoolSize: 4}, now); err == nil {
			t.Fatal("expected IPv6 rejection")
		}
	})
}

// TestSeed_LayoutMath confirms the /30 walk produces non-overlapping
// subnets, correct host/guest IPs, and vsock CIDs starting at 3. The
// layout is consumed by the host-side `ip` invocations in a follow-up
// file; a regression here would silently misroute guest traffic.
func TestSeed_LayoutMath(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 4}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// We can't list pool rows directly through the wrapper (by design;
	// callers go through Allocate). Drive Allocate against four
	// throwaway sandboxes and assert the slots we get back form the
	// expected layout. Allocate orders by tap_name ASC so the first
	// allocation gets fctap0, etc.
	wantSlots := []Slot{
		{TapName: "fctap0", CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3},
		{TapName: "fctap1", CIDR: "172.16.0.4/30", HostIP: "172.16.0.5", GuestIP: "172.16.0.6", VsockCID: 4},
		{TapName: "fctap2", CIDR: "172.16.0.8/30", HostIP: "172.16.0.9", GuestIP: "172.16.0.10", VsockCID: 5},
		{TapName: "fctap3", CIDR: "172.16.0.12/30", HostIP: "172.16.0.13", GuestIP: "172.16.0.14", VsockCID: 6},
	}
	for i, want := range wantSlots {
		sb := newTestSandbox(t, st, "sb-layout-"+iToS(i))
		got, err := p.Allocate(ctx, sb, now)
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if *got != want {
			t.Errorf("slot %d = %+v, want %+v", i, *got, want)
		}
	}
}

// TestSeed_Idempotent confirms re-Seeding with the same config does not
// duplicate rows or shuffle vsock CIDs. The daemon's boot path may
// re-Seed on every startup.
func TestSeed_Idempotent(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	cfg := SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 3}

	if err := p.Seed(ctx, cfg, now); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if err := p.Seed(ctx, cfg, now); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	stats, err := p.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d after duplicate seed, want 3", stats.Total)
	}
}

// TestAllocate_GetRelease drives the full lifecycle.
func TestAllocate_GetRelease(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 2}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sb := newTestSandbox(t, st, "sb-rt")

	// Allocate
	first, err := p.Allocate(ctx, sb, now)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if first.TapName != "fctap0" {
		t.Errorf("first.TapName = %q, want fctap0", first.TapName)
	}

	// Idempotent re-Allocate
	again, err := p.Allocate(ctx, sb, now)
	if err != nil {
		t.Fatalf("re-allocate: %v", err)
	}
	if again.TapName != first.TapName {
		t.Errorf("re-allocate returned different slot: %q vs %q", again.TapName, first.TapName)
	}

	// Get
	g, err := p.Get(ctx, sb)
	if err != nil || g == nil {
		t.Fatalf("get: err=%v g=%+v", err, g)
	}
	if g.VsockCID != 3 {
		t.Errorf("VsockCID = %d, want 3", g.VsockCID)
	}

	// Release
	if err := p.Release(ctx, sb); err != nil {
		t.Fatalf("release: %v", err)
	}
	g2, err := p.Get(ctx, sb)
	if err != nil {
		t.Fatalf("get after release: %v", err)
	}
	if g2 != nil {
		t.Errorf("get after release = %+v, want nil", g2)
	}
}

// TestAllocate_PoolExhausted confirms the exhaustion sentinel surfaces
// through the wrapper unchanged. The runtime driver depends on this
// error identity to map to a clean admission failure.
func TestAllocate_PoolExhausted(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 1}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sb1 := newTestSandbox(t, st, "sb-1")
	sb2 := newTestSandbox(t, st, "sb-2")
	if _, err := p.Allocate(ctx, sb1, now); err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	_, err := p.Allocate(ctx, sb2, now)
	if !errors.Is(err, store.ErrNoFreeFirecrackerTapSlot) {
		t.Fatalf("expected ErrNoFreeFirecrackerTapSlot, got %v", err)
	}
}

func TestTransfer_RekeysOwner(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 2}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	warm, err := p.Allocate(ctx, "vmms-warm", now)
	if err != nil {
		t.Fatalf("allocate warm: %v", err)
	}
	got, err := p.Transfer(ctx, "vmms-warm", "sb-claimed", now.Add(time.Second))
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if got.TapName != warm.TapName || got.GuestIP != warm.GuestIP || got.VsockCID != warm.VsockCID {
		t.Fatalf("transferred slot = %+v, want same identity as %+v", got, warm)
	}
	if old, err := p.Get(ctx, "vmms-warm"); err != nil || old != nil {
		t.Fatalf("old owner get = %+v err=%v, want nil nil", old, err)
	}
	if claimed, err := p.Get(ctx, "sb-claimed"); err != nil || claimed == nil || claimed.TapName != warm.TapName {
		t.Fatalf("new owner get = %+v err=%v, want %s", claimed, err, warm.TapName)
	}
}

func TestTransfer_TargetAlreadyHasSlot(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 2}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := p.Allocate(ctx, "vmms-warm", now); err != nil {
		t.Fatalf("allocate warm: %v", err)
	}
	target, err := p.Allocate(ctx, "sb-target", now)
	if err != nil {
		t.Fatalf("allocate target: %v", err)
	}
	if _, err := p.Transfer(ctx, "vmms-warm", "sb-target", now); err == nil {
		t.Fatal("expected conflict transferring onto an existing different target slot")
	}
	if got, err := p.Get(ctx, "sb-target"); err != nil || got == nil || got.TapName != target.TapName {
		t.Fatalf("target changed after failed transfer: %+v err=%v", got, err)
	}
}

func TestTransfer_SourceMissing(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 1}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := p.Transfer(ctx, "missing", "sb-target", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("transfer missing source err = %v, want ErrNotFound", err)
	}
}

func TestTransfer_RetryIsIdempotent(t *testing.T) {
	st := newTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 1}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	first, err := p.Allocate(ctx, "vmms-warm", now)
	if err != nil {
		t.Fatalf("allocate warm: %v", err)
	}
	if _, err := p.Transfer(ctx, "vmms-warm", "sb-target", now); err != nil {
		t.Fatalf("first transfer: %v", err)
	}
	again, err := p.Transfer(ctx, "vmms-warm", "sb-target", now)
	if err != nil {
		t.Fatalf("retry transfer: %v", err)
	}
	if again.TapName != first.TapName {
		t.Fatalf("retry returned %s, want %s", again.TapName, first.TapName)
	}
}

// TestTransfer_ConcurrentDuplicate is the fragile-area idempotency
// regression (pr-review.md rule #1): racing Transfers of one slot must
// resolve to exactly one owner with no partial state. The ownership
// change is a single atomic UPDATE keyed on the source id, so of N
// racers to distinct targets exactly one wins; duplicates retrying the
// SAME target must all succeed idempotently.
func TestTransfer_ConcurrentDuplicate(t *testing.T) {
	t.Run("same target", func(t *testing.T) {
		st := newTestStore(t)
		p := New(st)
		ctx := context.Background()
		now := time.Now().UTC()
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 2}, now); err != nil {
			t.Fatalf("seed: %v", err)
		}
		warm, err := p.Allocate(ctx, "vmms-warm", now)
		if err != nil {
			t.Fatalf("allocate warm: %v", err)
		}

		const racers = 8
		var wg sync.WaitGroup
		results := make([]*Slot, racers)
		errs := make([]error, racers)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = p.Transfer(ctx, "vmms-warm", "sb-claimed", now)
			}(i)
		}
		wg.Wait()

		for i := 0; i < racers; i++ {
			if errs[i] != nil {
				t.Fatalf("racer %d: duplicate transfer must be idempotent, got %v", i, errs[i])
			}
			if results[i] == nil || results[i].TapName != warm.TapName {
				t.Fatalf("racer %d: slot = %+v, want %s", i, results[i], warm.TapName)
			}
		}
		if old, err := p.Get(ctx, "vmms-warm"); err != nil || old != nil {
			t.Fatalf("old owner get = %+v err=%v, want nil nil", old, err)
		}
	})

	t.Run("distinct targets", func(t *testing.T) {
		st := newTestStore(t)
		p := New(st)
		ctx := context.Background()
		now := time.Now().UTC()
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 2}, now); err != nil {
			t.Fatalf("seed: %v", err)
		}
		warm, err := p.Allocate(ctx, "vmms-warm", now)
		if err != nil {
			t.Fatalf("allocate warm: %v", err)
		}

		const racers = 4
		var wg sync.WaitGroup
		errs := make([]error, racers)
		targets := make([]string, racers)
		for i := 0; i < racers; i++ {
			targets[i] = fmt.Sprintf("sb-racer-%d", i)
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = p.Transfer(ctx, "vmms-warm", targets[i], now)
			}(i)
		}
		wg.Wait()

		wins := 0
		for i := 0; i < racers; i++ {
			if errs[i] == nil {
				wins++
				got, err := p.Get(ctx, targets[i])
				if err != nil || got == nil || got.TapName != warm.TapName {
					t.Fatalf("winner %s get = %+v err=%v, want %s", targets[i], got, err, warm.TapName)
				}
			}
		}
		if wins != 1 {
			t.Fatalf("winners = %d, want exactly 1", wins)
		}
		if old, err := p.Get(ctx, "vmms-warm"); err != nil || old != nil {
			t.Fatalf("old owner get = %+v err=%v, want nil nil", old, err)
		}
	})
}

// newTestSandbox inserts a row into sandboxes so the firecracker_tap_pool
// allocate doesn't break referential expectations. The pool table does
// NOT carry a FOREIGN KEY on sandbox_id (the table seeds before any
// sandbox exists, so a FK would order-break the seed loop) — but the
// reconcile path correlates the two by ID, so the tests model a real
// sandbox row.
func newTestSandbox(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	// The pool's allocate path does not actually read the sandboxes
	// table — it only writes the sandbox_id string into the pool row.
	// We can skip creating a sandbox row and still exercise the pool
	// correctly. The string ID is enough.
	return id
}

func iToS(i int) string {
	if i == 0 {
		return "0"
	}
	d := []byte{}
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}
