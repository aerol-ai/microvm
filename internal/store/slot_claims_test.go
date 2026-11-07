package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// slotClaimer is one of the five slot allocators, seen from a test: seed
// fills a fresh store with n claimable slots, claim takes one for owner and
// returns the slot's key, empty is the error a drained pool returns.
type slotClaimer struct {
	name  string
	seed  func(t *testing.T, st *Store, n int)
	claim func(st *Store, owner string) (string, error)
	empty error
	// perOwner is false for the prewarm claim, which has no owner and so
	// cannot be idempotent per caller.
	perOwner bool
}

func slotClaimers() []slotClaimer {
	ctx := context.Background()
	now := time.Now().UTC()
	seedNetns := func(t *testing.T, st *Store, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := st.SeedContainerNetnsSlot(ctx, fmt.Sprintf("aerol-netns-%03d", i), now); err != nil {
				t.Fatalf("seed netns: %v", err)
			}
		}
	}
	return []slotClaimer{
		{
			name: "netns reserve",
			seed: seedNetns,
			claim: func(st *Store, owner string) (string, error) {
				slot, err := st.ReserveContainerNetnsSlot(ctx, owner, now)
				if err != nil {
					return "", err
				}
				return slot.SlotID, nil
			},
			empty:    ErrNoFreeContainerNetnsSlot,
			perOwner: true,
		},
		{
			name: "netns prewarm",
			seed: seedNetns,
			claim: func(st *Store, _ string) (string, error) {
				slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
				if err != nil {
					return "", err
				}
				if slot.SandboxID != slot.SlotID {
					return "", fmt.Errorf("prewarm owner = %q, want the slot's own id %q", slot.SandboxID, slot.SlotID)
				}
				return slot.SlotID, nil
			},
			empty: ErrNoFreeContainerNetnsSlot,
		},
		{
			name: "netns claim pooled",
			seed: func(t *testing.T, st *Store, n int) {
				t.Helper()
				seedNetns(t, st, n)
				for i := 0; i < n; i++ {
					slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
					if err != nil {
						t.Fatalf("prewarm: %v", err)
					}
					if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/run/netns/"+slot.SlotID, fmt.Sprintf("10.1.%d.%d", i/250, i%250+2), now); err != nil {
						t.Fatalf("finish prewarm: %v", err)
					}
				}
			},
			claim: func(st *Store, owner string) (string, error) {
				slot, err := st.ClaimPooledContainerNetnsSlot(ctx, owner, now)
				if err != nil {
					return "", err
				}
				return slot.SlotID, nil
			},
			empty:    ErrNoPooledContainerNetnsSlot,
			perOwner: true,
		},
		{
			name: "firecracker tap",
			seed: func(t *testing.T, st *Store, n int) {
				t.Helper()
				for i := 0; i < n; i++ {
					if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
						TapName: fmt.Sprintf("tap%03d", i), CIDR: fmt.Sprintf("10.2.%d.0/30", i),
						HostIP: fmt.Sprintf("10.2.%d.1", i), GuestIP: fmt.Sprintf("10.2.%d.2", i), VsockCID: uint32(100 + i),
					}, now); err != nil {
						t.Fatalf("seed tap: %v", err)
					}
				}
			},
			claim: func(st *Store, owner string) (string, error) {
				slot, err := st.AllocateFirecrackerTapSlot(ctx, owner, now)
				if err != nil {
					return "", err
				}
				return slot.TapName, nil
			},
			empty:    ErrNoFreeFirecrackerTapSlot,
			perOwner: true,
		},
		{
			name: "firecracker vmm",
			seed: func(t *testing.T, st *Store, n int) {
				t.Helper()
				for i := 0; i < n; i++ {
					id := fmt.Sprintf("vmm-%03d", i)
					if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: id, TemplateID: "tpl"}, now); err != nil {
						t.Fatalf("insert vmm: %v", err)
					}
					if err := st.MarkFirecrackerVMMSlotLoaded(ctx, id, "/run/"+id+".sock", "/run/"+id, uint32(1000+i), now.Add(time.Duration(i)*time.Millisecond)); err != nil {
						t.Fatalf("mark vmm loaded: %v", err)
					}
				}
			},
			claim: func(st *Store, owner string) (string, error) {
				slot, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl", owner, now)
				if err != nil {
					return "", err
				}
				return slot.ID, nil
			},
			empty:    ErrNoFreeFirecrackerVMMSlot,
			perOwner: true,
		},
	}
}

// TestSlotClaimsNeverFailWhileSlotsAreFree is the regression test for the
// read-then-claim allocators: they read the lowest free slot, claimed it only
// if still free, and gave up after 8 lost races. With more than 8 creates
// racing, some failed with "pool contested" while slots were still free (on
// main, 41 of 640 reservations in 20 rounds of 32). Now every claim is one
// statement under the single writer, so with more callers than slots exactly
// the slots' worth succeed, each on its own slot, and every other caller gets
// the typed pool-empty error, never anything else.
func TestSlotClaimsNeverFailWhileSlotsAreFree(t *testing.T) {
	const slots, callers = 48, 64
	for _, c := range slotClaimers() {
		t.Run(c.name, func(t *testing.T) {
			st := newTestStore(t)
			c.seed(t, st, slots)

			type result struct {
				key string
				err error
			}
			results := make(chan result, callers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < callers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					key, err := c.claim(st, fmt.Sprintf("sb-%03d", i))
					results <- result{key, err}
				}(i)
			}
			close(start)
			wg.Wait()
			close(results)

			claimed := map[string]bool{}
			var empty int
			for r := range results {
				switch {
				case r.err == nil:
					if claimed[r.key] {
						t.Fatalf("slot %s handed out twice", r.key)
					}
					claimed[r.key] = true
				case errors.Is(r.err, c.empty):
					empty++
				default:
					t.Fatalf("claim failed with %v while it should either win a slot or see an empty pool", r.err)
				}
			}
			if len(claimed) != slots || empty != callers-slots {
				t.Fatalf("claimed %d slots and %d saw an empty pool; want %d and %d", len(claimed), empty, slots, callers-slots)
			}
		})
	}
}

// TestSlotClaimsSameOwnerGetsOneSlot covers a retried create racing itself:
// concurrent claims for one owner must all return the same slot and take
// only one. Before, both calls could pass the "already own a slot?" check
// before either claimed, and the second claim failed on the unique index.
func TestSlotClaimsSameOwnerGetsOneSlot(t *testing.T) {
	const slots, callers = 8, 16
	for _, c := range slotClaimers() {
		if !c.perOwner {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			st := newTestStore(t)
			c.seed(t, st, slots)

			keys := make(chan string, callers)
			errs := make(chan error, callers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < callers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					key, err := c.claim(st, "sb-same")
					if err != nil {
						errs <- err
						return
					}
					keys <- key
				}()
			}
			close(start)
			wg.Wait()
			close(keys)
			close(errs)
			for err := range errs {
				t.Fatalf("duplicate claim failed: %v", err)
			}
			seen := map[string]bool{}
			for k := range keys {
				seen[k] = true
			}
			if len(seen) != 1 {
				t.Fatalf("one owner got %d different slots, want 1", len(seen))
			}
			// The rest of the pool is untouched: a second owner still gets a slot.
			if _, err := c.claim(st, "sb-other"); err != nil {
				t.Fatalf("second owner: %v", err)
			}
		})
	}
}
