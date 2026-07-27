package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestContainerNetnsPrewarmClaimRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()

	for i := 0; i < 3; i++ {
		if err := st.SeedContainerNetnsSlot(ctx, "aerol-netns-"+iToStr(i), now); err != nil {
			t.Fatalf("SeedContainerNetnsSlot: %v", err)
		}
	}

	// Refill path: claim free → realize as pooled (sandbox_id cleared).
	slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatalf("BeginPrewarmContainerNetnsSlot: %v", err)
	}
	if slot.State != NetnsSlotStateReserved || slot.SandboxID != slot.SlotID {
		t.Fatalf("prewarm reserved = %+v, want state=reserved sandbox_id=slot_id", slot)
	}

	if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/var/run/netns/"+slot.SlotID, "10.88.0.2", now); err != nil {
		t.Fatalf("FinishPrewarmContainerNetnsSlot: %v", err)
	}

	pooled, err := st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStatePooled)
	if err != nil || len(pooled) != 1 {
		t.Fatalf("pooled = %d err=%v, want 1", len(pooled), err)
	}
	if pooled[0].SandboxID != "" || pooled[0].NetnsPath == "" || pooled[0].ContainerIP != "10.88.0.2" {
		t.Fatalf("pooled slot = %+v", pooled[0])
	}

	claimed, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-warm-1", now)
	if err != nil {
		t.Fatalf("ClaimPooledContainerNetnsSlot: %v", err)
	}
	if claimed.State != NetnsSlotStateAdopted || claimed.SandboxID != "sb-warm-1" {
		t.Fatalf("claimed = %+v, want adopted by sb-warm-1", claimed)
	}

	// Idempotent reclaim for the same sandbox must not walk the pool again.
	again, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-warm-1", now)
	if err != nil || again.SlotID != claimed.SlotID {
		t.Fatalf("idempotent claim = %+v err=%v", again, err)
	}

	nonFree, err := st.ListNonFreeContainerNetnsSlots(ctx)
	if err != nil {
		t.Fatalf("ListNonFreeContainerNetnsSlots: %v", err)
	}
	if len(nonFree) != 1 || nonFree[0].State != NetnsSlotStateAdopted {
		t.Fatalf("non-free = %+v, want one adopted", nonFree)
	}

	if err := st.ResetContainerNetnsSlotToFree(ctx, claimed.SlotID, now); err != nil {
		t.Fatalf("ResetContainerNetnsSlotToFree: %v", err)
	}
	stats, err := st.GetContainerNetnsPoolStats(ctx)
	if err != nil {
		t.Fatalf("GetContainerNetnsPoolStats: %v", err)
	}
	if stats.Free != 3 || stats.Adopted != 0 {
		t.Fatalf("stats after reset = %+v, want free=3 adopted=0", stats)
	}
}

func TestContainerNetnsPrewarmValidationAndMisses(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := st.BeginPrewarmContainerNetnsSlot(ctx, now); !errors.Is(err, ErrNoFreeContainerNetnsSlot) {
		t.Fatalf("empty pool begin = %v, want ErrNoFreeContainerNetnsSlot", err)
	}
	if _, err := st.ClaimPooledContainerNetnsSlot(ctx, "", now); err == nil {
		t.Fatal("empty sandbox claim")
	}
	if _, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-x", now); !errors.Is(err, ErrNoPooledContainerNetnsSlot) {
		t.Fatalf("no pooled = %v, want ErrNoPooledContainerNetnsSlot", err)
	}

	if err := st.FinishPrewarmContainerNetnsSlot(ctx, "", "/n", "10.0.0.1", now); err == nil {
		t.Fatal("finish missing slot_id")
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, "s", "", "10.0.0.1", now); err == nil {
		t.Fatal("finish missing netns_path")
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, "s", "/n", "", now); err == nil {
		t.Fatal("finish missing container_ip")
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, "ghost", "/n", "10.0.0.1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finish unknown = %v, want ErrNotFound", err)
	}
	if err := st.ResetContainerNetnsSlotToFree(ctx, "", now); err == nil {
		t.Fatal("reset empty slot_id")
	}
	if err := st.ResetContainerNetnsSlotToFree(ctx, "ghost", now); err != nil {
		t.Fatalf("reset missing slot should be no-op: %v", err)
	}

	nonFree, err := st.ListNonFreeContainerNetnsSlots(ctx)
	if err != nil || len(nonFree) != 0 {
		t.Fatalf("empty non-free = %v err=%v", nonFree, err)
	}
}

func TestContainerNetnsFinishWrongOwnerState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)

	// Finish only matches sandbox_id == slot_id AND state=reserved (prewarm shape).
	_, err := st.ReserveContainerNetnsSlot(ctx, "sb-real", now)
	if err != nil {
		t.Fatalf("ReserveContainerNetnsSlot: %v", err)
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, "aerol-netns-0", "/n", "10.0.0.9", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finish against sandbox-owned reserved = %v, want ErrNotFound", err)
	}
}

func TestContainerNetnsMarkRealizedConflictAndWrongState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-r", now)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "sb-r", "/n1", "10.0.0.1", now)

	// Already realized with different paths must fail (not silently rewrite).
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "sb-r", "/n2", "10.0.0.2", now); err == nil {
		t.Fatal("expected conflict on different realized network")
	}
	// Same paths is idempotent.
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "sb-r", "/n1", "10.0.0.1", now); err != nil {
		t.Fatalf("idempotent realize: %v", err)
	}

	_, _ = st.AdoptContainerNetnsSlot(ctx, "sb-r", now)
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "sb-r", "/n3", "10.0.0.3", now); err == nil {
		t.Fatal("expected conflict on adopted with different network")
	}
}

func TestContainerNetnsAdoptWrongStateAndReassignEdges(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-1", now)

	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-park", now)
	if _, err := st.AdoptContainerNetnsSlot(ctx, "sb-park", now); err == nil {
		t.Fatal("adopt reserved (not realized) should fail")
	}
	if _, err := st.AdoptContainerNetnsSlot(ctx, "ghost", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("adopt missing = %v", err)
	}

	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "sb-park", "/n", "10.0.0.5", now)
	_, _ = st.AdoptContainerNetnsSlot(ctx, "sb-park", now)

	if err := st.ReassignContainerNetnsSandbox(ctx, "", "to", now); err == nil {
		t.Fatal("reassign empty from")
	}
	if err := st.ReassignContainerNetnsSandbox(ctx, "from", "", now); err == nil {
		t.Fatal("reassign empty to")
	}
	if err := st.ReassignContainerNetnsSandbox(ctx, "sb-park", "sb-park", now); err != nil {
		t.Fatalf("same-id reassign: %v", err)
	}
	// Target already owns a slot → no-op success (warm park collision).
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-other", now)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "sb-other", "/n2", "10.0.0.6", now)
	_, _ = st.AdoptContainerNetnsSlot(ctx, "sb-other", now)
	if err := st.ReassignContainerNetnsSandbox(ctx, "sb-park", "sb-other", now); err != nil {
		t.Fatalf("reassign when target owns: %v", err)
	}
	if err := st.ReassignContainerNetnsSandbox(ctx, "ghost-from", "ghost-to", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reassign missing source = %v, want ErrNotFound", err)
	}
}

func TestContainerNetnsListByStateValidationAndGetEmpty(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.ListContainerNetnsSlotsByState(ctx, ""); err == nil {
		t.Fatal("empty state list")
	}
	if _, err := st.GetContainerNetnsSlotBySandbox(ctx, ""); err == nil {
		t.Fatal("empty sandbox get")
	}
	slot, err := st.GetContainerNetnsSlotBySandbox(ctx, "nobody")
	if err != nil || slot != nil {
		t.Fatalf("missing get = %+v err=%v", slot, err)
	}
}

func TestContainerNetnsPrewarmContestedPool(t *testing.T) {
	// Concurrent BeginPrewarm on a single free row exercises the
	// RowsAffected=0 retry loop; one winner, the rest either succeed on
	// later free rows or surface exhaustion.
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-"+iToStr(i), now)
	}

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	var ok, exhausted int
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrNoFreeContainerNetnsSlot):
			exhausted++
		default:
			t.Fatalf("unexpected begin err: %v", err)
		}
	}
	if ok != 4 {
		t.Fatalf("begin winners = %d exhausted=%d, want 4 winners", ok, exhausted)
	}

	// Finish all reserved-as-self slots into pooled, then race Claim.
	reserved, err := st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateReserved)
	if err != nil {
		t.Fatalf("list reserved: %v", err)
	}
	for _, slot := range reserved {
		if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/n/"+slot.SlotID, "10.0.0."+slot.SlotID[len(slot.SlotID)-1:], now); err != nil {
			t.Fatalf("finish %s: %v", slot.SlotID, err)
		}
	}

	wg = sync.WaitGroup{}
	wg.Add(n)
	claimErrs := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-claim-"+iToStr(i), now)
			claimErrs <- err
		}()
	}
	wg.Wait()
	close(claimErrs)

	ok, miss := 0, 0
	for err := range claimErrs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrNoPooledContainerNetnsSlot):
			miss++
		default:
			t.Fatalf("unexpected claim err: %v", err)
		}
	}
	if ok != 4 {
		t.Fatalf("claim winners = %d miss=%d, want 4", ok, miss)
	}
}

func TestContainerNetnsClosedDBErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.Close()

	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb", now)
	_, _ = st.BeginPrewarmContainerNetnsSlot(ctx, now)
	_ = st.FinishPrewarmContainerNetnsSlot(ctx, "aerol-netns-0", "/n", "10.0.0.1", now)
	_, _ = st.ClaimPooledContainerNetnsSlot(ctx, "sb", now)
	_, _ = st.ListNonFreeContainerNetnsSlots(ctx)
	_ = st.ResetContainerNetnsSlotToFree(ctx, "aerol-netns-0", now)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "sb", "/n", "10.0.0.1", now)
	_, _ = st.AdoptContainerNetnsSlot(ctx, "sb", now)
	_ = st.ReleaseContainerNetnsSlot(ctx, "sb", now)
	_ = st.ReassignContainerNetnsSandbox(ctx, "a", "b", now)
	_, _ = st.GetContainerNetnsSlotBySandbox(ctx, "sb")
	_, _ = st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateFree)
	_, _ = st.GetContainerNetnsPoolStats(ctx)
}
