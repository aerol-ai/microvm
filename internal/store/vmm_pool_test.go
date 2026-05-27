package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestFirecrackerVMMPool covers the persistent state machine that
// backs the warm-VMM pool (plans/snapshot-clone-fast-boot.md, Phase 4
// PR-A). It mirrors the firecracker_tap_pool regression block in
// store_test.go in spirit: every CRUD path, the partial unique index
// rejection, idempotency under retry, and the allocator's behavior
// under concurrent contention. Any change to the table or to
// AllocateFirecrackerVMMSlot must re-run these — they are the
// load-bearing assertions for the pr-review.md §5 fragility class.
func TestFirecrackerVMMPool(t *testing.T) {
	ctx := context.Background()

	// seedSlot is a small helper to insert a slot in 'spawning' state
	// for the given (slotID, templateID). Kept local to this test
	// because the store-level Insert validates and rejects malformed
	// rows — the helper just generates the boilerplate we want.
	seedSlot := func(t *testing.T, st *Store, slotID, templateID string, now time.Time) {
		t.Helper()
		if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{
			ID:         slotID,
			TemplateID: templateID,
		}, now); err != nil {
			t.Fatalf("seed slot %q: %v", slotID, err)
		}
	}
	// loadSlot promotes a 'spawning' slot to 'loaded'. Bakes in
	// non-reserved CIDs so the store guard is satisfied.
	loadSlot := func(t *testing.T, st *Store, slotID string, vsockCID uint32, now time.Time) {
		t.Helper()
		if err := st.MarkFirecrackerVMMSlotLoaded(ctx, slotID,
			"/run/sandboxd/"+slotID+"/api.sock",
			"/run/sandboxd/"+slotID,
			vsockCID, now); err != nil {
			t.Fatalf("mark slot %q loaded: %v", slotID, err)
		}
	}

	t.Run("insert_validates_required_fields", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{}, now); err == nil {
			t.Fatal("expected error on empty id+template_id")
		}
		if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "vmms-x"}, now); err == nil {
			t.Fatal("expected error on missing template_id")
		}
		// Anything other than 'spawning' (or empty, which we coerce to
		// 'spawning') must be rejected so the spawner stays the only
		// path that produces a 'loaded' row.
		err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{
			ID: "vmms-x", TemplateID: "tpl-a", Status: FirecrackerVMMSlotStatusLoaded,
		}, now)
		if err == nil {
			t.Fatal("expected error on pre-loaded insert")
		}
	})

	t.Run("insert_then_mark_loaded_round_trip", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-aaa", "tpl-a", now)

		// A fresh row reads as 'spawning' with the right artifact paths
		// still empty — the spawner hasn't run yet.
		got, err := st.GetFirecrackerVMMSlotByID(ctx, "vmms-aaa")
		if err != nil || got == nil {
			t.Fatalf("get by id: %v / %+v", err, got)
		}
		if got.Status != FirecrackerVMMSlotStatusSpawning {
			t.Fatalf("initial status = %q, want %q", got.Status, FirecrackerVMMSlotStatusSpawning)
		}
		if got.APISocket != "" || got.RunDir != "" || got.VsockCID != 0 {
			t.Fatalf("spawning slot leaked spawner state: %+v", got)
		}

		loadSlot(t, st, "vmms-aaa", 7, now.Add(time.Second))
		got, err = st.GetFirecrackerVMMSlotByID(ctx, "vmms-aaa")
		if err != nil {
			t.Fatalf("get after load: %v", err)
		}
		if got.Status != FirecrackerVMMSlotStatusLoaded {
			t.Fatalf("post-load status = %q, want loaded", got.Status)
		}
		if got.VsockCID != 7 || got.APISocket == "" || got.RunDir == "" {
			t.Fatalf("loaded slot missing artifact fields: %+v", got)
		}
		if got.LoadedAt.IsZero() {
			t.Fatal("loaded_at not stamped")
		}
	})

	t.Run("mark_loaded_rejects_reserved_cid", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-x", "tpl-a", now)
		if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "vmms-x",
			"/run/sock", "/run/dir", 2, now); err == nil {
			t.Fatal("expected reserved-CID rejection")
		}
	})

	t.Run("mark_loaded_only_from_spawning", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-x", "tpl-a", now)
		loadSlot(t, st, "vmms-x", 5, now)
		// Second load attempt against an already-loaded row must miss
		// the WHERE status='spawning' guard and surface ErrNotFound.
		err := st.MarkFirecrackerVMMSlotLoaded(ctx, "vmms-x",
			"/run/other", "/run/other-dir", 6, now.Add(time.Second))
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound on re-load, got %v", err)
		}
	})

	t.Run("mark_failed_moves_spawning_to_released", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-x", "tpl-a", now)
		if err := st.MarkFirecrackerVMMSlotFailed(ctx, "vmms-x", "boom: kernel panic", now); err != nil {
			t.Fatalf("mark failed: %v", err)
		}
		got, err := st.GetFirecrackerVMMSlotByID(ctx, "vmms-x")
		if err != nil || got == nil {
			t.Fatalf("get: %v / %+v", err, got)
		}
		if got.Status != FirecrackerVMMSlotStatusReleased {
			t.Fatalf("status after failed = %q, want released", got.Status)
		}
		if got.LastError == "" {
			t.Fatal("last_error not persisted")
		}
		if got.ReleasedAt.IsZero() {
			t.Fatal("released_at not stamped")
		}
	})

	t.Run("allocate_release_round_trip", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		for i, cid := range []uint32{3, 4, 5} {
			id := fmt.Sprintf("vmms-%d", i)
			seedSlot(t, st, id, "tpl-a", now)
			loadSlot(t, st, id, cid, now)
		}

		// Acquire one for sandbox sb1.
		slot, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb1", now)
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		if slot == nil || slot.SandboxID != "sb1" || slot.Status != FirecrackerVMMSlotStatusAllocated {
			t.Fatalf("allocated slot = %+v", slot)
		}
		if slot.AllocatedAt.IsZero() {
			t.Fatal("allocated_at not stamped")
		}

		// Idempotency: a second Allocate for sb1 returns the same slot
		// without changing the row's state. The TAP pool's idempotency
		// guarantee is mirrored exactly.
		again, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb1", now.Add(time.Second))
		if err != nil {
			t.Fatalf("re-allocate: %v", err)
		}
		if again.ID != slot.ID {
			t.Fatalf("re-allocate returned a different slot: %s vs %s", again.ID, slot.ID)
		}

		// GetBySandbox sees it.
		got, err := st.GetFirecrackerVMMSlotBySandbox(ctx, "sb1")
		if err != nil || got == nil {
			t.Fatalf("get by sandbox: %v / %+v", err, got)
		}
		if got.ID != slot.ID {
			t.Fatalf("get returned %s, want %s", got.ID, slot.ID)
		}

		// Release returns it to 'released' (NOT 'loaded' — no recycling).
		if err := st.ReleaseFirecrackerVMMSlot(ctx, "sb1", now.Add(2*time.Second)); err != nil {
			t.Fatalf("release: %v", err)
		}
		got, err = st.GetFirecrackerVMMSlotByID(ctx, slot.ID)
		if err != nil || got == nil {
			t.Fatalf("post-release get: %v / %+v", err, got)
		}
		if got.Status != FirecrackerVMMSlotStatusReleased {
			t.Fatalf("post-release status = %q, want released (no recycling)", got.Status)
		}
		if got.SandboxID != "" {
			t.Fatalf("post-release sandbox_id = %q, want empty", got.SandboxID)
		}
	})

	t.Run("template_isolation", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		// Two templates with one loaded slot each.
		seedSlot(t, st, "vmms-a", "tpl-a", now)
		seedSlot(t, st, "vmms-b", "tpl-b", now)
		loadSlot(t, st, "vmms-a", 11, now)
		loadSlot(t, st, "vmms-b", 12, now)

		// Acquire for tpl-a — must NOT return tpl-b's slot even though
		// it's also 'loaded' and free.
		slot, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb1", now)
		if err != nil {
			t.Fatalf("allocate tpl-a: %v", err)
		}
		if slot.TemplateID != "tpl-a" {
			t.Fatalf("crossed template lineage: got %s, want tpl-a", slot.TemplateID)
		}
		// Exhausting tpl-a's pool must NOT make Allocate fall through
		// to tpl-b's loaded slot — sentinel only.
		_, err = st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb2", now)
		if !errors.Is(err, ErrNoFreeFirecrackerVMMSlot) {
			t.Fatalf("expected ErrNoFreeFirecrackerVMMSlot for tpl-a exhaustion, got %v", err)
		}
	})

	t.Run("exhaustion_returns_sentinel", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		// No slots at all — Allocate must hit the sentinel immediately,
		// not loop or fabricate a row.
		_, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb1", now)
		if !errors.Is(err, ErrNoFreeFirecrackerVMMSlot) {
			t.Fatalf("expected ErrNoFreeFirecrackerVMMSlot, got %v", err)
		}
		// A row in 'spawning' (not yet 'loaded') also counts as
		// exhausted — the slot isn't claimable until the spawner
		// promotes it.
		seedSlot(t, st, "vmms-x", "tpl-a", now)
		_, err = st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb1", now)
		if !errors.Is(err, ErrNoFreeFirecrackerVMMSlot) {
			t.Fatalf("expected sentinel for spawning-only pool, got %v", err)
		}
	})

	t.Run("partial_unique_index_blocks_double_allocate_raw", func(t *testing.T) {
		// Direct-SQL test of the partial unique index — the Go Allocate
		// path can't trigger it (the idempotency pre-check returns
		// early), but a future code path that issued raw UPDATEs
		// without that check would. Pinning the index here catches a
		// migration that ever drops it.
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-a", "tpl-a", now)
		seedSlot(t, st, "vmms-b", "tpl-a", now)
		loadSlot(t, st, "vmms-a", 3, now)
		loadSlot(t, st, "vmms-b", 4, now)

		if _, err := st.db.ExecContext(ctx, `
			UPDATE firecracker_vmm_pool SET sandbox_id = ?, status = ?
			WHERE id = ?`, "sb1", FirecrackerVMMSlotStatusAllocated, "vmms-a"); err != nil {
			t.Fatalf("first raw update: %v", err)
		}
		_, err := st.db.ExecContext(ctx, `
			UPDATE firecracker_vmm_pool SET sandbox_id = ?, status = ?
			WHERE id = ?`, "sb1", FirecrackerVMMSlotStatusAllocated, "vmms-b")
		if err == nil {
			t.Fatal("expected partial unique index to reject second slot for same sandbox_id")
		}
	})

	t.Run("concurrent_allocate_resolves_exactly_n_winners", func(t *testing.T) {
		// 10 goroutines race Allocate over 3 loaded slots. Exactly 3
		// must win; the other 7 must get the sentinel — never a
		// duplicate claim. SQLite's single-writer model serializes
		// the contest; the allocator's SELECT-then-UPDATE pattern
		// keeps correctness if that ever changes.
		st := newTestStore(t)
		now := time.Now().UTC()
		for i, cid := range []uint32{3, 4, 5} {
			id := fmt.Sprintf("vmms-%d", i)
			seedSlot(t, st, id, "tpl-a", now)
			loadSlot(t, st, id, cid, now)
		}

		const n = 10
		var (
			wg         sync.WaitGroup
			mu         sync.Mutex
			wins       int
			exhausted  int
			otherErrs  []error
			claimedIDs = map[string]struct{}{}
		)
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				slot, err := st.AllocateFirecrackerVMMSlot(ctx,
					"tpl-a", fmt.Sprintf("sb-%d", i), now)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					wins++
					if _, dup := claimedIDs[slot.ID]; dup {
						otherErrs = append(otherErrs, fmt.Errorf("duplicate slot id %s", slot.ID))
					}
					claimedIDs[slot.ID] = struct{}{}
				case errors.Is(err, ErrNoFreeFirecrackerVMMSlot):
					exhausted++
				default:
					otherErrs = append(otherErrs, err)
				}
			}(i)
		}
		close(start)
		wg.Wait()

		if len(otherErrs) > 0 {
			t.Fatalf("unexpected errors: %v", otherErrs)
		}
		if wins != 3 {
			t.Fatalf("winners = %d, want exactly 3", wins)
		}
		if exhausted != n-3 {
			t.Fatalf("exhausted count = %d, want %d", exhausted, n-3)
		}
		if len(claimedIDs) != 3 {
			t.Fatalf("distinct claimed slot ids = %d, want 3", len(claimedIDs))
		}
	})

	t.Run("release_is_idempotent_and_status_gated", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-x", "tpl-a", now)
		loadSlot(t, st, "vmms-x", 3, now)

		// Release before allocate is a no-op.
		if err := st.ReleaseFirecrackerVMMSlot(ctx, "sb-never", now); err != nil {
			t.Fatalf("release before allocate: %v", err)
		}

		if _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb1", now); err != nil {
			t.Fatalf("allocate: %v", err)
		}
		if err := st.ReleaseFirecrackerVMMSlot(ctx, "sb1", now); err != nil {
			t.Fatalf("first release: %v", err)
		}
		// Second release of the same sandbox is also a no-op — the
		// row's status is now 'released', so the WHERE filters it out.
		if err := st.ReleaseFirecrackerVMMSlot(ctx, "sb1", now); err != nil {
			t.Fatalf("idempotent release: %v", err)
		}
	})

	t.Run("list_for_refill_excludes_released", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		// tpl-a layout, by intended terminal status:
		//   vmms-spawning: still in 'spawning' (no load yet)
		//   vmms-loaded:   loaded, no claimant
		//   vmms-failed:   went directly to 'released' via MarkFailed
		//   vmms-claimed:  loaded → allocated → released via Release
		// tpl-b layout: vmms-b loaded (must NOT appear in tpl-a's list).
		seedSlot(t, st, "vmms-spawning", "tpl-a", now)
		seedSlot(t, st, "vmms-loaded", "tpl-a", now)
		seedSlot(t, st, "vmms-failed", "tpl-a", now)
		seedSlot(t, st, "vmms-claimed", "tpl-a", now)
		seedSlot(t, st, "vmms-b", "tpl-b", now)
		loadSlot(t, st, "vmms-loaded", 3, now)
		loadSlot(t, st, "vmms-claimed", 4, now)
		loadSlot(t, st, "vmms-b", 5, now)
		// vmms-failed never loads — drive it straight from spawning to
		// released. Deterministic — does not depend on which row the
		// allocator picks.
		if err := st.MarkFirecrackerVMMSlotFailed(ctx, "vmms-failed", "boom", now); err != nil {
			t.Fatalf("mark failed: %v", err)
		}
		// vmms-claimed: allocate then release. The allocator could pick
		// either vmms-loaded or vmms-claimed (both 'loaded' with
		// identical loaded_at). Whichever it picks, release moves THAT
		// row to 'released' — the assertion below counts rather than
		// names so the test is invariant to the tie-break.
		if _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb-tmp", now); err != nil {
			t.Fatalf("allocate: %v", err)
		}
		if err := st.ReleaseFirecrackerVMMSlot(ctx, "sb-tmp", now); err != nil {
			t.Fatalf("release: %v", err)
		}

		slots, err := st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl-a")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		// Expect: 1 spawning + 1 loaded survivor = 2. Both released
		// rows excluded; tpl-b's row excluded by template_id filter.
		var spawning, loaded, other int
		for _, sl := range slots {
			if sl.TemplateID != "tpl-a" {
				t.Fatalf("crossed-lineage row in tpl-a listing: %+v", sl)
			}
			switch sl.Status {
			case FirecrackerVMMSlotStatusSpawning:
				spawning++
			case FirecrackerVMMSlotStatusLoaded:
				loaded++
			default:
				other++
			}
		}
		if spawning != 1 || loaded != 1 || other != 0 {
			t.Fatalf("list breakdown = spawning=%d loaded=%d other=%d, want 1/1/0; rows=%+v",
				spawning, loaded, other, slots)
		}
	})

	t.Run("list_released_respects_ttl", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-old", "tpl-a", now.Add(-2*time.Hour))
		seedSlot(t, st, "vmms-new", "tpl-a", now)
		if err := st.MarkFirecrackerVMMSlotFailed(ctx, "vmms-old", "old failure", now.Add(-2*time.Hour)); err != nil {
			t.Fatalf("fail old: %v", err)
		}
		if err := st.MarkFirecrackerVMMSlotFailed(ctx, "vmms-new", "new failure", now); err != nil {
			t.Fatalf("fail new: %v", err)
		}

		// Cutoff at -1h should pick up only vmms-old.
		olderThan := now.Add(-1 * time.Hour)
		got, err := st.ListReleasedFirecrackerVMMSlots(ctx, olderThan)
		if err != nil {
			t.Fatalf("list released: %v", err)
		}
		if len(got) != 1 || got[0].ID != "vmms-old" {
			t.Fatalf("ttl filter wrong: got %+v", got)
		}
	})

	t.Run("delete_drops_row", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-x", "tpl-a", now)
		if err := st.DeleteFirecrackerVMMSlot(ctx, "vmms-x"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		got, err := st.GetFirecrackerVMMSlotByID(ctx, "vmms-x")
		if err != nil || got != nil {
			t.Fatalf("expected nil after delete, got %+v / %v", got, err)
		}
		// Double-delete returns ErrNotFound — caller's choice to swallow.
		if err := st.DeleteFirecrackerVMMSlot(ctx, "vmms-x"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("double-delete error = %v, want ErrNotFound", err)
		}
	})

	t.Run("stats_groups_by_status", func(t *testing.T) {
		st := newTestStore(t)
		now := time.Now().UTC()
		seedSlot(t, st, "vmms-a", "tpl-a", now)
		seedSlot(t, st, "vmms-b", "tpl-a", now)
		seedSlot(t, st, "vmms-c", "tpl-a", now)
		seedSlot(t, st, "vmms-d", "tpl-b", now)
		loadSlot(t, st, "vmms-b", 3, now)
		loadSlot(t, st, "vmms-c", 4, now)
		loadSlot(t, st, "vmms-d", 5, now)
		if _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-a", "sb-c", now); err != nil {
			t.Fatalf("allocate: %v", err)
		}
		// tpl-a now has: 1 spawning + 1 loaded + 1 allocated = 3 total
		stats, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl-a")
		if err != nil {
			t.Fatalf("stats: %v", err)
		}
		if stats.Total != 3 || stats.Spawning != 1 || stats.Loaded != 1 || stats.Allocated != 1 {
			t.Fatalf("stats = %+v, want total=3 spawning=1 loaded=1 allocated=1", stats)
		}
		// Stats for tpl-b are computed independently.
		statsB, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl-b")
		if err != nil {
			t.Fatalf("stats b: %v", err)
		}
		if statsB.Total != 1 || statsB.Loaded != 1 {
			t.Fatalf("stats b = %+v, want total=1 loaded=1", statsB)
		}
	})
}
