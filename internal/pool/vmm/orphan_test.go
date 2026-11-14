package vmm

import (
	"context"
	"errors"
	"testing"
	"time"
)

// recordingCleaner is an OrphanCleaner that fails while err is set.
type recordingCleaner struct {
	slots []Slot
	err   error
}

func (c *recordingCleaner) CleanupOrphanSlot(_ context.Context, slot Slot) error {
	c.slots = append(c.slots, slot)
	return c.err
}

// A released slot the pool holds no handle for (after a daemon restart no
// handle survives) is torn down through the OrphanCleaner before its row
// goes. The reap used to delete the row straight away, and with it the
// only record of the slot's run dir and TAP device.
func TestPool_ReapReleasedTearsDownSlotsWithNoHandle(t *testing.T) {
	cases := []struct {
		name        string
		handle      bool  // the pool still holds the slot's handle
		cleanErr    error // the first teardown fails
		wantCleaned int   // teardown calls on the first pass
		wantKept    bool  // the row survives the first pass
	}{
		{name: "left by a restart", wantCleaned: 1},
		{name: "teardown fails", cleanErr: errors.New("tap busy"), wantCleaned: 1, wantKept: true},
		{name: "handle in memory", handle: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p, st := newTestPool(t)
			cleaner := &recordingCleaner{err: tc.cleanErr}
			p.SetOrphanCleaner(cleaner)
			old := time.Now().UTC().Add(-2 * time.Hour)
			if err := p.RecordSpawning(ctx, "vmms-a", "tpl-a", old); err != nil {
				t.Fatal(err)
			}
			if err := p.RecordLoaded(ctx, "vmms-a", "/run/fc/vmms-a/api.sock", "/run/fc/vmms-a", 7, old); err != nil {
				t.Fatal(err)
			}
			if tc.handle {
				p.registerHandle("vmms-a", &stubHandle{api: "/run/fc/vmms-a/api.sock", run: "/run/fc/vmms-a"})
			}
			// What a restart does to a loaded row no handle survives for.
			if _, err := p.releaseOrphanedRowsAtStart(ctx, old); err != nil {
				t.Fatal(err)
			}

			deleted, err := p.ReapReleased(ctx, time.Now().UTC())
			if err != nil {
				t.Fatalf("reap: %v", err)
			}
			if len(cleaner.slots) != tc.wantCleaned {
				t.Fatalf("teardown calls = %d, want %d", len(cleaner.slots), tc.wantCleaned)
			}
			if tc.wantCleaned > 0 && (cleaner.slots[0].ID != "vmms-a" || cleaner.slots[0].RunDir != "/run/fc/vmms-a" || cleaner.slots[0].APISocket != "/run/fc/vmms-a/api.sock") {
				t.Fatalf("teardown got %+v, want the row's slot", cleaner.slots[0])
			}
			stats, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl-a")
			if err != nil {
				t.Fatal(err)
			}
			if kept := stats.Total == 1; kept != tc.wantKept || (deleted == 1) == tc.wantKept {
				t.Fatalf("after the first pass: deleted %d, rows %d; want kept=%v", deleted, stats.Total, tc.wantKept)
			}
			if !tc.wantKept {
				return
			}

			cleaner.err = nil
			if deleted, err := p.ReapReleased(ctx, time.Now().UTC()); err != nil || deleted != 1 {
				t.Fatalf("second pass = %d, %v; want the row gone once teardown works", deleted, err)
			}
		})
	}
}
