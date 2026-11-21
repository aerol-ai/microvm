package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// setTemplateGOARCH sets the architecture the sweep checks for one test,
// and puts the real one back after it.
func setTemplateGOARCH(t *testing.T, goarch string) {
	t.Helper()
	orig := templateGOARCH
	templateGOARCH = goarch
	t.Cleanup(func() { templateGOARCH = orig })
}

// seedTemplateSavedWith is seedReadyTemplate with the snapshot's
// nested-virtualization record ("" leaves it unknown).
func seedTemplateSavedWith(t *testing.T, st *store.Store, templatesDir, id, saved string) *models.Template {
	t.Helper()
	tpl := seedReadyTemplate(t, st, templatesDir, id)
	if saved == "" {
		return tpl
	}
	if err := st.UpdateTemplateSnapshotReady(context.Background(), id, tpl.SnapshotMemoryPath, tpl.SnapshotStatePath,
		tpl.SnapshotSizeBytes, tpl.SnapshotChecksum, tpl.SnapshotVsockCID, true, saved); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetTemplate(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// serialSnapshotter wraps the fake snapshotter, records the most saves that
// ran at once, and runs hook (if set) in the middle of each save.
type serialSnapshotter struct {
	inner          *fakeTemplateSnapshotter
	inFlight, most atomic.Int32
	hook           func(req TemplateSnapshotRequest)
}

func (s *serialSnapshotter) SnapshotTemplate(ctx context.Context, req TemplateSnapshotRequest) (*TemplateSnapshotResult, error) {
	n := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		m := s.most.Load()
		if n <= m || s.most.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	if s.hook != nil {
		s.hook(req)
	}
	return s.inner.SnapshotTemplate(ctx, req)
}

// At start, every ready template saved under another setting than this
// node's is saved again, one at a time, to new files, and stays ready the
// whole time; the rest are left alone. The next start removes the files the
// rows no longer name.
func TestResaveTemplateSnapshotsForNestedVirtAtStart(t *testing.T) {
	setTemplateGOARCH(t, "amd64")
	for _, tc := range []struct {
		name        string
		nodeAllowed bool
		resaved     []string
		kept        []string
	}{
		{"node hides", false, []string{"tpl-unknown", "tpl-on"}, []string{"tpl-off"}},
		{"node allows", true, []string{"tpl-off"}, []string{"tpl-unknown", "tpl-on"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, st, templatesDir := newHealthHarness(t)
			svc.cfg.FirecrackerNestedVirt = tc.nodeAllowed
			before := map[string]*models.Template{}
			for id, saved := range map[string]string{"tpl-unknown": "", "tpl-on": "on", "tpl-off": "off"} {
				before[id] = seedTemplateSavedWith(t, st, templatesDir, id, saved)
			}
			seedReadyTemplate(t, st, templatesDir, "tpl-unhealthy")
			if _, err := st.MarkTemplateUnhealthy(ctx, "tpl-unhealthy", "being rebuilt"); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-no-snapshot", Image: "docker://alpine:3.19",
				Status: models.TemplateStatusReadyNoSnapshot, RootfsPath: "/r", CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			want := "off"
			if tc.nodeAllowed {
				want = "on"
			}
			// Mid-save, every template is still ready and still has its old
			// snapshot: creates keep loading it.
			var notReady atomic.Int32
			snapper := &serialSnapshotter{inner: &fakeTemplateSnapshotter{done: make(chan struct{}, 8), nestedVirt: want}}
			snapper.hook = func(req TemplateSnapshotRequest) {
				got, err := st.GetTemplate(ctx, req.TemplateID)
				if err != nil || got.Status != models.TemplateStatusReady || !got.HasSnapshot ||
					got.SnapshotMemoryPath != before[req.TemplateID].SnapshotMemoryPath {
					notReady.Add(1)
				}
			}
			svc.SetTemplateSnapshotter(snapper)
			svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

			svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
			if !svc.WaitForTemplateRebuilds(10 * time.Second) {
				t.Fatal("saves did not finish")
			}
			if snapper.inner.calls != len(tc.resaved) || snapper.most.Load() > 1 || notReady.Load() != 0 {
				t.Fatalf("saves: %d (want %d), at most %d at once (want 1), %d saw the template out of service",
					snapper.inner.calls, len(tc.resaved), snapper.most.Load(), notReady.Load())
			}
			for _, id := range tc.resaved {
				got, err := st.GetTemplate(ctx, id)
				if err != nil || got.Status != models.TemplateStatusReady || !got.HasSnapshot || got.SnapshotNestedVirt != want ||
					got.SnapshotMemoryPath == before[id].SnapshotMemoryPath || got.SnapshotStatePath == before[id].SnapshotStatePath {
					t.Fatalf("%s after the save = %+v, %v; want ready, new files, saved with %q", id, got, err, want)
				}
				for _, p := range []string{got.SnapshotMemoryPath, got.SnapshotStatePath, before[id].SnapshotMemoryPath} {
					if _, err := os.Stat(p); err != nil {
						t.Fatalf("%s: %s missing after the save: %v (a running clone may still use the old file)", id, p, err)
					}
				}
			}
			for _, id := range tc.kept {
				if got, _ := st.GetTemplate(ctx, id); got.SnapshotMemoryPath != before[id].SnapshotMemoryPath {
					t.Fatalf("%s was saved again: %+v", id, got)
				}
			}
			for id, status := range map[string]models.TemplateStatus{
				"tpl-unhealthy": models.TemplateStatusUnhealthy, "tpl-no-snapshot": models.TemplateStatusReadyNoSnapshot,
			} {
				if got, _ := st.GetTemplate(ctx, id); got.Status != status {
					t.Fatalf("%s moved to %s; the sweep only reads ready rows", id, got.Status)
				}
			}

			// The next start removes the old snapshot files, and nothing else.
			svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
			if !svc.WaitForTemplateRebuilds(10 * time.Second) {
				t.Fatal("second start did not settle")
			}
			if snapper.inner.calls != len(tc.resaved) {
				t.Fatalf("the second start saved again: %d saves", snapper.inner.calls)
			}
			for _, id := range tc.resaved {
				got, _ := st.GetTemplate(ctx, id)
				if _, err := os.Stat(before[id].SnapshotMemoryPath); !os.IsNotExist(err) {
					t.Fatalf("%s: the old memory file is still there: %v", id, err)
				}
				for _, p := range []string{got.SnapshotMemoryPath, got.SnapshotStatePath, got.RootfsPath} {
					if _, err := os.Stat(p); err != nil {
						t.Fatalf("%s: %s was removed: %v", id, p, err)
					}
				}
			}
		})
	}
}

// A save drops its files and leaves the row alone when the template moved
// on meanwhile, and when the snapshotter fails; the template keeps its old
// snapshot either way, for the next start to try again.
func TestResaveTemplateSnapshotLeavesTheTemplateAsItWas(t *testing.T) {
	setTemplateGOARCH(t, "amd64")
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		set  func(st *store.Store, s *serialSnapshotter)
		want error
	}{
		{"moved on", func(st *store.Store, s *serialSnapshotter) {
			s.hook = func(req TemplateSnapshotRequest) {
				if err := st.UpdateTemplateSnapshotReady(ctx, req.TemplateID, "/elsewhere.memory", "/elsewhere.state", 1,
					"sha256:rebuilt|sha256:rebuilt", 42, true, ""); err != nil {
					t.Error(err)
				}
			}
		}, errTemplateMovedOn},
		{"snapshotter fails", func(_ *store.Store, s *serialSnapshotter) { s.inner.err = errors.New("vmm boot timeout") }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, templatesDir := newHealthHarness(t)
			tpl := seedReadyTemplate(t, st, templatesDir, "tpl-race")
			snapper := &serialSnapshotter{inner: &fakeTemplateSnapshotter{done: make(chan struct{}, 1), nestedVirt: "off"}}
			tc.set(st, snapper)
			svc.SetTemplateSnapshotter(snapper)
			svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

			err := svc.resaveTemplateSnapshot(ctx, tpl)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("resave = %v, want an error (%v)", err, tc.want)
			}
			entries, _ := os.ReadDir(filepath.Dir(tpl.RootfsPath))
			for _, e := range entries {
				if isTemplateSnapshotFile(e.Name()) && e.Name() != snapshotMemoryFilename && e.Name() != snapshotStateFilename {
					t.Fatalf("a dropped save left %s", e.Name())
				}
			}
			if got, _ := st.GetTemplate(ctx, tpl.ID); got.Status != models.TemplateStatusReady || !got.HasSnapshot {
				t.Fatalf("the template left service: %+v", got)
			}
		})
	}

	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-no-cid")
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{done: make(chan struct{}, 1)})
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{allocateErr: errors.New("cid exhausted")})
	if err := svc.resaveTemplateSnapshot(ctx, tpl); err == nil {
		t.Fatal("a save with no CID returned no error")
	}
}

// A failed save is logged and the next template still gets its turn.
func TestResaveTemplateSnapshotsContinuesAfterAFailure(t *testing.T) {
	setTemplateGOARCH(t, "amd64")
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	seedReadyTemplate(t, st, templatesDir, "tpl-a")
	seedReadyTemplate(t, st, templatesDir, "tpl-b")
	var calls atomic.Int32
	snapper := &serialSnapshotter{inner: &fakeTemplateSnapshotter{done: make(chan struct{}, 2), nestedVirt: "off"}}
	snapper.hook = func(TemplateSnapshotRequest) {
		if calls.Add(1) == 1 {
			snapper.inner.mu.Lock()
			snapper.inner.err = errors.New("first save fails")
			snapper.inner.mu.Unlock()
			return
		}
		snapper.inner.mu.Lock()
		snapper.inner.err = nil
		snapper.inner.mu.Unlock()
	}
	svc.SetTemplateSnapshotter(snapper)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
	if !svc.WaitForTemplateRebuilds(10 * time.Second) {
		t.Fatal("saves did not finish")
	}
	saved := 0
	for _, id := range []string{"tpl-a", "tpl-b"} {
		if got, _ := st.GetTemplate(ctx, id); got.SnapshotNestedVirt == "off" {
			saved++
		}
	}
	if calls.Load() != 2 || saved != 1 {
		t.Fatalf("saves tried %d, done %d; want 2 tried, 1 done", calls.Load(), saved)
	}
}

// Where nothing is hidden (arm64), no template is saved again; without the
// snapshot pipeline nothing happens at all; a store that cannot list is
// logged.
func TestResaveTemplateSnapshotsForNestedVirtAtStartEdges(t *testing.T) {
	ctx := context.Background()
	setTemplateGOARCH(t, "arm64")
	svc, st, templatesDir := newHealthHarness(t)
	seedReadyTemplate(t, st, templatesDir, "tpl-unknown")
	snapper := &fakeTemplateSnapshotter{done: make(chan struct{}, 1)}
	svc.SetTemplateSnapshotter(snapper)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
	if !svc.WaitForTemplateRebuilds(10*time.Second) || snapper.calls != 0 {
		t.Fatalf("arm64 saved %d templates again", snapper.calls)
	}

	setTemplateGOARCH(t, "amd64")
	unwired, st2, dir2 := newHealthHarness(t)
	seedReadyTemplate(t, st2, dir2, "tpl-unknown")
	unwired.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
	if got, _ := st2.GetTemplate(ctx, "tpl-unknown"); got.Status != models.TemplateStatusReady {
		t.Fatalf("an unwired sweep moved the template: %+v", got)
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
}

func TestIsTemplateSnapshotFile(t *testing.T) {
	for name, want := range map[string]bool{
		"snapshot.memory": true, "snapshot.state": true, "snapshot.k3j2.memory": true, "snapshot.k3j2.state": true,
		"rootfs.ext4": false, "manifest.json": false, "snapshot.memory.bak": false, "snapshots": false,
	} {
		if got := isTemplateSnapshotFile(name); got != want {
			t.Errorf("isTemplateSnapshotFile(%q) = %v, want %v", name, got, want)
		}
	}
}

// A re-save and a rebuild of one template never run their snapshot VMs at
// once: both use the VM id tpl-snap-<id>, its TAP slot and its run dir.
// The re-save, which lost the row to the rebuild, drops its files.
func TestTemplateSnapshotVMsOfOneTemplateTakeTurns(t *testing.T) {
	setTemplateGOARCH(t, "amd64")
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-turns")
	entered, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	snapper := &serialSnapshotter{inner: &fakeTemplateSnapshotter{done: make(chan struct{}, 2), nestedVirt: "off"}}
	snapper.hook = func(TemplateSnapshotRequest) {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	}
	svc.SetTemplateSnapshotter(snapper)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	resaveErr := make(chan error, 1)
	go func() { resaveErr <- svc.resaveTemplateSnapshot(ctx, tpl) }()
	<-entered
	if _, err := st.MarkTemplateUnhealthy(ctx, tpl.ID, "operator-requested"); err != nil {
		t.Fatal(err)
	}
	rebuildErr := make(chan error, 1)
	go func() { rebuildErr <- svc.RebuildTemplateSnapshot(ctx, tpl.ID) }()
	time.Sleep(20 * time.Millisecond) // the rebuild is now waiting for its turn
	close(release)

	if err := <-resaveErr; !errors.Is(err, errTemplateMovedOn) {
		t.Fatalf("re-save = %v, want errTemplateMovedOn (the rebuild took the row)", err)
	}
	if err := <-rebuildErr; err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if snapper.most.Load() != 1 || snapper.inner.calls != 2 {
		t.Fatalf("snapshot VMs: %d at once (want 1), %d in all (want 2)", snapper.most.Load(), snapper.inner.calls)
	}
	got, _ := st.GetTemplate(ctx, tpl.ID)
	if got.Status != models.TemplateStatusReady || got.SnapshotNestedVirt != "off" {
		t.Fatalf("after both: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(tpl.RootfsPath))
	snapshots := 0
	for _, e := range entries {
		if isTemplateSnapshotFile(e.Name()) {
			snapshots++
		}
	}
	if snapshots != 2 {
		t.Fatalf("%d snapshot files left, want the rebuild's 2 (the old pair and the dropped re-save's are gone)", snapshots)
	}
}

// A re-save reads the row again under the lock, and does nothing for a
// template that no longer needs it.
func TestResaveSkipsATemplateThatNoLongerNeedsIt(t *testing.T) {
	setTemplateGOARCH(t, "amd64")
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	listed := seedReadyTemplate(t, st, templatesDir, "tpl-fixed")
	// Saved again with this node's setting after the sweep listed it.
	if err := st.UpdateTemplateSnapshotReady(ctx, listed.ID, listed.SnapshotMemoryPath, listed.SnapshotStatePath,
		listed.SnapshotSizeBytes, listed.SnapshotChecksum, listed.SnapshotVsockCID, true, "off"); err != nil {
		t.Fatal(err)
	}
	snapper := &fakeTemplateSnapshotter{done: make(chan struct{}, 1)}
	svc.SetTemplateSnapshotter(snapper)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	if err := svc.resaveTemplateSnapshot(ctx, listed); !errors.Is(err, errTemplateMovedOn) || snapper.calls != 0 {
		t.Fatalf("re-save of a template already saved with this setting = %v, %d VMs booted; want errTemplateMovedOn, 0", err, snapper.calls)
	}
	if err := st.DeleteTemplate(ctx, "tpl-fixed"); err != nil {
		t.Fatal(err)
	}
	if err := svc.resaveTemplateSnapshot(ctx, listed); err == nil {
		t.Fatal("re-save of a deleted template returned no error")
	}
}

// A rebuild saves to new names and then removes the old pair, so repeated
// rebuilds (rotation) do not pile memory files up.
func TestRebuildRemovesTheOldSnapshotFiles(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-rotate")
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{done: make(chan struct{}, 2), nestedVirt: "off"})
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	for round := 0; round < 2; round++ {
		before, _ := st.GetTemplate(ctx, tpl.ID)
		if _, err := st.MarkTemplateUnhealthy(ctx, tpl.ID, "rotation"); err != nil {
			t.Fatal(err)
		}
		if err := svc.RebuildTemplateSnapshot(ctx, tpl.ID); err != nil {
			t.Fatalf("rebuild %d: %v", round, err)
		}
		got, _ := st.GetTemplate(ctx, tpl.ID)
		if got.SnapshotMemoryPath == before.SnapshotMemoryPath {
			t.Fatalf("rebuild %d wrote the old name in place", round)
		}
		for _, p := range []string{before.SnapshotMemoryPath, before.SnapshotStatePath} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatalf("rebuild %d left %s: %v", round, p, err)
			}
		}
		for _, p := range []string{got.SnapshotMemoryPath, got.SnapshotStatePath} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("rebuild %d: new file %s: %v", round, p, err)
			}
		}
	}
}

// A save queued behind another save of the same template gets its whole
// timeout: the clock starts once it holds the lock. Here the lock is held
// for longer than the timeout; both the rebuild and the re-save still
// finish.
func TestTemplateSaveTimeoutStartsOnceTheLockIsHeld(t *testing.T) {
	setTemplateGOARCH(t, "amd64")
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	// Long enough for a rebuild's own store writes under a loaded CI
	// runner; the lock is held half as long again, past it.
	svc.cfg.FirecrackerTemplateBuildTimeout = time.Second
	seedReadyTemplate(t, st, templatesDir, "tpl-rebuild")
	seedReadyTemplate(t, st, templatesDir, "tpl-resave")
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{done: make(chan struct{}, 4), nestedVirt: "off"})
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	unlockRebuild := svc.lockTemplateSnapshot("tpl-rebuild")
	unlockResave := svc.lockTemplateSnapshot("tpl-resave")
	if err := svc.MarkSnapshotCorrupt(ctx, "tpl-rebuild", "rotation"); err != nil {
		t.Fatal(err)
	}
	svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
	time.Sleep(1500 * time.Millisecond) // longer than the timeout
	unlockRebuild()
	unlockResave()
	if !svc.WaitForTemplateRebuilds(10 * time.Second) {
		t.Fatal("saves did not finish")
	}
	for id, want := range map[string]string{"tpl-rebuild": "", "tpl-resave": "off"} {
		got, _ := st.GetTemplate(ctx, id)
		if got.Status != models.TemplateStatusReady || !got.HasSnapshot {
			t.Fatalf("%s after waiting longer than its timeout: %+v; the wait used up its time", id, got)
		}
		if want != "" && got.SnapshotNestedVirt != want {
			t.Fatalf("%s record = %q, want %q", id, got.SnapshotNestedVirt, want)
		}
	}
}

// lockRefs is the number of callers holding or waiting on a template's
// lock, 0 when it has no entry.
func lockRefs(svc *Service, id string) int {
	svc.templateSnapshotLocksMu.Lock()
	defer svc.templateSnapshotLocksMu.Unlock()
	if l := svc.templateSnapshotLocks[id]; l != nil {
		return l.refs
	}
	return 0
}

func waitForRefs(t *testing.T, svc *Service, id string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for lockRefs(svc, id) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d callers on the lock, want %d", id, lockRefs(svc, id), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// The lock table drops an entry only when its last holder or waiter is
// gone. A waiter that takes the lock over keeps the entry, so a caller who
// arrives later waits for it rather than getting a second lock for the
// same template; once everyone is done, the table is empty.
func TestTemplateSnapshotLockTableEmptiesAndExcludes(t *testing.T) {
	svc := &Service{}
	unlockFirst := svc.lockTemplateSnapshot("tpl-one")

	waiterHolds := make(chan func())
	go func() { waiterHolds <- svc.lockTemplateSnapshot("tpl-one") }()
	waitForRefs(t, svc, "tpl-one", 2)
	unlockFirst()
	unlockWaiter := <-waiterHolds

	// The waiter holds the lock now. A caller who comes later must wait.
	lateHolds := make(chan func(), 1)
	go func() { lateHolds <- svc.lockTemplateSnapshot("tpl-one") }()
	waitForRefs(t, svc, "tpl-one", 2)
	select {
	case unlock := <-lateHolds:
		unlock()
		t.Fatal("a later caller took the template's lock while the waiter held it: two locks for one template")
	case <-time.After(50 * time.Millisecond):
	}
	unlockWaiter()
	(<-lateHolds)()

	if n := lockRefs(svc, "tpl-one"); n != 0 {
		t.Fatalf("%d callers left on the lock after everyone unlocked", n)
	}
	svc.templateSnapshotLocksMu.Lock()
	left := len(svc.templateSnapshotLocks)
	svc.templateSnapshotLocksMu.Unlock()
	if left != 0 {
		t.Fatalf("lock table has %d entries after everyone unlocked, want 0", left)
	}
}
