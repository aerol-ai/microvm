package cluster

import (
	"errors"
	"os"
	"testing"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

func applyPlaceWithSpec(t *testing.T, fsm *placementFSM, id string) string {
	t.Helper()
	c, err := encodeCommand(command{
		Op: opPlace, SandboxID: id, OwnerNodeID: "node-a", OwnerAPIURL: "http://a",
		Spec: &models.CreateSandboxRequest{Image: "img-" + id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := fsm.Apply(&raft.Log{Data: c}); res != nil {
		t.Fatalf("apply %s: %v", id, res)
	}
	p, ok := fsm.get(id)
	if !ok || p.RecoveryRef == "" {
		t.Fatalf("placement %s has no recovery blob: %+v", id, p)
	}
	return p.RecoveryRef
}

func requireBlob(t *testing.T, store *placementRecoveryFileStore, ref, why string) {
	t.Helper()
	if _, ok, err := store.Get(ref); err != nil || !ok {
		t.Fatalf("%s: blob %s is gone (ok=%v err=%v)", why, ref, ok, err)
	}
}

// TestSnapshotGCKeepsBlobsPutWhileItPersists: the GC that ends a snapshot
// keeps only the refs the last snapshots name. A create applied after the
// snapshot read its rows, while it was still being written, has a live row
// whose blob no snapshot names yet; the GC used to delete it, and failover
// then found no recovery spec for that sandbox.
func TestSnapshotGCKeepsBlobsPutWhileItPersists(t *testing.T) {
	fsm, err := newPlacementFSMWithFileRecovery(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := fsm.recoveryStore.(*placementRecoveryFileStore)
	refA := applyPlaceWithSpec(t, fsm, "sb-a")
	orphan, err := store.Put("sb-orphan", recoveryFor("orphan"))
	if err != nil {
		t.Fatal(err)
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	refB := applyPlaceWithSpec(t, fsm, "sb-b") // applied mid-snapshot
	if err := snap.Persist(&orderSink{}); err != nil {
		t.Fatal(err)
	}
	snap.Release()

	requireBlob(t, store, refA, "a row the snapshot named")
	requireBlob(t, store, refB, "a row applied while the snapshot was written")
	if _, ok, _ := store.Get(orphan); ok {
		t.Fatal("a blob no row names and no open snapshot saw Put must still be collected")
	}

	// The next snapshot names sb-b itself, so its blob stays without the
	// tracking (which Release ended).
	snap, err = fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.Persist(&orderSink{}); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	requireBlob(t, store, refB, "a row the next snapshot named")
	if store.openSnapshots != 0 || store.putSince != nil {
		t.Fatalf("tracking left on after every snapshot was released: open=%d putSince=%v", store.openSnapshots, store.putSince)
	}
}

// TestSnapshotGCOverlappingSnapshotsAndDoubleRelease: with two snapshots
// open, releasing the first (twice, as a defensive caller might) must not
// end the tracking the second still needs.
func TestSnapshotGCOverlappingSnapshotsAndDoubleRelease(t *testing.T) {
	fsm, err := newPlacementFSMWithFileRecovery(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := fsm.recoveryStore.(*placementRecoveryFileStore)
	applyPlaceWithSpec(t, fsm, "sb-a")

	first, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	second, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	first.Release()
	refX := applyPlaceWithSpec(t, fsm, "sb-x")
	if err := second.Persist(&orderSink{}); err != nil {
		t.Fatal(err)
	}
	requireBlob(t, store, refX, "a row applied while the second snapshot was open")
	second.Release()
	if store.openSnapshots != 0 {
		t.Fatalf("open snapshots = %d after both released", store.openSnapshots)
	}
}

// TestRecoveryFileStoreGCKeepsABlobPutAgainMidSnapshot: Put skips the write
// when the blob is already there (same name = same bytes). An orphan blob
// that a row takes up again while a snapshot is open is therefore never
// rewritten, and only the tracking tells the GC it is live again.
func TestRecoveryFileStoreGCKeepsABlobPutAgainMidSnapshot(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Put("sb", recoveryFor("i"))
	if err != nil {
		t.Fatal(err)
	}
	store.BeginSnapshot()
	if again, err := store.Put("sb", recoveryFor("i")); err != nil || again != ref {
		t.Fatalf("second Put = %q, %v; want %q", again, err, ref)
	}
	if err := store.RetainSnapshotRefs(nil); err != nil {
		t.Fatal(err)
	}
	requireBlob(t, store, ref, "a blob Put again while a snapshot was open")
	store.EndSnapshot()
	store.EndSnapshot() // one too many: ignored
	if err := store.RetainSnapshotRefs(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Get(ref); ok {
		t.Fatal("once no snapshot is open and none names it, the blob must be collected")
	}
}

// TestRecoveryFileStoreSyncRunsEveryBlobAndKeepsOnlyFailuresDirty: Sync
// fsyncs every dirty blob (several at once), and on failure keeps only the
// blobs whose fsync failed for the next Sync.
func TestRecoveryFileStoreSyncRunsEveryBlobAndKeepsOnlyFailuresDirty(t *testing.T) {
	log := countFsyncs(t)
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, img := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t"} {
		ref, err := store.Put("sb-"+img, recoveryFor(img))
		if err != nil {
			t.Fatal(err)
		}
		path, _ := store.pathForRef(ref)
		paths = append(paths, path)
	}
	bad := paths[7]
	log.fail[bad] = errors.New("disk on fire")
	if err := store.Sync(); err == nil {
		t.Fatal("Sync should fail when one blob's fsync fails")
	}
	got := log.take()
	for _, path := range paths {
		if !containsString(got, path) {
			t.Fatalf("Sync stopped before fsyncing %s; every blob gets its try", path)
		}
	}
	delete(log.fail, bad)
	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !equalStrings(got, sortedStrings(bad, store.dir)) {
		t.Fatalf("the retry fsynced %v, want only the failed blob and the dir", got)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Fatal(err)
	}
}
