package cluster

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fsyncLog records the paths recoveryStoreFsync is asked to sync, and can
// fail chosen ones.
type fsyncLog struct {
	mu    sync.Mutex
	paths []string
	fail  map[string]error
	// onSync runs before each fsync (an ordering check).
	onSync func(path string)
}

func countFsyncs(t *testing.T) *fsyncLog {
	t.Helper()
	l := &fsyncLog{fail: map[string]error{}}
	prev := recoveryStoreFsync
	recoveryStoreFsync = func(path string) error {
		l.mu.Lock()
		l.paths = append(l.paths, path)
		err := l.fail[path]
		hook := l.onSync
		l.mu.Unlock()
		if hook != nil {
			hook(path)
		}
		if err != nil {
			return err
		}
		return syncFile(path)
	}
	t.Cleanup(func() { recoveryStoreFsync = prev })
	return l
}

func (l *fsyncLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.paths
	l.paths = nil
	sort.Strings(out)
	return out
}

func recoveryFor(image string) placementRecovery {
	return placementRecovery{Spec: &models.CreateSandboxRequest{Image: image}, SecretRef: "s", SecretVersion: 1}
}

// TestRecoveryFileStorePutLeavesSyncToSync: Put writes the blob and does
// not fsync it, Sync then fsyncs every blob Put since the last Sync and the
// directory, once. Put runs on the raft apply loop, where an fsync per blob
// held up every create's reserve and promote.
func TestRecoveryFileStorePutLeavesSyncToSync(t *testing.T) {
	log := countFsyncs(t)
	dir := filepath.Join(t.TempDir(), "recovery")
	store, err := newPlacementRecoveryFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	refA, err := store.Put("sb-a", recoveryFor("a"))
	if err != nil {
		t.Fatal(err)
	}
	refB, err := store.Put("sb-b", recoveryFor("b"))
	if err != nil {
		t.Fatal(err)
	}
	if got := log.take(); len(got) != 0 {
		t.Fatalf("Put fsynced %v; the snapshot syncs blobs, not Put", got)
	}
	for _, ref := range []string{refA, refB} {
		if _, ok, err := store.GetRecord(ref); err != nil || !ok {
			t.Fatalf("GetRecord(%s) = ok %v err %v right after Put", ref, ok, err)
		}
	}

	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	pathA, _ := store.pathForRef(refA)
	pathB, _ := store.pathForRef(refB)
	want := []string{dir, pathA, pathB}
	sort.Strings(want)
	if got := log.take(); !equalStrings(got, want) {
		t.Fatalf("Sync fsynced %v, want %v", got, want)
	}
	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); len(got) != 0 {
		t.Fatalf("a second Sync with nothing new fsynced %v", got)
	}
}

// TestRecoveryFileStorePutSameBlobAgain: a blob already on disk with the
// same bytes is not written again (no unsynced rename over a durable blob),
// but is synced by the next Sync all the same, since a sandboxd that crashed
// may have left it in the page cache only.
func TestRecoveryFileStorePutSameBlobAgain(t *testing.T) {
	log := countFsyncs(t)
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Put("sb", recoveryFor("i"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	log.take()
	path, _ := store.pathForRef(ref)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	again, err := store.Put("sb", recoveryFor("i"))
	if err != nil || again != ref {
		t.Fatalf("Put again = %q, %v; want %q", again, err, ref)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the same blob was written again (renamed over the durable one)")
	}
	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !equalStrings(got, sortedStrings(path, store.dir)) {
		t.Fatalf("Sync after a repeated Put fsynced %v", got)
	}
}

// TestRecoveryFileStorePutRewritesATornBlob: a blob a crash cut short (its
// bytes are not the payload its name hashes) is written again by the Put
// that replays its entry.
func TestRecoveryFileStorePutRewritesATornBlob(t *testing.T) {
	countFsyncs(t)
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Put("sb", recoveryFor("i"))
	if err != nil {
		t.Fatal(err)
	}
	path, _ := store.pathForRef(ref)
	if err := os.WriteFile(path, nil, 0o600); err != nil { // the crash
		t.Fatal(err)
	}
	if _, _, err := store.GetRecord(ref); err == nil {
		t.Fatal("GetRecord of a torn blob should fail")
	}
	if _, err := store.Put("sb", recoveryFor("i")); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := store.GetRecord(ref)
	if err != nil || !ok || rec.Recovery.Spec.Image != "i" {
		t.Fatalf("GetRecord after the replayed Put = %+v ok %v err %v", rec, ok, err)
	}
}

// TestRecoveryFileStoreSyncFailureKeepsBlobsDirty: a Sync that fails leaves
// what it did not sync for the next Sync; a blob removed meanwhile is
// skipped.
func TestRecoveryFileStoreSyncFailureKeepsBlobsDirty(t *testing.T) {
	log := countFsyncs(t)
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Put("sb", recoveryFor("i"))
	if err != nil {
		t.Fatal(err)
	}
	path, _ := store.pathForRef(ref)

	log.fail[path] = errors.New("disk on fire")
	if err := store.Sync(); err == nil {
		t.Fatal("Sync should fail when a blob's fsync fails")
	}
	delete(log.fail, path)
	log.fail[store.dir] = errors.New("dir on fire")
	if err := store.Sync(); err == nil {
		t.Fatal("Sync should fail when the directory's fsync fails")
	}
	delete(log.fail, store.dir)
	log.take()
	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !equalStrings(got, sortedStrings(path, store.dir)) {
		t.Fatalf("the retry fsynced %v, want the blob and the dir", got)
	}

	gone, err := store.Put("sb-gone", recoveryFor("gone"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(gone); err != nil {
		t.Fatal(err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync of a blob deleted since its Put: %v", err)
	}
}

// TestRecoveryFileStoreSyncRef: SyncRef makes one blob durable and leaves
// the others for Sync.
func TestRecoveryFileStoreSyncRef(t *testing.T) {
	log := countFsyncs(t)
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	one, _ := store.Put("sb-1", recoveryFor("1"))
	two, _ := store.Put("sb-2", recoveryFor("2"))
	pathOne, _ := store.pathForRef(one)
	pathTwo, _ := store.pathForRef(two)
	if err := store.SyncRef(one); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !equalStrings(got, sortedStrings(pathOne, store.dir)) {
		t.Fatalf("SyncRef fsynced %v", got)
	}
	if err := store.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !equalStrings(got, sortedStrings(pathTwo, store.dir)) {
		t.Fatalf("Sync after SyncRef fsynced %v, want only the other blob", got)
	}
	if err := store.SyncRef("not-a-ref"); err == nil {
		t.Fatal("SyncRef of an invalid ref should fail")
	}
	log.fail[pathOne] = errors.New("x")
	if err := store.SyncRef(one); err == nil {
		t.Fatal("SyncRef should report the blob's fsync failure")
	}
	delete(log.fail, pathOne)
	log.fail[store.dir] = errors.New("x")
	if err := store.SyncRef(one); err == nil {
		t.Fatal("SyncRef should report the directory's fsync failure")
	}
}

// orderSink records whether Close came after the blobs' fsync.
type orderSink struct {
	bytes.Buffer
	closed, cancelled bool
}

func (s *orderSink) ID() string    { return "order" }
func (s *orderSink) Cancel() error { s.cancelled = true; return nil }
func (s *orderSink) Close() error  { s.closed = true; return nil }

// TestFSMApplyDoesNotFsyncAndPersistSyncsBeforeClose: applying placements
// with a recovery spec writes their blobs without an fsync on the apply loop
// (the create-path regression), and the snapshot that stands in for those
// entries fsyncs them before it is closed; a snapshot whose blobs can't be
// synced is cancelled, so raft keeps the log entries that would write them
// again.
func TestFSMApplyDoesNotFsyncAndPersistSyncsBeforeClose(t *testing.T) {
	log := countFsyncs(t)
	fsm, err := newPlacementFSMWithFileRecovery(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sb-a", "sb-b", "sb-c"} {
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
	}
	if got := log.take(); len(got) != 0 {
		t.Fatalf("apply fsynced %v; the raft apply loop must not wait on the disk", got)
	}
	store := fsm.recoveryStore.(*placementRecoveryFileStore)
	var refs []string
	for _, id := range []string{"sb-a", "sb-b", "sb-c"} {
		p, ok := fsm.get(id)
		if !ok || p.RecoveryRef == "" {
			t.Fatalf("placement %s has no recovery blob: %+v", id, p)
		}
		path, _ := store.pathForRef(p.RecoveryRef)
		refs = append(refs, path)
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &orderSink{}
	log.onSync = func(string) {
		if sink.closed {
			t.Error("a blob was fsynced after the snapshot was closed")
		}
	}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	if !sink.closed {
		t.Fatal("snapshot not closed")
	}
	synced := log.take()
	for _, path := range refs {
		if !containsString(synced, path) {
			t.Fatalf("snapshot persisted without fsyncing blob %s (synced %v)", path, synced)
		}
	}

	// A failed sync cancels the snapshot.
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-d", OwnerNodeID: "node-a", OwnerAPIURL: "http://a",
		Spec: &models.CreateSandboxRequest{Image: "img-d"}})
	fsm.Apply(&raft.Log{Data: c})
	p, _ := fsm.get("sb-d")
	pathD, _ := store.pathForRef(p.RecoveryRef)
	log.onSync = nil
	log.fail[pathD] = errors.New("disk on fire")
	snap, err = fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	bad := &orderSink{}
	if err := snap.Persist(bad); err == nil {
		t.Fatal("Persist should fail when the blobs can't be synced")
	}
	if bad.closed || !bad.cancelled {
		t.Fatalf("failed snapshot closed %v cancelled %v; want cancelled, not closed", bad.closed, bad.cancelled)
	}
}

// TestFSMFetchedRecoveryBlobSyncedAtOnce: a blob fetched from a peer for a
// snapshot row is made durable when it is stored, since no log entry here
// would write it again.
func TestFSMFetchedRecoveryBlobSyncedAtOnce(t *testing.T) {
	log := countFsyncs(t)
	fsm, err := newPlacementFSMWithFileRecovery(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := fsm.recoveryStore.(*placementRecoveryFileStore)
	rec := recoveryFor("fetched")
	ref, payload, err := encodePlacementRecoveryRecord(placementRecoveryStoreRecord{SandboxID: "sb-f", Recovery: rec})
	if err != nil || len(payload) == 0 {
		t.Fatal(err)
	}
	if err := fsm.storeRecoveryBlob(RecoveryBlob{Ref: ref, SandboxID: "sb-f", Spec: rec.Spec, SecretRef: rec.SecretRef, SecretVersion: rec.SecretVersion}); err != nil {
		t.Fatal(err)
	}
	path, _ := store.pathForRef(ref)
	if got := log.take(); !equalStrings(got, sortedStrings(path, store.dir)) {
		t.Fatalf("storing a fetched blob fsynced %v, want the blob and the dir", got)
	}
}

func sortedStrings(s ...string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
