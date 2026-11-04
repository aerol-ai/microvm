package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// A deleted snapshot's registry copy is retired: the obligation is written
// with the row delete (or by a push that lands after it), and the push
// worker removes the manifest by digest. No test here touches the network:
// the registry delete is a recording fake.

const (
	retireDigestOld = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	retireDigestNew = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeManifestDeleter records the manifests a pusher retires.
type fakeManifestDeleter struct {
	mu      sync.Mutex
	deleted []string
	cfgs    []wasmmod.ORASPushConfig
	err     error
}

func (f *fakeManifestDeleter) delete(_ context.Context, cfg wasmmod.ORASPushConfig, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfgs = append(f.cfgs, cfg)
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, ref)
	return nil
}

func (f *fakeManifestDeleter) refs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

func retirePusher(t *testing.T, dk SnapshotPushDocker, del *fakeManifestDeleter) *SnapshotPusher {
	t.Helper()
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{
		Enabled: true, Host: "aocr.test", ClusterID: "cluster-1", PATPath: writePATFile(t, "token"),
	}, dk, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if del != nil {
		pusher.deleteRef = del.delete
	}
	return pusher
}

func repoOf(ref string) string {
	return ref[:strings.LastIndex(ref, ":")]
}

// The copy is deleted by digest — the tag may already hold a newer snapshot
// of the same name — with the credentials it was pushed with, and only
// inside this cluster's snapshot namespace on the configured host.
func TestRetireManifest(t *testing.T) {
	del := &fakeManifestDeleter{}
	p := retirePusher(t, &fakeSnapshotPushDocker{}, del)
	ref := p.DestRefFor("acme", "app")

	if err := p.RetireManifest(context.Background(), ref, retireDigestOld); err != nil {
		t.Fatalf("RetireManifest: %v", err)
	}
	if got := del.refs(); len(got) != 1 || got[0] != repoOf(ref)+"@"+retireDigestOld {
		t.Fatalf("deleted %v, want %s pinned by digest", got, repoOf(ref))
	}
	if cfg := del.cfgs[0]; cfg.Host != "aocr.test" || cfg.ClusterID != "cluster-1" || cfg.PATPath != p.cfg.PATPath {
		t.Fatalf("delete cfg = %+v, want the pusher's own", cfg)
	}

	refused := []struct{ name, ref, digest string }{
		{"another host", strings.Replace(ref, "aocr.test", "evil.test", 1), retireDigestOld},
		{"another cluster", strings.Replace(ref, "cluster-1", "cluster-2", 1), retireDigestOld},
		{"not a snapshot path", "aocr.test/cluster/cluster-1/templates/app:latest", retireDigestOld},
		{"the import namespace", "aocr.test/cluster/cluster-1/_imported/python:3.12", retireDigestOld},
		{"unparsable ref", "Not A Ref", retireDigestOld},
		{"not a digest", ref, "latest"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			before := len(del.refs())
			if err := p.RetireManifest(context.Background(), tc.ref, tc.digest); !errors.Is(err, errRegistryCopyNotOurs) {
				t.Fatalf("RetireManifest = %v, want errRegistryCopyNotOurs", err)
			}
			if len(del.refs()) != before {
				t.Fatal("a refused copy reached the registry")
			}
		})
	}

	del.err = errors.New("registry 503")
	if err := p.RetireManifest(context.Background(), ref, retireDigestOld); err == nil || errors.Is(err, errRegistryCopyNotOurs) {
		t.Fatalf("registry failure = %v, want a retryable error", err)
	}
	var none *SnapshotPusher
	if err := none.RetireManifest(context.Background(), ref, retireDigestOld); err == nil {
		t.Fatal("a nil pusher retired something")
	}
	// The production deleter reads the PAT first, so a missing PAT file
	// fails before any network call.
	offline := retirePusher(t, &fakeSnapshotPushDocker{}, nil)
	offline.cfg.PATPath = t.TempDir() + "/missing"
	if err := offline.RetireManifest(context.Background(), ref, retireDigestOld); err == nil || !strings.Contains(err.Error(), "PAT") {
		t.Fatalf("default deleter without a PAT = %v", err)
	}
}

// The worker's decision for each obligation, against the fake ledger.
func TestSnapshotRetirementPass(t *testing.T) {
	ctx := context.Background()
	const ref = "aocr.test/cluster/cluster-1/snapshots/app:latest"
	ob := store.SnapshotRegistryRetirement{RegistryRef: ref, Digest: retireDigestOld, Name: "app"}
	cases := []struct {
		name        string
		set         func(*fakePushStore, *fakeManifestDeleter)
		ob          store.SnapshotRegistryRetirement
		wantDeleted bool
		wantKept    bool
		wantStats   SnapshotPushReconcileStats
	}{
		{name: "no row names it: removed", ob: ob, wantDeleted: true, wantStats: SnapshotPushReconcileStats{Retired: 1}},
		{name: "a live row names the manifest: void", ob: ob, set: func(s *fakePushStore, _ *fakeManifestDeleter) {
			s.seed(&models.SandboxSnapshot{Name: "other", ImageRegistryRef: ref, ImageDigest: retireDigestOld, PushState: models.SnapshotPushStateActive})
		}},
		{name: "same name still pushing: waits", ob: ob, wantKept: true, set: func(s *fakePushStore, _ *fakeManifestDeleter) {
			s.seed(pendingLocal("app"))
		}},
		{name: "registry fails: kept for the next sweep", ob: ob, wantKept: true, wantStats: SnapshotPushReconcileStats{RetireFailed: 1},
			set: func(_ *fakePushStore, d *fakeManifestDeleter) { d.err = errors.New("registry 503") }},
		{name: "not ours: dropped untouched", ob: store.SnapshotRegistryRetirement{RegistryRef: "ghcr.io/org/app:latest", Digest: retireDigestOld}},
		{name: "in-use check fails: kept", ob: ob, wantKept: true,
			set: func(s *fakePushStore, _ *fakeManifestDeleter) { s.inUseErr = errors.New("db busy") }},
		{name: "defer and drop failures are logged", ob: ob, wantKept: true, set: func(s *fakePushStore, _ *fakeManifestDeleter) {
			s.seed(pendingLocal("app"))
			s.deferErr = errors.New("db busy")
		}},
		{name: "failure record fails too", ob: ob, wantKept: true, wantStats: SnapshotPushReconcileStats{RetireFailed: 1},
			set: func(s *fakePushStore, d *fakeManifestDeleter) {
				d.err = errors.New("registry 503")
				s.deferErr = errors.New("db busy")
			}},
		{name: "drop fails after the delete", ob: ob, wantDeleted: true, wantKept: true, wantStats: SnapshotPushReconcileStats{Retired: 1},
			set: func(s *fakePushStore, _ *fakeManifestDeleter) { s.dropRetireErr = errors.New("db busy") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakePushStore()
			del := &fakeManifestDeleter{}
			if tc.set != nil {
				tc.set(fs, del)
			}
			if err := fs.ScheduleSnapshotRegistryRetirement(ctx, tc.ob); err != nil {
				t.Fatal(err)
			}
			rec := newTestReconcilerN(t, fs, &fakeSnapshotPushDocker{}, 1)
			rec.pusher.deleteRef = del.delete
			var stats SnapshotPushReconcileStats
			rec.retireRegistryCopies(ctx, &stats)
			if (len(del.refs()) == 1) != tc.wantDeleted {
				t.Fatalf("deleted %v, want deleted=%v", del.refs(), tc.wantDeleted)
			}
			if tc.wantDeleted && del.refs()[0] != repoOf(ref)+"@"+retireDigestOld {
				t.Fatalf("deleted %v, want the old digest", del.refs())
			}
			if _, kept := fs.retirement(tc.ob.RegistryRef, tc.ob.Digest); kept != tc.wantKept {
				t.Fatalf("obligation kept = %v, want %v", kept, tc.wantKept)
			}
			if stats.Retired != tc.wantStats.Retired || stats.RetireFailed != tc.wantStats.RetireFailed {
				t.Fatalf("stats = %+v, want %+v", stats, tc.wantStats)
			}
		})
	}

	t.Run("a failure is counted on the obligation", func(t *testing.T) {
		fs := newFakePushStore()
		_ = fs.ScheduleSnapshotRegistryRetirement(ctx, ob)
		rec := newTestReconcilerN(t, fs, &fakeSnapshotPushDocker{}, 1)
		rec.pusher.deleteRef = (&fakeManifestDeleter{err: errors.New("registry 503")}).delete
		var stats SnapshotPushReconcileStats
		rec.retireRegistryCopies(ctx, &stats)
		if got, _ := fs.retirement(ref, retireDigestOld); got.Attempts != 1 || !strings.Contains(got.LastError, "registry 503") {
			t.Fatalf("obligation = %+v", got)
		}
	})
	t.Run("list failure and a cancelled sweep do nothing", func(t *testing.T) {
		fs := newFakePushStore()
		_ = fs.ScheduleSnapshotRegistryRetirement(ctx, ob)
		del := &fakeManifestDeleter{}
		rec := newTestReconcilerN(t, fs, &fakeSnapshotPushDocker{}, 1)
		rec.pusher.deleteRef = del.delete
		fs.listRetireErr = errors.New("db busy")
		var stats SnapshotPushReconcileStats
		rec.retireRegistryCopies(ctx, &stats)
		fs.listRetireErr = nil
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		rec.retireRegistryCopies(cancelled, &stats)
		if len(del.refs()) != 0 {
			t.Fatalf("deleted %v", del.refs())
		}
	})
}

// retirementHarness: a real store, a service whose push worker has a
// recording deleter, and one committed-and-pushed snapshot.
type retirementHarness struct {
	svc  *Service
	st   *store.Store
	path string
	rec  *SnapshotPushReconciler
	del  *fakeManifestDeleter
	dk   *fakeSnapshotPushDocker
}

func newRetirementHarness(t *testing.T, withPusher bool) *retirementHarness {
	t.Helper()
	st, path := openPushStore(t)
	if err := st.Create(context.Background(), seedSnapshotSandbox("sb-retire", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	h := &retirementHarness{
		st:   st,
		path: path,
		del:  &fakeManifestDeleter{},
		dk:   &fakeSnapshotPushDocker{digest: retireDigestOld},
	}
	h.svc = &Service{store: st, docker: &fakeSnapshotRuntime{imageID: "sha256:img"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if withPusher {
		pusher := retirePusher(t, h.dk, h.del)
		h.rec = NewSnapshotPushReconciler(pusher, st, h.svc.logger, 1)
		h.svc.AttachSnapshotPusher(pusher, h.rec)
	}
	return h
}

func (h *retirementHarness) createAndPush(t *testing.T, name string) *models.SandboxSnapshot {
	t.Helper()
	snap, err := h.svc.CreateSnapshot(context.Background(), "sb-retire", models.CreateSandboxSnapshotRequest{Name: name})
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if h.rec != nil {
		if _, err := h.rec.RunOnce(context.Background()); err != nil {
			t.Fatalf("push sweep: %v", err)
		}
	}
	got, err := h.st.GetSnapshot(context.Background(), snap.OwnerRef, snap.Name)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (h *retirementHarness) ledger(t *testing.T) []store.SnapshotRegistryRetirement {
	t.Helper()
	due, err := h.st.ListDueSnapshotRegistryRetirements(context.Background(), time.Now().UTC().Add(time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	return due
}

// Deleting a pushed snapshot records its registry copy for retirement in the
// same transaction, wakes the worker, and the worker removes it by digest.
func TestDeleteSnapshotRetiresItsRegistryCopy(t *testing.T) {
	h := newRetirementHarness(t, true)
	snap := h.createAndPush(t, "app")
	if snap.ImageRegistryRef == "" || snap.ImageDigest != retireDigestOld {
		t.Fatalf("pushed row = %+v", snap)
	}
	if err := h.svc.DeleteSnapshot(context.Background(), snap.Name); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	ledger := h.ledger(t)
	if len(ledger) != 1 || ledger[0].RegistryRef != snap.ImageRegistryRef || ledger[0].Digest != retireDigestOld || ledger[0].Name != "app" {
		t.Fatalf("ledger = %+v", ledger)
	}
	if len(h.rec.gate.wake) != 1 {
		t.Fatal("the delete did not wake the worker")
	}
	stats, err := h.rec.RunOnce(context.Background())
	if err != nil || stats.Retired != 1 {
		t.Fatalf("retire sweep = %+v, %v", stats, err)
	}
	if got := h.del.refs(); len(got) != 1 || got[0] != repoOf(snap.ImageRegistryRef)+"@"+retireDigestOld {
		t.Fatalf("deleted %v", got)
	}
	if ledger := h.ledger(t); len(ledger) != 0 {
		t.Fatalf("ledger after retirement = %+v", ledger)
	}
}

// Re-creating a snapshot under a deleted one's name pushes a new digest to
// the same tag. Retirement waits until that push lands and then removes the
// OLD digest only: the new snapshot's copy is untouched.
func TestRetirementSparesARecreatedSnapshotOfTheSameName(t *testing.T) {
	h := newRetirementHarness(t, true)
	old := h.createAndPush(t, "app")
	if err := h.svc.DeleteSnapshot(context.Background(), old.Name); err != nil {
		t.Fatal(err)
	}
	// Re-created before the worker ran; its push is still to come.
	if _, err := h.svc.CreateSnapshot(context.Background(), "sb-retire", models.CreateSandboxSnapshotRequest{Name: "app"}); err != nil {
		t.Fatal(err)
	}
	var stats SnapshotPushReconcileStats
	h.rec.retireRegistryCopies(context.Background(), &stats)
	if len(h.del.refs()) != 0 || len(h.ledger(t)) != 1 {
		t.Fatalf("retired while the new snapshot's push was pending: %v", h.del.refs())
	}

	h.dk.digest = retireDigestNew
	if _, err := h.rec.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.del.refs(); len(got) != 1 || got[0] != repoOf(old.ImageRegistryRef)+"@"+retireDigestOld {
		t.Fatalf("deleted %v, want only the old digest", got)
	}
	cur, err := h.st.GetSnapshot(context.Background(), "", "app")
	if err != nil || cur.ImageDigest != retireDigestNew || cur.ImageRegistryRef != old.ImageRegistryRef {
		t.Fatalf("re-created row = %+v, %v", cur, err)
	}
}

// A push that finishes after its row was deleted records the copy it just
// made for retirement; the next sweep removes it.
func TestLatePushAfterDeleteIsRetired(t *testing.T) {
	h := newRetirementHarness(t, true)
	blocking := newBlockingPushDocker()
	h.rec.pusher.docker = blocking
	if _, err := h.svc.CreateSnapshot(context.Background(), "sb-retire", models.CreateSandboxSnapshotRequest{Name: "late"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan SnapshotPushReconcileStats)
	go func() {
		stats, _ := h.rec.RunOnce(context.Background())
		done <- stats
	}()
	dest := <-blocking.started
	// Deleted mid-push: no registry copy yet, so no obligation from the delete.
	if err := h.svc.DeleteSnapshot(context.Background(), "late"); err != nil {
		t.Fatal(err)
	}
	if ledger := h.ledger(t); len(ledger) != 0 {
		t.Fatalf("the delete recorded %+v before any copy existed", ledger)
	}
	close(blocking.release)
	first := <-done
	if first.Skipped != 1 {
		t.Fatalf("late push stats = %+v, want a fenced skip", first)
	}
	// The worker's next round (the delete's kick) removed it; or this one does.
	if len(h.del.refs()) == 0 {
		if stats, err := h.rec.RunOnce(context.Background()); err != nil || stats.Retired != 1 {
			t.Fatalf("retire sweep = %+v, %v", stats, err)
		}
	}
	want := repoOf(dest) + "@sha256:" + strings.Repeat("a", 64)
	if got := h.del.refs(); len(got) != 1 || got[0] != want {
		t.Fatalf("deleted %v, want %s", got, want)
	}
	if ledger := h.ledger(t); len(ledger) != 0 {
		t.Fatalf("ledger = %+v", ledger)
	}
}

// The late-push obligation is best-effort logged when the ledger write fails.
func TestLatePushRetirementWriteFailureIsLogged(t *testing.T) {
	fs := newFakePushStore()
	fs.seed(pendingLocal("gone"))
	fs.scheduleErr = errors.New("db busy")
	dk := newBlockingPushDocker()
	close(dk.release)
	dk.onPush = func(string) {
		fs.mu.Lock()
		delete(fs.rows, "gone")
		fs.mu.Unlock()
	}
	rec := newTestReconcilerN(t, fs, dk, 1)
	if got := rec.pushOne(context.Background(), pendingLocal("gone")); got != snapshotPushSkipped {
		t.Fatalf("pushOne = %v, want skipped", got)
	}
}

// No registry, or a copy this node did not push, means no obligation.
func TestDeleteSnapshotRecordsNoRetirementForCopiesItDidNotPush(t *testing.T) {
	t.Run("no registry configured", func(t *testing.T) {
		h := newRetirementHarness(t, false)
		snap := h.createAndPush(t, "app")
		// A registry copy written by some other path must not be retired
		// by a node with no pusher.
		if err := h.st.DeleteSnapshot(context.Background(), snap.OwnerRef, snap.Name); err != nil {
			t.Fatal(err)
		}
		if err := h.st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
			Name: "app", Image: snap.Image, SourceSandboxID: "sb-retire", CreatedAt: time.Now().UTC(),
			ImageDistributionMode: models.ImageDistributionAOCR,
			ImageRegistryRef:      "aocr.test/cluster/cluster-1/snapshots/app:latest", ImageDigest: retireDigestOld,
		}); err != nil {
			t.Fatal(err)
		}
		if err := h.svc.DeleteSnapshot(context.Background(), "app"); err != nil {
			t.Fatal(err)
		}
		if ledger := h.ledger(t); len(ledger) != 0 {
			t.Fatalf("ledger = %+v", ledger)
		}
	})
	t.Run("registered with a registry image", func(t *testing.T) {
		h := newRetirementHarness(t, true)
		ref := h.rec.pusher.DestRefFor("", "reg")
		if err := h.st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
			Name: "reg", Image: ref, CreatedAt: time.Now().UTC(), PushState: models.SnapshotPushStateActive,
			ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: ref, ImageDigest: retireDigestOld,
		}); err != nil {
			t.Fatal(err)
		}
		if err := h.svc.DeleteSnapshot(context.Background(), "reg"); err != nil {
			t.Fatal(err)
		}
		if ledger := h.ledger(t); len(ledger) != 0 {
			t.Fatalf("a copy someone else owns was scheduled: %+v", ledger)
		}
	})
	t.Run("pushed without a digest", func(t *testing.T) {
		h := newRetirementHarness(t, true)
		h.dk.digest = ""
		snap := h.createAndPush(t, "nodigest")
		if snap.ImageRegistryRef == "" || snap.ImageDigest != "" {
			t.Fatalf("row = %+v", snap)
		}
		if err := h.svc.DeleteSnapshot(context.Background(), snap.Name); err != nil {
			t.Fatal(err)
		}
		if ledger := h.ledger(t); len(ledger) != 0 {
			t.Fatalf("a tag-only copy was scheduled: %+v", ledger)
		}
	})
}

// A row delete that fails leaves the row (a retry can find it) and records
// no obligation: the two only ever go together.
func TestDeleteSnapshotStoreFailureKeepsRowAndRecordsNothing(t *testing.T) {
	h := newRetirementHarness(t, true)
	snap := h.createAndPush(t, "app")
	cb96SQL(t, h.path, `CREATE TRIGGER keep_snap BEFORE DELETE ON sandbox_snapshots BEGIN SELECT RAISE(ABORT, 'locked'); END`)
	if err := h.svc.DeleteSnapshot(context.Background(), snap.Name); err == nil {
		t.Fatal("DeleteSnapshot succeeded")
	}
	if _, err := h.st.GetSnapshot(context.Background(), "", snap.Name); err != nil {
		t.Fatalf("row gone: %v", err)
	}
	if ledger := h.ledger(t); len(ledger) != 0 {
		t.Fatalf("ledger = %+v", ledger)
	}
}
