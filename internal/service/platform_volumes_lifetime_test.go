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

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// lifetimeHarness is a single-node service with platform volumes on and a
// recording reclaimer, so a test can drive a destroy and then the sweep.
func lifetimeHarness(t *testing.T) (*Service, *store.Store, *fakeReclaimer) {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.PATToken = "operator-pat"
	svc.cfg.PlatformVolumes = enabledVolumeService(t).cfg.PlatformVolumes
	fr := &fakeReclaimer{}
	svc.SetVolumeReclaimer(fr)
	return svc, st, fr
}

// attachVolume makes (or finds) the named volume with dws and attaches it to
// a started sandbox row id, as a create would.
func attachVolume(t *testing.T, svc *Service, st *store.Store, sandboxID, name string, dws bool) models.Volume {
	t.Helper()
	ctx := context.Background()
	tenant, err := svc.volumeTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row, err := firstUseVolumeRow(svc.cfg.PlatformVolumes, tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	row.ID, row.DeleteWithSandbox = "vol-"+name, dws
	vol, _, err := svc.volumeMeta().GetOrCreate(ctx, row, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, sandboxID); err != nil {
		seedStartedSandbox(t, st, sandboxID)
	}
	if err := svc.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		Tenant: vol.Tenant, VolumeID: vol.ID, SandboxID: sandboxID, IncarnationID: "inc-" + sandboxID, Target: "/" + name, Source: vol.Source,
	}}); err != nil {
		t.Fatal(err)
	}
	return *vol
}

func volumeExists(t *testing.T, svc *Service, v models.Volume) bool {
	t.Helper()
	_, err := svc.volumeMeta().ByID(context.Background(), v.Tenant, v.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func reclaimedSources(fr *fakeReclaimer) []string {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	var out []string
	for _, c := range fr.calls {
		out = append(out, c.source)
	}
	return out
}

// TestResolvePlatformVolumesDeleteWithSandbox: the flag is set on the volume
// a create makes, a later reference must agree, and a conflict rolls back
// every volume the same create made.
func TestResolvePlatformVolumesDeleteWithSandbox(t *testing.T) {
	s := &Service{cfg: enabledS3Cfg(), store: volumesTestStore(t), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	tenant, err := tenantScopeForTest(s, ctx)
	if err != nil {
		t.Fatal(err)
	}

	req := models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{{Name: "scratch", Path: "/s", DeleteWithSandbox: true}}}
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err != nil {
		t.Fatal(err)
	}
	vol, err := s.store.GetVolume(ctx, tenant, "scratch")
	if err != nil || !vol.DeleteWithSandbox {
		t.Fatalf("made volume = %+v, %v; want delete_with_sandbox", vol, err)
	}

	cases := []struct {
		name string
		refs []models.PlatformVolumeMount
		ok   bool
	}{
		{"same value again", []models.PlatformVolumeMount{{Name: "scratch", Path: "/s", DeleteWithSandbox: true}}, true},
		{"kept volume referenced as delete_with_sandbox", []models.PlatformVolumeMount{{Name: "scratch", Path: "/s"}}, false},
		{"one name, two values in one create", []models.PlatformVolumeMount{{Name: "pair", Path: "/a"}, {Name: "pair", Path: "/b", DeleteWithSandbox: true}}, false},
		{"a new volume, then a conflict", []models.PlatformVolumeMount{{Name: "fresh", Path: "/f", DeleteWithSandbox: true}, {Name: "scratch", Path: "/s"}}, false},
	}
	for _, tc := range cases {
		r := models.CreateSandboxRequest{PlatformVolumes: tc.refs}
		_, err := s.resolvePlatformVolumes(ctx, &r, models.RuntimeDocker)
		if tc.ok != (err == nil) {
			t.Fatalf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if !tc.ok && !errors.Is(err, models.ErrPlatformVolumeConflict) {
			t.Fatalf("%s: err = %v, want ErrPlatformVolumeConflict", tc.name, err)
		}
	}
	for _, name := range []string{"pair", "fresh"} {
		if _, err := s.store.GetVolume(ctx, tenant, name); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("volume %q made by a refused create must be rolled back, got %v", name, err)
		}
	}
}

// TestDestroyDeletesDeleteWithSandboxVolume: the last sandbox's destroy
// deletes the delete_with_sandbox volume's record at once and leaves its
// bytes to the sweep; a normal volume on the same sandbox survives.
func TestDestroyDeletesDeleteWithSandboxVolume(t *testing.T) {
	svc, st, fr := lifetimeHarness(t)
	ctx := context.Background()
	dws := attachVolume(t, svc, st, "sb-one", "scratch", true)
	keep := attachVolume(t, svc, st, "sb-one", "data", false)

	if err := svc.DestroySandbox(ctx, "sb-one"); err != nil {
		t.Fatal(err)
	}
	if volumeExists(t, svc, dws) {
		t.Fatal("the delete_with_sandbox volume must go with its last sandbox")
	}
	if !volumeExists(t, svc, keep) {
		t.Fatal("a normal volume outlives its sandbox")
	}
	pending, _ := st.ListPendingVolumeDeletions(ctx)
	if len(pending) != 1 || pending[0].VolumeID != dws.ID || pending[0].Source != dws.Source {
		t.Fatalf("ledger = %+v, want the delete_with_sandbox volume only", pending)
	}

	svc.runVolumeReclaim(ctx)
	if got := reclaimedSources(fr); len(got) != 1 || got[0] != dws.Source {
		t.Fatalf("reclaimed = %v, want %s", got, dws.Source)
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
		t.Fatalf("ledger not drained: %+v", pending)
	}
}

// TestDestroyKeepsSharedDeleteWithSandboxVolume: while another sandbox holds
// the volume it stays, files included; the last one's destroy deletes it.
func TestDestroyKeepsSharedDeleteWithSandboxVolume(t *testing.T) {
	svc, st, fr := lifetimeHarness(t)
	ctx := context.Background()
	vol := attachVolume(t, svc, st, "sb-a", "shared", true)
	attachVolume(t, svc, st, "sb-b", "shared", true)

	if err := svc.DestroySandbox(ctx, "sb-a"); err != nil {
		t.Fatal(err)
	}
	if !volumeExists(t, svc, vol) {
		t.Fatal("sb-b still holds the volume")
	}
	svc.runVolumeReclaim(ctx)
	if got := reclaimedSources(fr); len(got) != 0 {
		t.Fatalf("bytes of a held volume reclaimed: %v", got)
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 1 {
		t.Fatalf("a young ledger row for a held volume is kept for the grace, got %+v", pending)
	}

	if err := svc.DestroySandbox(ctx, "sb-b"); err != nil {
		t.Fatal(err)
	}
	if volumeExists(t, svc, vol) {
		t.Fatal("the last sandbox's destroy must delete the volume")
	}
	svc.runVolumeReclaim(ctx)
	if got := reclaimedSources(fr); len(got) != 1 || got[0] != vol.Source {
		t.Fatalf("reclaimed = %v", got)
	}
}

// TestConcurrentDestroysDeleteSharedVolumeOnce: two sandboxes sharing the
// volume destroyed at once: neither destroy fails, the volume goes, and its
// bytes are reclaimed once.
func TestConcurrentDestroysDeleteSharedVolumeOnce(t *testing.T) {
	svc, st, fr := lifetimeHarness(t)
	ctx := context.Background()
	vol := attachVolume(t, svc, st, "sb-x", "pair", true)
	attachVolume(t, svc, st, "sb-y", "pair", true)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{"sb-x", "sb-y"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = svc.DestroySandbox(ctx, id)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A destroy that read the other's attachment still present leaves the
	// row to the sweep, which finishes it on its first pass.
	svc.runVolumeReclaim(ctx)
	if volumeExists(t, svc, vol) {
		t.Fatal("the volume must be gone after both destroys and a sweep")
	}
	if got := reclaimedSources(fr); len(got) != 1 {
		t.Fatalf("reclaimed %v, want once", got)
	}
	// A retried destroy of a gone sandbox changes nothing.
	if err := svc.DestroySandbox(ctx, "sb-x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retried destroy = %v, want not found", err)
	}
}

// TestSweepFinishesDeleteAfterCrash: the destroy recorded the volume and
// died before deleting its row (or its store write failed); the sweep
// deletes row and bytes, and retries a failed backend delete on its next
// pass.
func TestSweepFinishesDeleteAfterCrash(t *testing.T) {
	svc, st, fr := lifetimeHarness(t)
	ctx := context.Background()
	vol := attachVolume(t, svc, st, "sb-crash", "job", true)
	sb, err := st.Get(ctx, "sb-crash")
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); len(got) != 1 {
		t.Fatalf("recorded %+v", got)
	}
	// The "crash": the row goes (attachments with it), the finish never runs.
	if err := st.Delete(ctx, "sb-crash"); err != nil {
		t.Fatal(err)
	}
	fr.fail = map[string]error{vol.Source: errors.New("s3 unreachable")}
	svc.runVolumeReclaim(ctx)
	if volumeExists(t, svc, vol) {
		t.Fatal("the sweep must delete the volume row once nothing holds it")
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 1 {
		t.Fatalf("a failed backend delete must keep the ledger row, got %+v", pending)
	}
	fr.fail = nil
	svc.runVolumeReclaim(ctx)
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
		t.Fatalf("the retry must drain the ledger, got %+v", pending)
	}
}

// TestDestroyDeletesDeleteWithSandboxVolumeInCluster: in cluster mode the
// placement delete releases the attachments in the FSM and the volume row is
// deleted there.
func TestDestroyDeletesDeleteWithSandboxVolumeInCluster(t *testing.T) {
	svc, st, _ := lifetimeHarness(t)
	svc.cfg.EnableCluster = true
	svc.AttachCluster(&placementAwareVolumeNoop{
		Noop:      cluster.NewNoop("self", "http://self", ""),
		placement: cluster.Placement{SandboxID: "sb-cl", OwnerNodeID: "self", IncarnationID: "inc-sb-cl"},
	})
	vol := attachVolume(t, svc, st, "sb-cl", "clustered", true)
	if err := svc.DestroySandbox(context.Background(), "sb-cl"); err != nil {
		t.Fatal(err)
	}
	if volumeExists(t, svc, vol) {
		t.Fatal("the replicated volume row must be deleted with its last sandbox")
	}
}

// TestDeleteWithSandboxBestEffortPaths: a destroy never fails on the volume
// work, and a volume it cannot read is kept.
func TestDeleteWithSandboxBestEffortPaths(t *testing.T) {
	svc, st, _ := lifetimeHarness(t)
	ctx := context.Background()
	sb := &models.Sandbox{ID: "sb-q"}

	svc.cfg.PlatformVolumes.Enabled = false
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); got != nil {
		t.Fatal("platform volumes off: nothing to record")
	}
	svc.cfg.PlatformVolumes.Enabled = true

	svc.testVolumeMeta = &scriptedVolumeMeta{forSandboxErr: errors.New("list boom")}
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); got != nil {
		t.Fatal("a failed list keeps every volume")
	}
	att := []models.VolumeAttachment{{Tenant: "t", VolumeID: "v"}, {Tenant: "t", VolumeID: "v"}}
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandbox: att, byIDErr: errors.New("lookup boom")}
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); got != nil {
		t.Fatal("a failed lookup keeps the volume")
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandbox: att, byIDErr: store.ErrNotFound}
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); got != nil {
		t.Fatal("a volume already gone is skipped")
	}
	// A pre-migration row with no source still records, from config.
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandbox: att, byID: &models.Volume{ID: "v", Tenant: "t", Name: "legacy", Backend: "s3", DeleteWithSandbox: true}}
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); len(got) != 1 {
		t.Fatalf("recorded %+v", got)
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 1 || pending[0].Source == "" {
		t.Fatalf("ledger = %+v", pending)
	}
	// Ledger write failure (no source, no config to compute one): still
	// returned, so the finish step tries.
	svc.cfg.PlatformVolumes.S3Bucket = ""
	if got := svc.recordSandboxVolumeDeletes(ctx, sb); len(got) != 1 {
		t.Fatalf("recorded %+v", got)
	}
	// The finish step's failure is logged, never returned, and leaves the
	// ledger row for the reclaim sweep.
	var logs strings.Builder
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	before, _ := st.ListPendingVolumeDeletions(ctx)
	svc.testVolumeMeta = &scriptedVolumeMeta{byID: &models.Volume{ID: "v", Tenant: "t", Source: "b/v"}, deleteRowErr: errors.New("raft down")}
	svc.finishSandboxVolumeDeletes(ctx, "sb-q", []models.Volume{{ID: "v", Tenant: "t", Source: "b/v"}})
	if !strings.Contains(logs.String(), "the reclaim sweep retries it") || !strings.Contains(logs.String(), "raft down") {
		t.Fatalf("the failed delete was not logged: %q", logs.String())
	}
	if after, _ := st.ListPendingVolumeDeletions(ctx); len(after) != len(before) || len(after) == 0 {
		t.Fatalf("ledger before %+v, after %+v: the sweep's row must stay", before, after)
	}
}

// TestSweepDeleteWithSandboxBranches pins the sweep's retry rules.
func TestSweepDeleteWithSandboxBranches(t *testing.T) {
	svc, st, _ := lifetimeHarness(t)
	ctx := context.Background()
	vol := models.Volume{ID: "v", Tenant: "t", Source: "b/v", DeleteWithSandbox: true}
	young := models.PendingVolumeDeletion{VolumeID: "v", Tenant: "t", Source: "b/v", CreatedAt: time.Now()}
	old := young
	old.CreatedAt = time.Now().Add(-2 * deleteWithSandboxPendingGrace)
	if err := st.SchedulePendingVolumeDeletion(ctx, vol, vol.Source); err != nil {
		t.Fatal(err)
	}

	svc.testVolumeMeta = &scriptedVolumeMeta{attachmentCountErr: errors.New("count boom")}
	if svc.sweepDeleteWithSandbox(ctx, vol, young) {
		t.Fatal("an unknown count must not delete")
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{attachmentCount: 1}
	if svc.sweepDeleteWithSandbox(ctx, vol, young) {
		t.Fatal("a held volume must not be deleted")
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 1 {
		t.Fatal("a young row for a held volume is kept")
	}
	if svc.sweepDeleteWithSandbox(ctx, vol, old) {
		t.Fatal("a held volume must not be deleted")
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
		t.Fatal("past the grace, a row for a volume another sandbox holds is dropped")
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{deleteRowErr: store.ErrVolumeInUse}
	if svc.sweepDeleteWithSandbox(ctx, vol, young) {
		t.Fatal("an attach that raced the delete keeps the volume")
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{deleteRowErr: errors.New("raft down")}
	if svc.sweepDeleteWithSandbox(ctx, vol, young) {
		t.Fatal("a failed delete is retried next pass")
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{deleteRowErr: store.ErrNotFound}
	if !svc.sweepDeleteWithSandbox(ctx, vol, young) {
		t.Fatal("a row already gone lets the bytes go")
	}
}

// reconcileVolumeService is a service whose runtime reports no containers,
// so reconcile and the destroy event see the sandbox's container gone.
func reconcileVolumeService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	base, st, _ := lifetimeHarness(t)
	base.docker = &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	return base, st
}

// TestReconcileAndDestroyEventDeleteDeleteWithSandboxVolume: the two other
// ways a sandbox's row goes (reconcile finds the container gone; the engine
// reports it destroyed) delete its delete_with_sandbox volume too.
func TestReconcileAndDestroyEventDeleteDeleteWithSandboxVolume(t *testing.T) {
	ctx := context.Background()

	svc, st := reconcileVolumeService(t)
	vol := attachVolume(t, svc, st, "sb-rec", "recjob", true)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "sb-rec"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("setup: reconcile must reap the sandbox, got %v", err)
	}
	if volumeExists(t, svc, vol) {
		t.Fatal("reconcile's reap must delete the delete_with_sandbox volume")
	}

	svc2, st2 := reconcileVolumeService(t)
	vol2 := attachVolume(t, svc2, st2, "sb-evt", "evtjob", true)
	sb, err := st2.Get(ctx, "sb-evt")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.handleDestroyEvent(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if volumeExists(t, svc2, vol2) {
		t.Fatal("a destroy event must delete the delete_with_sandbox volume")
	}
}

// laggingVolumeMeta answers AttachmentCount as a replica that has not yet
// applied a placement delete: the volume still looks attached for the first
// stale reads.
type laggingVolumeMeta struct {
	volumeMetaStore
	mu    sync.Mutex
	stale int
}

func (m *laggingVolumeMeta) AttachmentCount(ctx context.Context, tenant, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stale > 0 {
		m.stale--
		return 1, nil
	}
	return m.volumeMetaStore.AttachmentCount(ctx, tenant, id)
}

// TestDeleteWithSandboxRetriesWhileTheReplicaLags: in a cluster a destroy's
// own node can still count the dying sandbox's attachment for a moment
// after committing the placement delete; the volume must still go within
// seconds, not wait for the reclaim sweep (UC-412/413 live). On a single
// node the holder is real, so nothing retries.
func TestDeleteWithSandboxRetriesWhileTheReplicaLags(t *testing.T) {
	old := deleteWithSandboxRetryDelays
	deleteWithSandboxRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond, 5 * time.Millisecond}
	t.Cleanup(func() { deleteWithSandboxRetryDelays = old })

	for _, tc := range []struct {
		name       string
		cluster    bool
		stale      int
		wantExists bool
	}{
		{"cluster: catches up after two stale reads", true, 2, false},
		{"cluster: a holder still there after every retry is kept", true, 10, true},
		{"single node: no retry", false, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, _ := lifetimeHarness(t)
			vol := attachVolume(t, svc, st, "sb-lag", "lagging", true)
			if err := svc.volumeMeta().DeleteAttachmentsForSandbox(context.Background(), "sb-lag", "inc-sb-lag"); err != nil {
				t.Fatal(err)
			}
			lag := &laggingVolumeMeta{volumeMetaStore: svc.volumeMeta(), stale: tc.stale}
			svc.testVolumeMeta = lag
			svc.cfg.EnableCluster = tc.cluster
			svc.finishSandboxVolumeDeletes(context.Background(), "sb-lag", []models.Volume{vol})
			deadline := time.Now().Add(2 * time.Second)
			for volumeExists(t, svc, vol) != tc.wantExists && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond) // let any remaining retry finish
			if got := volumeExists(t, svc, vol); got != tc.wantExists {
				t.Fatalf("volume exists = %v, want %v", got, tc.wantExists)
			}
		})
	}
}
