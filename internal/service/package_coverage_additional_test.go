package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeTemplateReadyBeforeStore struct {
	rows []*models.Template
	err  error
}

func (f *fakeTemplateReadyBeforeStore) ListTemplatesReadyBefore(_ context.Context, _ time.Time) ([]*models.Template, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]*models.Template(nil), f.rows...), nil
}

func TestTemplateRotationStoreAdapterCoverage(t *testing.T) {
	ctx := context.Background()
	if _, err := (&TemplateRotationStoreAdapter{}).ListTemplatesReadyBefore(ctx, time.Now()); err == nil {
		t.Fatal("nil store accepted")
	}

	wantErr := errors.New("db down")
	adapter := &TemplateRotationStoreAdapter{Store: &fakeTemplateReadyBeforeStore{err: wantErr}}
	if _, err := adapter.ListTemplatesReadyBefore(ctx, time.Now()); !errors.Is(err, wantErr) {
		t.Fatalf("ListTemplatesReadyBefore() error = %v, want %v", err, wantErr)
	}

	ready := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	adapter = &TemplateRotationStoreAdapter{Store: &fakeTemplateReadyBeforeStore{rows: []*models.Template{
		nil,
		{ID: "tpl-a", ReadyAt: &ready},
		{ID: "tpl-b"},
	}}}
	got, err := adapter.ListTemplatesReadyBefore(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListTemplatesReadyBefore() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(got))
	}
	if got[0].ID != "tpl-a" || !got[0].ReadyAt.Equal(ready) {
		t.Fatalf("first candidate = %+v, want tpl-a at %v", got[0], ready)
	}
	if got[1].ID != "tpl-b" || !got[1].ReadyAt.IsZero() {
		t.Fatalf("second candidate = %+v, want zero ReadyAt", got[1])
	}
}

func TestClusterOwnershipHelperCoverage(t *testing.T) {
	if placementCanBeClaimedBySelf(cluster.Placement{OwnerNodeID: "peer"}, "self") {
		t.Fatal("non-orphaned placement should not be claimable")
	}
	if !placementCanBeClaimedBySelf(cluster.Placement{OwnerState: cluster.PlacementOwnerStateOrphaned}, "self") {
		t.Fatal("orphaned placement without owner should be claimable")
	}
	if !placementCanBeClaimedBySelf(cluster.Placement{OwnerState: cluster.PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "self"}, "self") {
		t.Fatal("self-orphaned placement should be claimable")
	}
	if placementCanBeClaimedBySelf(cluster.Placement{OwnerState: cluster.PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "peer"}, "self") {
		t.Fatal("peer-orphaned placement should not be claimable")
	}

	sb := &models.Sandbox{
		CustomDomains: []models.CustomDomain{{Hostname: "a.example.test"}, {Hostname: "b.example.test"}},
		ExposedPorts: []models.ExposedPort{
			{Port: -1, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 443, Protocol: models.ExposedPortProtocolTLS, HostPort: 30443, PublicURL: "https://a.example.test"},
		},
	}
	if !placementMissingLocalCustomHostnames(cluster.Placement{CustomHostnames: []string{"a.example.test"}}, sb) {
		t.Fatal("missing local hostname should force replay")
	}
	if placementMissingLocalCustomHostnames(cluster.Placement{CustomHostnames: []string{"a.example.test", "b.example.test"}}, sb) {
		t.Fatal("matching hostnames should not force replay")
	}
	if !placementMissingLocalPorts(cluster.Placement{}, sb) {
		t.Fatal("missing local port should force replay")
	}
	if placementMissingLocalPorts(cluster.Placement{ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
		443: {Protocol: models.ExposedPortProtocolTLS, HostPort: 30443, PublicURL: "https://a.example.test"},
	}}, sb) {
		t.Fatal("matching exposed port should not force replay")
	}

	ports := clusterPortsFromSandbox(sb)
	if len(ports) != 1 || ports[443].HostPort != 30443 {
		t.Fatalf("clusterPortsFromSandbox() = %+v, want only port 443", ports)
	}
	if clusterPortsFromSandbox(nil) != nil {
		t.Fatal("clusterPortsFromSandbox(nil) should return nil")
	}

	if !isStoppedFirecrackerSnapshotRow(&models.Sandbox{Runtime: models.RuntimeFirecracker, Status: models.SandboxStatusStopped}) {
		t.Fatal("stopped firecracker sandbox should qualify")
	}
	if isStoppedFirecrackerSnapshotRow(&models.Sandbox{Runtime: models.RuntimeDocker, Status: models.SandboxStatusStopped}) {
		t.Fatal("docker sandbox should not qualify")
	}
}

func TestServiceCoordinatorHelperCoverage(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	if svc.SnapshotPushReconciler() != nil || svc.TemplateArtifactPushReconciler() != nil {
		t.Fatal("push reconcilers should be nil by default")
	}

	svc.AttachSnapshotPusher(nil, &SnapshotPushReconciler{})
	svc.AttachTemplateArtifactPusher(nil, &TemplateArtifactPushReconciler{})
	if svc.SnapshotPushReconciler() != nil || svc.TemplateArtifactPushReconciler() != nil {
		t.Fatal("nil pushers should leave reconcilers unset")
	}

	snapRec := &SnapshotPushReconciler{}
	tplRec := &TemplateArtifactPushReconciler{}
	svc.AttachSnapshotPusher(&SnapshotPusher{}, snapRec)
	svc.AttachTemplateArtifactPusher(&TemplateArtifactPusher{}, tplRec)
	if svc.SnapshotPushReconciler() != snapRec || svc.TemplateArtifactPushReconciler() != tplRec {
		t.Fatal("attached reconcilers were not returned")
	}

	localOnly := &models.SandboxSnapshot{ImageDistributionMode: models.ImageDistributionLocalOnly}
	remote := &models.SandboxSnapshot{ImageDistributionMode: models.ImageDistributionAOCR}
	if got := (&Service{}).initialSnapshotPushState(localOnly); got != models.SnapshotPushStateActive {
		t.Fatalf("initialSnapshotPushState() without pusher = %q, want active", got)
	}
	if got := svc.initialSnapshotPushState(remote); got != models.SnapshotPushStateActive {
		t.Fatalf("initialSnapshotPushState() for remote snapshot = %q, want active", got)
	}
	if got := svc.initialSnapshotPushState(localOnly); got != models.SnapshotPushStatePending {
		t.Fatalf("initialSnapshotPushState() for local-only snapshot = %q, want pending", got)
	}

	now := time.Now().UTC()
	snapshot := &models.SandboxSnapshot{
		Name:                  "snap-by-image-id",
		Image:                 "snap-by-image-id",
		ImageID:               "sha256:abc123",
		CreatedAt:             now,
		ImageDistributionMode: models.ImageDistributionLocalOnly,
		PushState:             models.SnapshotPushStatePending,
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}
	got, err := svc.GetSnapshot(ctx, "sha256:abc123")
	if err != nil {
		t.Fatalf("GetSnapshot() by image id error = %v", err)
	}
	if got.Name != snapshot.Name {
		t.Fatalf("GetSnapshot() = %+v, want %q", got, snapshot.Name)
	}
	if _, err := svc.GetSnapshot(ctx, "   "); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSnapshot() blank lookup error = %v, want store.ErrNotFound", err)
	}
}

func TestServiceBackgroundLoopCoverage(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			ReconcileInterval:       time.Millisecond,
			ImageBuildGCEnabled:     true,
			ImageBuildGCInterval:    time.Millisecond,
			IdleTimeoutMinutes:      1,
			FleetLiveSampleInterval: time.Millisecond,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc.StartLifecycleSweep(ctx)
	svc.StartReconcileLoop(ctx)
	svc.StartPendingImageGC(ctx)
	svc.StartBuiltImageGC(ctx)
	svc.StartLiveUsageSampler(ctx)
	svc.StartClusterIngressReconcile(ctx)
	cancel()

	svc = &Service{
		cfg: config.Config{
			EnableCluster:               true,
			ClusterShardAwareIngress:    false,
			NetstatsPollInterval:        time.Second,
			HTTPWakeDirectBypassEnabled: true,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := svc.ClusterTopologyError(); err != nil {
		t.Fatalf("ClusterTopologyError() without cluster = %v", err)
	}
	if !svc.netstatsPollIsStale(time.Now().UTC()) {
		t.Fatal("netstatsPollIsStale() should report stale when no tick was recorded")
	}
	svc.netstatsLastTick.Store(time.Now().Add(-3 * time.Second).UnixNano())
	if !svc.netstatsPollIsStale(time.Now().UTC()) {
		t.Fatal("old netstats tick should be stale")
	}
	recent := time.Now().UTC()
	svc.recordNetstatsActivity("sb", recent)
	floor := svc.activityFloorFor(&models.Sandbox{ID: "sb", LastActiveAt: recent.Add(-time.Minute)}, false)
	if !floor.Equal(recent) {
		t.Fatalf("activityFloorFor() = %v, want %v", floor, recent)
	}
	svc.forgetNetstatsActivity("sb")
	if got := svc.netstatsRecentActivityAt("sb"); !got.IsZero() {
		t.Fatalf("netstatsRecentActivityAt() after forget = %v, want zero", got)
	}

	leaderSvc := &Service{cfg: config.Config{EnableCluster: true}}
	leaderSvc.AttachCluster(&leaderCluster{Noop: cluster.NewNoop("self", "http://self", ""), leader: "self"})
	if err := leaderSvc.EnsureClusterReady(context.Background()); err != nil {
		t.Fatalf("EnsureClusterReady() error = %v", err)
	}
	if err := (&Service{}).EnsureClusterReady(context.Background()); err == nil {
		t.Fatal("EnsureClusterReady() without cluster should fail")
	}
}

func TestServiceHelperCoverageRoundTwo(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	if got := gpuCountForCapacity(nil); got != 0 {
		t.Fatalf("gpuCountForCapacity(nil) = %d, want 0", got)
	}
	if got := gpuCountForCapacity(&models.GPURequest{Count: 3}); got != 3 {
		t.Fatalf("gpuCountForCapacity(count) = %d, want 3", got)
	}

	if rt, err := svc.runtimeForSandbox(nil); err != nil || rt == nil {
		t.Fatalf("runtimeForSandbox(nil) = (%T, %v), want docker runtime", rt, err)
	}
	if _, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeFirecracker}); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("runtimeForSandbox(firecracker without driver) = %v, want ErrRuntimeNotImplemented", err)
	}
	if _, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeWasm}); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("runtimeForSandbox(wasm without driver) = %v, want ErrRuntimeNotImplemented", err)
	}

	if got := svc.netstatsRecentActivityAt("missing"); !got.IsZero() {
		t.Fatalf("netstatsRecentActivityAt(missing) = %v, want zero", got)
	}
	svc.recordNetstatsActivity("", time.Time{})
	svc.recordNetstatsActivity("sb-activity", time.Now().UTC())
	if got := svc.netstatsRecentActivityAt("sb-activity"); got.IsZero() {
		t.Fatal("recordNetstatsActivity should persist a timestamp")
	}
	svc.forgetNetstatsActivity("")
	svc.forgetNetstatsActivity("sb-activity")
	if got := svc.netstatsRecentActivityAt("sb-activity"); !got.IsZero() {
		t.Fatalf("forgetNetstatsActivity did not clear activity: %v", got)
	}

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           "sb-floor",
		LastActiveAt: now.Add(-time.Hour),
	}
	if got := svc.activityFloorFor(sb, true); !got.Equal(sb.LastActiveAt) {
		t.Fatalf("activityFloorFor fallback = %v, want LastActiveAt", got)
	}
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.recordNetstatsActivity(sb.ID, now)
	if got := svc.activityFloorFor(sb, false); !got.Equal(now) {
		t.Fatalf("activityFloorFor netstats = %v, want %v", got, now)
	}

	var nilSvc *Service
	if got := nilSvc.activityFloorFor(nil, false); !got.IsZero() {
		t.Fatalf("activityFloorFor(nil) = %v, want zero", got)
	}

	disabledGC := &Service{cfg: config.Config{ImageBuildGCEnabled: false}}
	disabledGC.StartBuiltImageGC(ctx)
	enabledNoEvents := &Service{cfg: config.Config{ImageBuildGCEnabled: true, ImageBuildGCInterval: time.Millisecond}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	enabledNoEvents.StartBuiltImageGC(ctx)

	zeroReconcile := &Service{cfg: config.Config{ReconcileInterval: 0}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	zeroReconcile.StartReconcileLoop(ctx)

	loopCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enabledReconcile, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	enabledReconcile.cfg.ReconcileInterval = time.Millisecond
	enabledReconcile.StartReconcileLoop(loopCtx)
	cancel()

	if err := (&Service{}).EnsureClusterReady(ctx); err == nil {
		t.Fatal("EnsureClusterReady() without cluster should fail")
	}
	leaderSvc := &Service{cfg: config.Config{EnableCluster: true}}
	leaderSvc.AttachCluster(&leaderCluster{Noop: cluster.NewNoop("self", "http://self", ""), leader: "self"})
	if err := leaderSvc.EnsureClusterReady(ctx); err != nil {
		t.Fatalf("EnsureClusterReady() with leader = %v", err)
	}
}
