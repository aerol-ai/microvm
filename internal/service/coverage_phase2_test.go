package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// --- metrics.go ---

func TestClassifyWakeErrorPaths(t *testing.T) {
	if classifyWakeError(nil) != "" {
		t.Fatal("nil wake error should classify to empty")
	}
	if got := classifyWakeError(ErrSandboxManuallyStopped); got != "manual_stopped" {
		t.Fatalf("manual stop = %q", got)
	}
	if got := classifyWakeError(ErrWakeCircuitOpen); got != "circuit_open" {
		t.Fatalf("circuit open = %q", got)
	}
	if got := classifyWakeError(capacity.ErrCapacityExceeded); got != "capacity" {
		t.Fatalf("capacity = %q", got)
	}
	if got := classifyWakeError(context.DeadlineExceeded); got != "timeout" {
		t.Fatalf("deadline = %q", got)
	}
	if got := classifyWakeError(errors.New("start container timed out")); got != "timeout" {
		t.Fatalf("timeout string = %q", got)
	}
	if got := classifyWakeError(errors.New("boom")); got != "start_failed" {
		t.Fatalf("generic = %q", got)
	}
}

func TestClassifyServiceAndSecretMetricErrorDefaults(t *testing.T) {
	if got := classifyServiceMetricError(errors.New("boom")); got != "error" {
		t.Fatalf("default service error = %q", got)
	}
	if got := classifyServiceMetricError(errors.New("no placement target available")); got != "no_placement_target" {
		t.Fatalf("placement = %q", got)
	}
	if got := classifySecretMetricError(errors.New("ref not found")); got != "ref_not_found" {
		t.Fatalf("ref not found = %q", got)
	}
	if got := classifySecretMetricError(errors.New("unwrap envelope")); got != "unwrap_failed" {
		t.Fatalf("unwrap = %q", got)
	}
	if got := classifySecretMetricError(errors.New("recipient not allowed to open")); got != "recipient_denied" {
		t.Fatalf("recipient denied = %q", got)
	}
}

// --- ingress_delta.go ---

func TestRouteShardFilterLogValue(t *testing.T) {
	if got := routeShardFilterLogValue(cluster.PlacementShardFilter{}); got != "all" {
		t.Fatalf("empty filter = %q, want all", got)
	}
	filter := cluster.PlacementShardFilter{ShardCount: 4, Shards: []int{0, 2}}
	if got := routeShardFilterLogValue(filter); got != "2/4" {
		t.Fatalf("sharded filter = %q, want 2/4", got)
	}
}

func TestApplyInFluxSandboxAndPortRoutes(t *testing.T) {
	fake := newApplyInFluxCaddyFake(
		"sandbox-sb1",
		caddy.IngressSandboxSNIRouteID("sb1"),
		"sandbox-sb1-port-8080",
		caddy.IngressPortSNIRouteID("sb1", 8080),
	)
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	caddyCfg := config.Config{
		Domain:            "example.test",
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		EnableCaddy:       true,
		HTTPClientTimeout: time.Second,
	}
	svc := &Service{
		cfg:    caddyCfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(caddyCfg),
	}
	p := cluster.Placement{SandboxID: "sb1"}

	if err := svc.applyInFluxSandboxRoute(context.Background(), p); err != nil {
		t.Fatalf("applyInFluxSandboxRoute domain mode: %v", err)
	}
	if !fake.hasRoute(caddy.InFluxSandboxRouteID("sb1")) {
		t.Fatal("expected in-flux sandbox route")
	}

	if err := svc.applyInFluxPortRoute(context.Background(), p, 8080); err != nil {
		t.Fatalf("applyInFluxPortRoute domain mode: %v", err)
	}
	if !fake.hasRoute(caddy.InFluxPortRouteID("sb1", 8080)) {
		t.Fatal("expected in-flux port route")
	}

	svc.cfg.Domain = ""
	if err := svc.applyInFluxSandboxRoute(context.Background(), p); err != nil {
		t.Fatalf("applyInFluxSandboxRoute ip mode: %v", err)
	}
	if err := svc.applyInFluxPortRoute(context.Background(), p, 8080); err != nil {
		t.Fatalf("applyInFluxPortRoute ip mode: %v", err)
	}
}

// --- l4wake.go ---

func TestL4ActivityTracking(t *testing.T) {
	svc := &Service{}
	releasePending, ok := svc.tryAcquireL4Pending("sb")
	if !ok || releasePending == nil {
		t.Fatal("expected pending acquire")
	}
	releasePending()
	releaseActive, ok := svc.tryAcquireL4Active("sb")
	if !ok || releaseActive == nil {
		t.Fatal("expected active acquire")
	}
	gen := svc.l4ActivityGenerations["sb"]
	if !svc.l4ActivityStillActive("sb", gen) {
		t.Fatal("activity should be active for current generation")
	}
	if svc.l4ActivityStillActive("sb", gen+1) {
		t.Fatal("wrong generation should not be active")
	}
	releaseActive()
	if svc.l4ActivityStillActive("sb", gen) {
		t.Fatal("activity should be cleared after release")
	}
}

func TestEnsureTLSWakeListenerAndClose(t *testing.T) {
	// Keep the socket path short — macOS rejects long unix socket paths.
	dir := filepath.Join(os.TempDir(), "l4w")
	svc := &Service{
		cfg:    config.Config{InternalL4WakeDir: dir},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	path, err := svc.ensureTLSWakeListener("sb-tls", 8443)
	if err != nil {
		t.Fatalf("ensureTLSWakeListener: %v", err)
	}
	if path == "" {
		t.Fatal("expected socket path")
	}
	path2, err := svc.ensureTLSWakeListener("sb-tls", 8443)
	if err != nil || path2 != path {
		t.Fatalf("second ensure = (%q, %v)", path2, err)
	}
	svc.closeTLSWakeListener("sb-tls", 8443)
	svc.scheduleTLSWakeListenerClose("sb-tls", 8443, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	svc.closeAllTLSWakeListeners()
}

func TestProxyCopyAndCloseWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{}, 1)
	go proxyCopyAndCloseWrite(server, strings.NewReader("hello"), done)
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read = %q, %v", buf, err)
	}
	<-done
}

// --- template_pull.go adapter ---

func TestNewTemplateArtifactPullDockerAdapterNil(t *testing.T) {
	if NewTemplateArtifactPullDockerAdapter(nil) != nil {
		t.Fatal("nil client should return nil adapter")
	}
}

// --- usage.go ---

func TestUsageLifecycleAndFallback(t *testing.T) {
	svc := newUsageService(&captureReporter{})
	now := time.Unix(200, 0).UTC()
	sb := &models.Sandbox{
		ID: "sb-u", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: time.Unix(150, 0).UTC(),
	}
	got := svc.reconcileFallbackWindowStart(sb, now)
	if !got.Equal(time.Unix(150, 0).UTC()) {
		t.Fatalf("fallback start = %v, want created_at", got)
	}
	svc.noteLifecycleStart("sb-u", now)
	svc.emitReservedUsageAt(context.Background(), []*models.Sandbox{sb}, now.Add(time.Minute))
}

func TestGPUReservedCount(t *testing.T) {
	n := gpuReservedCount(&models.GPURequest{Count: 3})
	if n != 3 {
		t.Fatalf("gpu count = %d, want 3", n)
	}
	if gpuReservedCount(nil) != 0 {
		t.Fatal("nil gpu request should be 0")
	}
}

// --- service.go helpers ---

func TestRegisterSnapshotAndKickReconciler(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	pushStore := newFakePushStore()
	pushStore.seed(&models.SandboxSnapshot{
		Name:                  "existing",
		Image:                 "img:v1",
		PushState:             models.SnapshotPushStateActive,
		ImageDistributionMode: models.ImageDistributionAOCR,
	})
	rec := newTestReconciler(t, pushStore, &fakeSnapshotPushDocker{})
	svc.AttachSnapshotPusher(&SnapshotPusher{}, rec)

	now := time.Now().UTC()
	snap := &models.SandboxSnapshot{
		Name:                  "snap-reg",
		Image:                 "img:reg",
		CreatedAt:             now,
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}
	got, err := svc.RegisterSnapshot(ctx, snap)
	if err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if got.PushState != models.SnapshotPushStatePending {
		t.Fatalf("push state = %q, want pending", got.PushState)
	}
	time.Sleep(20 * time.Millisecond) // kickSnapshotPushReconciler goroutine

	if _, err := svc.RegisterSnapshot(ctx, snap); err != nil {
		t.Fatalf("idempotent RegisterSnapshot: %v", err)
	}
	conflict := &models.SandboxSnapshot{Name: "snap-reg", Image: "other:img", CreatedAt: now}
	if _, err := svc.RegisterSnapshot(ctx, conflict); !errors.Is(err, store.ErrSnapshotNameConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, err := svc.RegisterSnapshot(ctx, nil); err == nil {
		t.Fatal("nil snapshot should fail")
	}

	row, err := st.GetSnapshot(ctx, "snap-reg")
	if err != nil || row == nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	_ = row
}

type removeImageRuntime struct {
	*recordingRuntime
	removeErr error
}

func (r *removeImageRuntime) RemoveImage(context.Context, string) error {
	return r.removeErr
}

func TestDeleteSnapshotPaths(t *testing.T) {
	ctx := context.Background()
	rt := &removeImageRuntime{recordingRuntime: &recordingRuntime{}}
	svc, st, _ := newServiceRuntimeHarness(t, rt.recordingRuntime)
	svc.docker = rt

	now := time.Now().UTC()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "del-me", Image: "img:del", CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if err := svc.DeleteSnapshot(ctx, "del-me"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := svc.DeleteSnapshot(ctx, "   "); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("blank id error = %v", err)
	}

	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "del-fail", Image: "img:fail", CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	rt.removeErr = errors.New("remove failed")
	if err := svc.DeleteSnapshot(ctx, "del-fail"); err == nil {
		t.Fatal("expected remove image failure")
	}
}

func TestKickAndMarkTemplatePush(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if svc.markTemplateForPush(ctx, "missing") {
		t.Fatal("mark without pusher should be false")
	}

	now := time.Now().UTC()
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-push", Image: "x", Status: models.TemplateStatusReady,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	svc.AttachTemplateArtifactPusher(&TemplateArtifactPusher{}, &TemplateArtifactPushReconciler{})
	if !svc.markTemplateForPush(ctx, "tpl-push") {
		t.Fatal("mark with pusher should succeed")
	}
	(&Service{}).kickTemplateArtifactPushReconciler("tpl-push")
	svc.kickSnapshotPushReconciler(nil)
	svc.kickSnapshotPushReconciler(&models.SandboxSnapshot{PushState: models.SnapshotPushStateActive})
}

func TestListMountsAndToolboxTarget(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	seedStartedSandbox(t, st, "sb-tool")

	target, err := svc.ToolboxTarget(ctx, "sb-tool")
	if err != nil {
		t.Fatalf("ToolboxTarget: %v", err)
	}
	if target.URL == "" {
		t.Fatal("expected toolbox URL")
	}
	if _, err := svc.ListMounts(ctx, "sb-tool"); err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if _, err := svc.WakeAwarePortTarget(ctx, "missing", 8080); err == nil {
		t.Fatal("WakeAwarePortTarget missing sandbox should fail")
	}
}

type clusterRemovePort struct {
	*cluster.Noop
	removed bool
}

func (c *clusterRemovePort) RemoveExposedPort(context.Context, string, int) error {
	c.removed = true
	return nil
}

func TestRemoveClusterExposedPort(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cl := &clusterRemovePort{Noop: cluster.NewNoop("self", "http://self", "example.com")}
	svc.AttachCluster(cl)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-rm-port", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		ExposedPorts: []models.ExposedPort{
			{SandboxID: "sb-rm-port", Port: 8080, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now},
		},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc.removeClusterExposedPort(ctx, "sb-rm-port", 8080)
	if !cl.removed {
		t.Fatal("cluster RemoveExposedPort should have been called")
	}
}

func TestRunLifecycleSweepIdleStop(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.IdleTimeoutMinutes = 1
	now := time.Now().UTC().Add(-2 * time.Minute)
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-idle", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		ContainerID: "ctr-idle", ContainerIP: "10.0.0.9",
		Lifecycle: models.Lifecycle{StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc.runLifecycleSweep(ctx)
	got, _ := st.Get(ctx, "sb-idle")
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("idle sweep status = %q, want stopped", got.Status)
	}
}

func TestAddLocalIngressExpectedRoutes(t *testing.T) {
	svc := &Service{}
	httpRoutes := map[string]struct{}{}
	tcpRoutes := map[string]struct{}{}
	tlsRoutes := map[string]struct{}{}
	now := time.Now().UTC()
	svc.addLocalIngressExpectedRoutes(httpRoutes, tcpRoutes, tlsRoutes, []*models.Sandbox{
		{
			ID: "sb-local", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
			ExposedPorts: []models.ExposedPort{
				{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-local-8080.example.com"},
				{Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 35432},
				{Port: 8443, Protocol: models.ExposedPortProtocolTLS, PublicURL: "tls://x"},
			},
			CreatedAt: now, UpdatedAt: now,
		},
		nil,
		{ID: "destroyed", Status: models.SandboxStatusDestroyed},
	})
	if len(httpRoutes) == 0 || len(tcpRoutes) == 0 || len(tlsRoutes) == 0 {
		t.Fatalf("expected routes populated: http=%d tcp=%d tls=%d", len(httpRoutes), len(tcpRoutes), len(tlsRoutes))
	}
}

// --- snapshot_push_retry pushOne edge cases ---

type claimFailPushStore struct {
	*fakePushStore
	claimErr error
}

func (f *claimFailPushStore) SetSnapshotPushState(ctx context.Context, name, state, errMsg string) error {
	if state == models.SnapshotPushStatePushing && f.claimErr != nil {
		return f.claimErr
	}
	return f.fakePushStore.SetSnapshotPushState(ctx, name, state, errMsg)
}

func TestPushOneClaimFailure(t *testing.T) {
	fs := &claimFailPushStore{
		fakePushStore: newFakePushStore(),
		claimErr:      errors.New("claim failed"),
	}
	fs.seed(&models.SandboxSnapshot{
		Name: "snap-claim", Image: "img:1",
		PushState:             models.SnapshotPushStatePending,
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	})
	rec := newTestReconciler(t, fs, &fakeSnapshotPushDocker{})
	out := rec.pushOne(context.Background(), fs.get("snap-claim"))
	if out != snapshotPushFailed {
		t.Fatalf("pushOne outcome = %v, want failed", out)
	}
}

// --- events.go handle paths ---

func TestHandleDockerEventDestroyAndStart(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)
	seedSandbox(t, st, "sb-evt", models.SandboxStatusStarted, 1, 512)
	admitter.Reserve("sb-evt", capacity.Request{CPU: 1, MemoryMB: 512})

	if err := svc.handleDockerEvent(ctx, dockerEvent("sb-evt", "start")); err != nil {
		t.Fatalf("start event: %v", err)
	}
	if err := svc.handleDockerEvent(ctx, dockerEvent("sb-evt", "destroy")); err != nil {
		t.Fatalf("destroy event: %v", err)
	}
	if _, err := st.Get(ctx, "sb-evt"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("destroy should remove row: %v", err)
	}
	if err := svc.handleDockerEvent(ctx, dockerEvent("missing", "stop")); err != nil {
		t.Fatalf("missing sandbox stop: %v", err)
	}
}

func dockerEvent(id, action string) docker.DockerEvent {
	return docker.DockerEvent{SandboxID: id, Action: action, Time: time.Now().UTC()}
}

// --- ingress.go ---

func TestCustomDomainDNSAndIngressTarget(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "ingress.example.com"))
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"
	seedStartedSandbox(t, st, "sb-dns")

	if _, err := svc.CustomDomainDNS(ctx, "sb-dns"); err != nil {
		t.Fatalf("CustomDomainDNS empty domains: %v", err)
	}
	if target := svc.IngressDNSTarget(); target.Hostname == "" && len(target.IPs) == 0 {
		t.Fatal("expected ingress target from cluster")
	}

	svc.cfg.EnableCustomDomains = false
	if _, err := svc.CustomDomainDNS(ctx, "sb-dns"); !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("disabled custom domains = %v", err)
	}
}

// --- auto_import_retry.go ---

func TestNewAutoImportReconcilerNilDeps(t *testing.T) {
	if NewAutoImportReconciler(nil, nil, nil, nil, 0) != nil {
		t.Fatal("nil deps should return nil reconciler")
	}
	importer := &AutoImporter{}
	if NewAutoImportReconciler(importer, newFakeStore(), &fakeSpecResolver{specs: map[string]*models.CreateSandboxRequest{}}, nil, 0) == nil {
		t.Fatal("expected reconciler with all deps")
	}
	var nilRec *AutoImportReconciler
	if stats, err := nilRec.RunOnce(context.Background()); err != nil || stats.Scanned != 0 {
		t.Fatalf("nil RunOnce = (%+v, %v)", stats, err)
	}
}

// --- template_rotation.go ---

type stubRotationMarker struct{}

func (stubRotationMarker) MarkSnapshotCorrupt(context.Context, string, string) error { return nil }

func TestNewTemplateRotationReconcilerValidation(t *testing.T) {
	cfg := TemplateRotationConfig{Interval: time.Hour, MaxAge: time.Hour}
	if _, err := NewTemplateRotationReconciler(cfg, nil, stubRotationMarker{}, nil); err == nil {
		t.Fatal("nil store should fail")
	}
	st, _ := store.Open(filepath.Join(t.TempDir(), "rot.db"))
	t.Cleanup(func() { _ = st.Close() })
	adapter := &TemplateRotationStoreAdapter{Store: st}
	if _, err := NewTemplateRotationReconciler(cfg, adapter, nil, nil); err == nil {
		t.Fatal("nil marker should fail")
	}
	if rec, err := NewTemplateRotationReconciler(TemplateRotationConfig{}, &TemplateRotationStoreAdapter{}, stubRotationMarker{}, nil); err != nil || rec != nil {
		t.Fatalf("disabled rotation = (%v, %v)", rec, err)
	}
}

// --- fleet_control.go list failure ---

func TestFleetControlListFailure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	createOwned(t, svc, "acme", "sb-fleet")
	_ = st.Close()
	if err := svc.StopByOwner(ctx, "acme"); err == nil {
		t.Fatal("StopByOwner should propagate list error")
	}
}
