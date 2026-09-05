package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFleetStopByOwnerSuspendErrHookWave23(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.testForceFleetSuspendErr = errors.New("suspend boom")
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fs23", Image: "a", Status: models.SandboxStatusStarted, OwnerRef: "own",
		ContainerID: "c", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if err := svc.StopByOwner(ctx, "own"); err == nil {
		t.Fatal("expected suspend error")
	}
}

func TestNetstatsRefetchWarnWave23(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ns", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	sink := netstatsServiceSink{svc: svc}
	_ = st.UpdateSandboxNetCounters(context.Background(), "sb-ns", 10, 20)
	_ = st.Close()
	sink.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "sb-ns", BytesIn: 1, BytesOut: 2, SampledAt: now,
	}})
	sink.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "gone", BytesIn: 1, BytesOut: 2, SampledAt: now,
	}})
	sink.handleNetworkSamples(context.Background(), nil)
}

func TestWasmPathUnderDirWave23(t *testing.T) {
	if wasmPathUnderDir("", "/x") || wasmPathUnderDir("/x", "") {
		t.Fatal("empty should be false")
	}
	dir := t.TempDir()
	if !wasmPathUnderDir(dir, filepath.Join(dir, "a.wasm")) {
		t.Fatal("child should be under")
	}
	if wasmPathUnderDir(dir, filepath.Join(dir, "..", "outside")) {
		t.Fatal("escape should be false")
	}
	_ = wasmPathUnderDir(dir, dir)
}

func TestStartWasmDurablePushSweepWave23(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.StartWasmDurablePushSweep(context.Background())
	svc.cfg.WasmDurablePushInterval = 0
	svc.wasmCheckpointPusher = &wasmCheckpointPusherStub{}
	svc.StartWasmDurablePushSweep(context.Background())
	svc.cfg.WasmDurablePushInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	svc.StartWasmDurablePushSweep(ctx)
	cancel()
}

func TestGcUnreferencedJSBundlesListFailWave23(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if n, err := svc.GCUnreferencedJSBundles(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil bundles = %d %v", n, err)
	}
	// With store closed and bundles still nil → early return; force list path via non-nil requires real store.
	_ = st.Close()
	_, _ = svc.GCUnreferencedJSBundles(context.Background())
}

func TestRunLifecycleSweepListFailWave23(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	_ = st.Close()
	svc.runLifecycleSweep(context.Background())
}

func TestReconcileMissingSelfOwnedWave23(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = false
	svc.reconcileMissingSelfOwnedPlacements(ctx, nil)

	svc.cfg.EnableCluster = true
	svc.cluster = nil
	svc.reconcileMissingSelfOwnedPlacements(ctx, nil)

	cl := &missingPlacementCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: []cluster.Placement{
			{SandboxID: "missing-local", OwnerNodeID: "self", State: cluster.PlacementStatePlaced},
			{SandboxID: "reserved", OwnerNodeID: "self", State: cluster.PlacementStateReserved},
			{SandboxID: "other", OwnerNodeID: "peer", State: cluster.PlacementStatePlaced},
			{SandboxID: "", OwnerNodeID: "self", State: cluster.PlacementStatePlaced},
		},
	}
	svc.cluster = cl
	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{"kept": {}})
}

type missingPlacementCluster struct {
	*cluster.Noop
	placements []cluster.Placement
}

func (c *missingPlacementCluster) Placements() []cluster.Placement { return c.placements }
func (c *missingPlacementCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	byID := make(map[string]cluster.Placement, len(c.placements))
	for _, p := range c.placements {
		byID[p.SandboxID] = p
	}
	for _, id := range ids {
		if p, ok := byID[id]; ok {
			out[id] = p
		}
	}
	return out
}
func (c *missingPlacementCluster) SpecOf(string) *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{Failover: &models.Failover{Policy: models.FailoverPolicyNone}}
}

func TestServerlessWakeGetUnderLockFailWave23(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-w23", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.Close()
	_, _ = svc.EnsureSandboxAwakeForHTTP(ctx, "sb-w23")
}

func TestWriteTemplateManifestOKWave23(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	if err := writeTemplateManifest(path, templateManifest{SourceImage: "img", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

func TestPendingImageGCDeleteFailWave23(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.ImageBuildGCTTL = time.Hour
	now := time.Now().UTC()
	_ = st.SchedulePendingImageGC(ctx, "alpine:gc23", now.Add(-2*time.Hour))
	svc.docker = &recordingRuntime{}
	svc.testAfterPendingImageGCList = func() { _ = st.Close() }
	svc.runPendingImageGC(ctx)
}

func TestClusterIngressIdleSkipWave23(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"apps":{}}`)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	_ = svc.ReconcileClusterIngress(ctx)
	_ = svc.ReconcileClusterIngress(ctx)
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableCluster = true
	svc2.cfg.EnableCaddy = true
	svc2.caddy = caddy.New(config.Config{EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second})
	svc2.AttachCluster(cluster.NewNoop("", "http://self", ""))
	_ = svc2.ReconcileClusterIngress(ctx)
}

func TestIdempotencyStateDefaultWave23(t *testing.T) {
	if got := idempotencyState(&models.IdempotentRequestRecord{State: "weird"}); got == "" {
		t.Fatal("expected non-empty")
	}
}

func TestUsageAppendReservedNilWave23(t *testing.T) {
	now := time.Now().UTC()
	_ = appendReservedSamples(nil, nil, now, now.Add(time.Second))
	sb := &models.Sandbox{ID: "x", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 256, DiskGB: 1, OwnerRef: "o", CreatedAt: now}
	_ = appendReservedSamples(nil, sb, now, now.Add(time.Second))
}
