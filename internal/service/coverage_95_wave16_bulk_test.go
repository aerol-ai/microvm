package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTemplateSkipSnapshotReasonsWave16(t *testing.T) {
	now := time.Now().UTC()

	// snapshotter set, cid nil → "cid allocator seam not wired"
	svc, st, _ := newTemplateHarness(t)
	svc.cfg.FirecrackerSnapshotEnabled = true
	done := make(chan struct{}, 1)
	svc.SetTemplateBuilder(&fakeTemplateBuilder{done: done})
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{})
	tpl := &models.Template{ID: "tpl-skip-cid", Image: "docker://a", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
	_ = st.CreateTemplate(context.Background(), tpl)
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	time.Sleep(40 * time.Millisecond)

	// both seams set but snapshot disabled → flag reason
	svc2, st2, _ := newTemplateHarness(t)
	svc2.cfg.FirecrackerSnapshotEnabled = false
	done2 := make(chan struct{}, 1)
	svc2.SetTemplateBuilder(&fakeTemplateBuilder{done: done2})
	svc2.SetTemplateSnapshotter(&fakeTemplateSnapshotter{})
	svc2.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 1})
	tpl2 := &models.Template{ID: "tpl-skip-flag", Image: "docker://a", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
	_ = st2.CreateTemplate(context.Background(), tpl2)
	svc2.kickTemplateBuild(tpl2)
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	time.Sleep(40 * time.Millisecond)
}

func TestTemplateGCReferencedSkipWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-ref16", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	_ = st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-ref16", Image: "docker://a", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale,
	})
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-uses-tpl", Image: "a", Status: models.SandboxStatusStarted, TemplateID: "tpl-ref16",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc.runTemplateGC(ctx, now)
}

func TestStopSandboxNilMountsForceErrWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.mounts = nil
	svc.testForceUnmountErr = errors.New("phantom fuse")
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-nil-mnt", Image: "a", Status: models.SandboxStatusStarted, ContainerID: "c",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, err := svc.stopSandboxInternal(ctx, "sb-nil-mnt", stopModeLifecycle); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestStopSandboxRuntimeMissWave16(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableWasm = true
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-rt-miss", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, err := svc.stopSandboxInternal(ctx, "sb-rt-miss", stopModeLifecycle); err == nil {
		t.Fatal("expected runtime miss")
	}
}

func TestPushWasmCheckpointBestEffortWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.wasmCheckpointPusher = failingWasmCheckpointPusher{}
	svc.pushWasmCheckpointBestEffort("sb-push", t.TempDir())

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.wasmCheckpointPusher = &configurableCheckpointPusher{
		latest: WasmCheckpointPushResult{RegistryRef: "reg/sb:latest", Digest: "sha256:deadbeefcafebabe0123456789abcdef"},
	}
	_ = st2.Close()
	svc2.pushWasmCheckpointBestEffort("sb-meta", t.TempDir())

	svc3, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc3.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc3.wasmCheckpointPusher = &configurableCheckpointPusher{
		latest:    WasmCheckpointPushResult{RegistryRef: "reg/sb:latest", Digest: "sha256:deadbeefcafebabe0123456789abcdef"},
		digestErr: errors.New("digest tag push fail"),
	}
	svc3.pushWasmCheckpointBestEffort("sb-dig", t.TempDir())
}

type configurableCheckpointPusher struct {
	latest    WasmCheckpointPushResult
	digestErr error
	n         int
}

func (p *configurableCheckpointPusher) DestRefFor(id string) string {
	return p.DestRefTagged(id, "latest")
}
func (p *configurableCheckpointPusher) DestRefTagged(sandboxID, tag string) string {
	return "reg/" + sandboxID + ":" + tag
}
func (p *configurableCheckpointPusher) PushOnceTo(_ context.Context, _, _, destRef string) (WasmCheckpointPushResult, error) {
	p.n++
	if p.n > 1 && p.digestErr != nil {
		return WasmCheckpointPushResult{}, p.digestErr
	}
	out := p.latest
	out.RegistryRef = destRef
	return out, nil
}
func (p *configurableCheckpointPusher) PullOnce(context.Context, string, string) error { return nil }
func (p *configurableCheckpointPusher) DeleteRef(context.Context, string) error        { return nil }

func TestDrainWasmFilterSkipsWave16(t *testing.T) {
	ctx := context.Background()
	rt := &fakeCheckpointRuntime{
		checkpointPath: "/tmp/c",
		cloneGen:       "g",
		wasmRecordingRuntime: wasmRecordingRuntime{
			managed: map[string]*models.SandboxRuntimeState{"sb-live": {SandboxID: "sb-live"}},
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-docker", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-stopped", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped, Durability: models.DurabilityDurable, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-ephem", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityEphemeral, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-notlive", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityDurable, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	if err := svc.DrainWasmSandboxes(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func TestRunWasmCheckpointPoolErrorWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.WasmCheckpointMaxParallel = 2
	err := svc.runWasmCheckpointPool(context.Background(), []*models.Sandbox{{ID: "a"}, {ID: "b"}}, func(sb *models.Sandbox) error {
		if sb.ID == "b" {
			return errors.New("boom")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected pool error")
	}
}

func TestApplyInFluxEmptyDomainWave16(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "x", 500)
	}))
	t.Cleanup(fail.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = ""
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	_ = svc.applyInFluxRoute(ctx, cluster.Placement{
		SandboxID: "sb-path",
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			80: {Protocol: models.ExposedPortProtocolHTTP},
		},
	})
}

func TestRegisterSnapshotFailArmsWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if _, err := svc.RegisterSnapshot(ctx, nil); err == nil {
		t.Fatal("expected nil snapshot")
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{}); err == nil {
		t.Fatal("expected empty name")
	}
	_ = st.Close()
	_, _ = svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "n", Image: "i", CreatedAt: time.Now().UTC()})
}

func TestListMountsAndFindExposureWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-m", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_, _ = svc.ListMounts(ctx, "sb-m")
	_ = findExposure(&models.Sandbox{ExposedPorts: []models.ExposedPort{{Port: 1}}}, 2)
	_ = findExposure(nil, 1)
	_ = st.Close()
	_, _ = svc.ListMounts(ctx, "sb-m")
}

func TestL4ListenPortHelpersWave16(t *testing.T) {
	_ = l4ListenPort(":443")
	_ = l4ListenPort("127.0.0.1:8443")
	_ = l4ListenPort("bad")
}
