package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

var _ wasmruntime.CheckpointHost = (*fakeWasmRecreateRuntime)(nil)

type fakeWasmRecreateRuntime struct {
	wasmModuleAPINoopRuntime
	noopWasmPortGateway
	rehydrated   []string
	rehydrateErr error
}

type noopWasmPortGateway struct{}

func (noopWasmPortGateway) EnsureHTTPListener(_ context.Context, _ string, _ int) (string, error) {
	return "127.0.0.1:0", nil
}

func (noopWasmPortGateway) ReleaseHTTPListener(string, int) {}

func (noopWasmPortGateway) SyncAllowedPorts(string, []int) {}

func (f *fakeWasmRecreateRuntime) CheckpointSandbox(context.Context, *models.Sandbox) (string, string, error) {
	return "", "", nil
}

func (f *fakeWasmRecreateRuntime) RehydrateSandbox(_ context.Context, sandbox *models.Sandbox, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if f.rehydrateErr != nil {
		return nil, f.rehydrateErr
	}
	if sandbox != nil {
		f.rehydrated = append(f.rehydrated, sandbox.ID)
	}
	return &models.SandboxRuntimeState{
		ContainerID: "wasm:" + sandbox.ID,
		ContainerIP: "127.0.0.1",
		Status:      models.SandboxStatusStarted,
	}, nil
}

type fakeWasmCheckpointStore struct {
	pullSrc   string
	pulled    int
	pullErr   error
	afterPull func()
}

func (f *fakeWasmCheckpointStore) DestRefFor(id string) string { return "test://" + id + ":latest" }

func (f *fakeWasmCheckpointStore) DestRefTagged(id, tag string) string {
	return "test://" + id + ":" + tag
}

func (f *fakeWasmCheckpointStore) PushOnceTo(context.Context, string, string, string) (WasmCheckpointPushResult, error) {
	return WasmCheckpointPushResult{}, nil
}

func (f *fakeWasmCheckpointStore) PullOnce(_ context.Context, _, dstDir string) error {
	f.pulled++
	if f.pullErr != nil {
		return f.pullErr
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	if err := copyWasmSnapshotDir(f.pullSrc, dstDir); err != nil {
		return err
	}
	if f.afterPull != nil {
		f.afterPull()
	}
	return nil
}

func (f *fakeWasmCheckpointStore) DeleteRef(context.Context, string) error { return nil }

func seedWasmSnapshot(t *testing.T, dir string, cloneGen string) {
	t.Helper()
	cap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:failover", Size: 1},
			Durability:      models.DurabilityDurable,
			CloneGeneration: cloneGen,
		},
		Memory:    []byte{0, 1, 2, 3},
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := wasmengine.WriteSnapshotDir(dir, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
}

func TestRecreateWasmDurableSandbox_ExistingPassivatedRehydrates(t *testing.T) {
	ctx := context.Background()
	modulesDir := t.TempDir()
	checkpointPath := filepath.Join(modulesDir, "sb-failover-1", "mem.snap")
	seedWasmSnapshot(t, checkpointPath, "gen-failover-1")

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:              "sb-failover-1",
		Runtime:         models.RuntimeWasm,
		Durability:      models.DurabilityDurable,
		ModuleRef:       "file:///tmp/demo.wasm",
		Status:          models.SandboxStatusPassivated,
		CheckpointPath:  checkpointPath,
		CloneGeneration: "gen-failover-1",
		CreatedAt:       now,
		UpdatedAt:       now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)

	if err := svc.recreateWasmDurableSandbox(ctx, "sb-failover-1", models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
	}, nil); err != nil {
		t.Fatalf("recreateWasmDurableSandbox: %v", err)
	}
	if len(rt.rehydrated) != 1 || rt.rehydrated[0] != "sb-failover-1" {
		t.Fatalf("rehydrated = %v", rt.rehydrated)
	}
	got, err := st.Get(ctx, "sb-failover-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", got.Status)
	}
}

func TestRecreateWasmDurableSandbox_AOCRPullThenRehydrates(t *testing.T) {
	ctx := context.Background()
	modulesDir := t.TempDir()
	remoteSnap := filepath.Join(t.TempDir(), "remote-mem.snap")
	seedWasmSnapshot(t, remoteSnap, "gen-pull-1")

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	puller := &fakeWasmCheckpointStore{pullSrc: remoteSnap}
	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)
	svc.AttachWasmCheckpointPusher(puller)

	spec := models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
	}
	if err := svc.recreateWasmDurableSandbox(ctx, "sb-failover-pull", spec, nil); err != nil {
		t.Fatalf("recreateWasmDurableSandbox: %v", err)
	}
	if puller.pulled != 1 {
		t.Fatalf("pull count = %d, want 1", puller.pulled)
	}
	if len(rt.rehydrated) != 1 || rt.rehydrated[0] != "sb-failover-pull" {
		t.Fatalf("rehydrated = %v", rt.rehydrated)
	}
	localPath := wasmCheckpointDir(modulesDir, "sb-failover-pull")
	if !wasmengine.DirExists(localPath) {
		t.Fatalf("checkpoint missing at %s", localPath)
	}
	got, err := st.Get(ctx, "sb-failover-pull")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CloneGeneration != "gen-pull-1" {
		t.Fatalf("clone_generation = %q", got.CloneGeneration)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", got.Status)
	}
}

func TestRehydrateWasmDurableSandbox_CorruptLocalCheckpointPullsAOCR(t *testing.T) {
	ctx := context.Background()
	modulesDir := t.TempDir()
	remoteSnap := filepath.Join(t.TempDir(), "remote-mem.snap")
	seedWasmSnapshot(t, remoteSnap, "gen-pull-good")
	localPath := wasmCheckpointDir(modulesDir, "sb-corrupt")
	if err := os.MkdirAll(localPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localPath, "config.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:              "sb-corrupt",
		Runtime:         models.RuntimeWasm,
		Durability:      models.DurabilityDurable,
		Status:          models.SandboxStatusPassivated,
		CheckpointPath:  localPath,
		CloneGeneration: "gen-local-bad",
		WasmRegistryRef: "test://sb-corrupt:latest",
		ModuleRef:       "file:///tmp/demo.wasm",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	puller := &fakeWasmCheckpointStore{pullSrc: remoteSnap}
	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)
	svc.AttachWasmCheckpointPusher(puller)

	if _, err := svc.rehydrateWasmIfNeeded(ctx, sb, nil); err != nil {
		t.Fatalf("rehydrateWasmIfNeeded: %v", err)
	}
	if puller.pulled != 1 {
		t.Fatalf("pull count = %d, want 1", puller.pulled)
	}
	if _, err := wasmengine.ReadSnapshotDir(localPath, wasmengine.EngineNameWazero()); err != nil {
		t.Fatalf("local checkpoint should be replaced with valid pull: %v", err)
	}
}

func TestRecreateSandboxWasmDurableFailoverE2E(t *testing.T) {
	ctx := context.Background()
	modulesDir := t.TempDir()
	remoteSnap := filepath.Join(t.TempDir(), "remote-mem.snap")
	seedWasmSnapshot(t, remoteSnap, "gen-e2e-1")

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	puller := &fakeWasmCheckpointStore{pullSrc: remoteSnap}
	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir, EnableCluster: true}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)
	svc.AttachWasmCheckpointPusher(puller)

	spec := models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
	}
	if err := svc.RecreateSandbox(ctx, "sb-failover-e2e", spec, cluster.PlacementSecrets{}, nil); err != nil {
		t.Fatalf("RecreateSandbox: %v", err)
	}
	if puller.pulled != 1 {
		t.Fatalf("pull count = %d, want 1", puller.pulled)
	}
	if len(rt.rehydrated) != 1 {
		t.Fatalf("rehydrated = %v", rt.rehydrated)
	}
}

func TestRecreateSandboxWasmDurableFailoverReplaysPorts(t *testing.T) {
	ctx := context.Background()
	modulesDir := t.TempDir()
	checkpointPath := filepath.Join(modulesDir, "sb-wasm-ports", "mem.snap")
	seedWasmSnapshot(t, checkpointPath, "gen-ports-1")

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:              "sb-wasm-ports",
		Runtime:         models.RuntimeWasm,
		Durability:      models.DurabilityDurable,
		ModuleRef:       "file:///tmp/demo.wasm",
		Status:          models.SandboxStatusPassivated,
		CheckpointPath:  checkpointPath,
		CloneGeneration: "gen-ports-1",
		ContainerID:     "wasm:sb-wasm-ports",
		ContainerIP:     "127.0.0.1",
		CreatedAt:       now,
		UpdatedAt:       now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{
		EnableWasm:     true,
		WasmModulesDir: modulesDir,
		EnableCluster:  true,
		EnableCaddy:    true,
		Domain:         "wasm.test",
	}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		EnableCaddy:       true,
		Domain:            "wasm.test",
		HTTPClientTimeout: time.Second,
	})

	ports := map[int]cluster.ExposedPortRoute{
		8080: {Protocol: models.ExposedPortProtocolHTTP},
	}
	spec := models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
	}
	if err := svc.RecreateSandbox(ctx, "sb-wasm-ports", spec, cluster.PlacementSecrets{}, ports); err != nil {
		t.Fatalf("RecreateSandbox: %v", err)
	}
	if len(rt.rehydrated) != 1 || rt.rehydrated[0] != "sb-wasm-ports" {
		t.Fatalf("rehydrated = %v", rt.rehydrated)
	}
}

func TestRecreateWasmDurableSandboxEdgeBranches(t *testing.T) {
	ctx := context.Background()
	modulesDir := t.TempDir()

	t.Run("store get error", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("store open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, &fakeWasmRecreateRuntime{}, nil, nil, nil, nil, nil)
		if err := svc.recreateWasmDurableSandbox(ctx, "sb-closed", models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm"}, nil); err == nil {
			t.Fatal("expected store get error")
		}
	})

	t.Run("missing module ref", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("store open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, &fakeWasmRecreateRuntime{}, nil, nil, nil, nil, nil)
		if err := svc.recreateWasmDurableSandbox(ctx, "sb-missing-ref", models.CreateSandboxRequest{Runtime: models.RuntimeWasm}, nil); err == nil {
			t.Fatal("expected missing module_ref error")
		}
	})

	t.Run("checkpoint pull failure", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("store open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		puller := &fakeWasmCheckpointStore{pullErr: errors.New("pull failed")}
		rt := &fakeWasmRecreateRuntime{}
		svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
		svc.AttachWasmCheckpointPusher(puller)
		if err := svc.recreateWasmDurableSandbox(ctx, "sb-pull-fail", models.CreateSandboxRequest{Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable, ModuleRef: "file:///tmp/demo.wasm"}, nil); err == nil {
			t.Fatal("expected checkpoint pull failure")
		}
	})

	t.Run("store upsert failure", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("store open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		remoteSnap := filepath.Join(t.TempDir(), "remote-mem.snap")
		seedWasmSnapshot(t, remoteSnap, "gen-upsert")
		puller := &fakeWasmCheckpointStore{
			pullSrc: remoteSnap,
			afterPull: func() {
				_ = st.Close()
			},
		}
		rt := &fakeWasmRecreateRuntime{}
		svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
		svc.AttachWasmCheckpointPusher(puller)
		if err := svc.recreateWasmDurableSandbox(ctx, "sb-upsert-fail", models.CreateSandboxRequest{Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable, ModuleRef: "file:///tmp/demo.wasm"}, nil); err == nil {
			t.Fatal("expected store upsert failure")
		}
	})

	t.Run("rehydrate failure", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("store open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		remoteSnap := filepath.Join(t.TempDir(), "remote-mem.snap")
		seedWasmSnapshot(t, remoteSnap, "gen-rehydrate")
		puller := &fakeWasmCheckpointStore{pullSrc: remoteSnap}
		rt := &fakeWasmRecreateRuntime{rehydrateErr: errors.New("rehydrate failed")}
		svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
		svc.SetWasmRuntime(rt)
		svc.AttachWasmCheckpointPusher(puller)
		if err := svc.recreateWasmDurableSandbox(ctx, "sb-rehydrate-fail", models.CreateSandboxRequest{Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable, ModuleRef: "file:///tmp/demo.wasm"}, nil); err == nil {
			t.Fatal("expected rehydrate failure")
		}
	})
}
