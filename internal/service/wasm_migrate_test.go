package service

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

var (
	_ wasmruntime.MigrationHost = (*fakeWasmMigrateRuntime)(nil)
)

type fakeWasmMigrateRuntime struct {
	wasmModuleAPINoopRuntime
	snapDir  string
	cloneGen string
}

type emptyMigrateRuntime struct {
	wasmModuleAPINoopRuntime
	memSnapDir string
	cloneGen   string
}

func (f *emptyMigrateRuntime) MigrateSandbox(_ context.Context, _ *models.Sandbox, _ string) (string, string, error) {
	return f.memSnapDir, f.cloneGen, nil
}

func (f *fakeWasmMigrateRuntime) MigrateSandbox(_ context.Context, sandbox *models.Sandbox, destDir string) (string, string, error) {
	id := "sandbox"
	if sandbox != nil && sandbox.ID != "" {
		id = sandbox.ID
	}
	dst := filepath.Join(destDir, id, "mem.snap")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", "", err
	}
	if err := copyWasmSnapshotDir(f.snapDir, dst); err != nil {
		return "", "", err
	}
	return dst, f.cloneGen, nil
}

func copyWasmSnapshotDir(src, dst string) error {
	for _, name := range wasmSnapshotTarFiles {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

type wasmMigrateClusterStub struct {
	*cluster.Noop
	selfID    string
	targetID  string
	targetURL string
	spec      *models.CreateSandboxRequest
}

func (c *wasmMigrateClusterStub) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{NodeID: c.selfID, IsSelf: true}, nil
}

func (c *wasmMigrateClusterStub) Members() []cluster.Member {
	targetURL := c.targetURL
	if targetURL == "" {
		targetURL = "http://target"
	}
	return []cluster.Member{
		{NodeID: c.selfID, APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: c.targetID, APIURL: targetURL, Alive: true, Role: config.NodeRoleWorker},
	}
}

func (c *wasmMigrateClusterStub) SpecOf(string) *models.CreateSandboxRequest {
	return c.spec
}

func insertWasmSandbox(t *testing.T, st *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:        id,
		Runtime:   models.RuntimeWasm,
		ModuleRef: "file:///tmp/demo.wasm",
		Image:     "file:///tmp/demo.wasm",
		Status:    models.SandboxStatusStarted,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Create sandbox %s: %v", id, err)
	}
}

func TestImportWasmMigrationRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	src := filepath.Join(t.TempDir(), "mem.snap")
	cap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc", Size: 1},
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-import-1",
		},
		Memory:    []byte("mem"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := wasmengine.WriteSnapshotDir(src, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	modulesDir := t.TempDir()
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir}, slog.Default(), st, nil, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: src, cloneGen: "gen-import-1"})
	svc.AttachCluster(&wasmMigrateClusterStub{
		Noop:     cluster.NewNoop("node-b", "http://node-b", ""),
		selfID:   "node-b",
		targetID: "node-a",
		spec: &models.CreateSandboxRequest{
			Runtime:   models.RuntimeWasm,
			ModuleRef: "file:///tmp/demo.wasm",
			Image:     "file:///tmp/demo.wasm",
		},
	})
	insertWasmSandbox(t, st, "sb-migrate-1")

	var tarBuf bytes.Buffer
	gen, err := svc.ExportWasmMigration(ctx, "sb-migrate-1", &tarBuf)
	if err != nil {
		t.Fatalf("ExportWasmMigration: %v", err)
	}
	if gen != "gen-import-1" {
		t.Fatalf("clone gen = %q", gen)
	}
	if err := svc.ImportWasmMigration(ctx, "sb-migrate-1", gen, bytes.NewReader(tarBuf.Bytes())); err != nil {
		t.Fatalf("ImportWasmMigration: %v", err)
	}
	got, err := st.Get(ctx, "sb-migrate-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != models.SandboxStatusPassivated || got.CloneGeneration != gen {
		t.Fatalf("row = status %q gen %q", got.Status, got.CloneGeneration)
	}
}

func TestMigrateWasmSandboxToNodePostsImportToTarget(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	src := filepath.Join(t.TempDir(), "mem.snap")
	cap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc", Size: 1},
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-handoff",
		},
		Memory:    []byte("mem"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := wasmengine.WriteSnapshotDir(src, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	var imported bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/import") {
			imported = true
			if got := r.Header.Get(cluster.WasmMigrateCloneGenHeader); got != "gen-handoff" {
				t.Errorf("clone gen header = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	const selfID = "node-a"
	const targetID = "node-b"
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, slog.Default(), st, nil, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: src, cloneGen: "gen-handoff"})
	svc.AttachCluster(&wasmMigrateClusterStub{
		Noop:      cluster.NewNoop(selfID, "http://self", ""),
		selfID:    selfID,
		targetID:  targetID,
		targetURL: ts.URL,
		spec: &models.CreateSandboxRequest{
			Runtime:   models.RuntimeWasm,
			ModuleRef: "file:///tmp/demo.wasm",
		},
	})
	insertWasmSandbox(t, st, "sb-handoff")

	resp, err := svc.MigrateWasmSandboxToNode(ctx, "sb-handoff", targetID)
	if err != nil {
		t.Fatalf("MigrateWasmSandboxToNode: %v", err)
	}
	if !imported {
		t.Fatal("expected import POST to target node")
	}
	if resp.SourceNodeID != selfID || resp.TargetNodeID != targetID || resp.CloneGeneration != "gen-handoff" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestPruneWasmCheckpointPushesKeepsLastN(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := New(config.Config{WasmCheckpointKeepLastN: 1}, slog.Default(), st, nil, nil, nil, nil, nil, nil)
	for i := 0; i < 3; i++ {
		if _, err := st.InsertWasmCheckpointPush(ctx, "sb-1", "ref-"+string(rune('a'+i)), "dig"); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	svc.pruneWasmCheckpointPushes(ctx, "sb-1")
	recs, err := st.ListWasmCheckpointPushes(ctx, "sb-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("kept %d rows, want 1", len(recs))
	}
}

func TestEnsureWasmSandboxRowForImport_CreatesNewRow(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true

	snap := wasmengine.SnapshotRestoreInput{
		Config: wasmengine.SnapshotConfig{
			Durability: string(models.DurabilityPassivatable),
			BaseModule: wasmengine.SnapshotBaseModule{Digest: "digest-1"},
		},
	}

	// This should fail initially because we don't have a cluster spec and module ref is missing
	err := svc.ensureWasmSandboxRowForImport(ctx, "sb-import-1", snap, "/path", "gen-1")
	if err == nil {
		t.Fatal("expected error missing cluster spec")
	}

	// Now we provide a fake cluster that returns a spec
	fakeCluster := &wasmMigrateClusterStub{
		Noop:   &cluster.Noop{},
		selfID: "node-1",
		spec: &models.CreateSandboxRequest{
			Runtime:    models.RuntimeWasm,
			ModuleRef:  "sha256:abcd",
			Durability: models.DurabilityPassivatable,
		},
	}
	svc.cfg.EnableCluster = true
	svc.clusterMu.Lock()
	svc.cluster = fakeCluster
	svc.clusterMu.Unlock()

	err = svc.ensureWasmSandboxRowForImport(ctx, "sb-import-1", snap, "/path", "gen-1")
	if err != nil {
		t.Fatalf("ensureWasmSandboxRowForImport failed: %v", err)
	}

	got, err := st.Get(ctx, "sb-import-1")
	if err != nil {
		t.Fatalf("get sandbox failed: %v", err)
	}
	if got.Status != models.SandboxStatusPassivated {
		t.Fatalf("status = %s", got.Status)
	}
	if got.ModuleRef != "sha256:abcd" {
		t.Fatalf("module_ref = %s", got.ModuleRef)
	}
}

func TestEnsureWasmSandboxRowForImport_UpdatesExistingRow(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true

	now := time.Now().UTC()
	st.Create(ctx, &models.Sandbox{
		ID:              "sb-import-exist",
		Runtime:         models.RuntimeWasm,
		Status:          models.SandboxStatusStarted,
		CloneGeneration: "gen-same",
		CreatedAt:       now, UpdatedAt: now,
	})

	snap := wasmengine.SnapshotRestoreInput{}
	err := svc.ensureWasmSandboxRowForImport(ctx, "sb-import-exist", snap, "/path", "gen-same")
	if err != nil {
		t.Fatalf("ensureWasmSandboxRowForImport failed: %v", err)
	}

	got, err := st.Get(ctx, "sb-import-exist")
	if err != nil {
		t.Fatalf("get sandbox failed: %v", err)
	}
	if got.Status != models.SandboxStatusPassivated {
		t.Fatalf("status = %s", got.Status)
	}
	if got.CheckpointPath != "/path" || got.CloneGeneration != "gen-same" {
		t.Fatalf("checkpoint path or clonegen mismatch")
	}
}

func TestWasmMigrationErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("export and import validation", func(t *testing.T) {
		svc := &Service{cfg: config.Config{EnableWasm: false}}
		if _, err := svc.ExportWasmMigration(ctx, "sb-any", io.Discard); err == nil {
			t.Fatal("ExportWasmMigration should fail when wasm is disabled")
		}
		if err := svc.ImportWasmMigration(ctx, " ", "", bytes.NewReader(nil)); err == nil {
			t.Fatal("ImportWasmMigration should reject blank sandbox IDs")
		}
	})

	t.Run("migrate orchestration validation", func(t *testing.T) {
		svc := &Service{}
		if _, _, err := svc.MigrateWasmSandbox(ctx, "sb", t.TempDir()); err == nil {
			t.Fatal("MigrateWasmSandbox should fail when wasm runtime is missing")
		}
		if _, err := svc.MigrateWasmSandboxToNode(ctx, "sb", "node-b"); err == nil {
			t.Fatal("MigrateWasmSandboxToNode should fail when cluster is nil")
		}

		svc = &Service{cfg: config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}}
		svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
		if _, err := svc.MigrateWasmSandboxToNode(ctx, " ", "node-b"); err == nil {
			t.Fatal("MigrateWasmSandboxToNode should reject blank sandbox IDs")
		}
		if _, err := svc.MigrateWasmSandboxToNode(ctx, "sb", " "); err == nil {
			t.Fatal("MigrateWasmSandboxToNode should reject blank target IDs")
		}
	})

	t.Run("export tar creation and import clone mismatch", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		svc := New(config.Config{EnableWasm: true, WasmModulesDir: filepath.Join(dir, "modules")}, slog.Default(), st, nil, nil, nil, nil, nil, nil)
		exportDir := t.TempDir()
		svc.SetWasmRuntime(&emptyMigrateRuntime{memSnapDir: exportDir, cloneGen: "gen-export"})
		insertWasmSandbox(t, st, "sb-export-empty")

		var tarBuf bytes.Buffer
		if _, err := svc.ExportWasmMigration(ctx, "sb-export-empty", &tarBuf); err == nil {
			t.Fatal("ExportWasmMigration should fail when mem.snap files are missing")
		}

		src := filepath.Join(t.TempDir(), "mem.snap")
		cap := wasmengine.SnapshotCapture{
			Config: wasmengine.SnapshotConfig{
				SchemaVersion:   1,
				Engine:          wasmengine.EngineNameWazero(),
				BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc", Size: 1},
				Durability:      models.DurabilityPassivatable,
				CloneGeneration: "gen-actual",
			},
			Memory:    []byte("mem"),
			Globals:   []byte("[]"),
			WASIState: []byte("{}"),
		}
		if err := wasmengine.WriteSnapshotDir(src, cap); err != nil {
			t.Fatalf("WriteSnapshotDir: %v", err)
		}
		if err := writeWasmCheckpointTar(&tarBuf, src); err != nil {
			t.Fatalf("writeWasmCheckpointTar: %v", err)
		}

		receiver := New(config.Config{EnableWasm: true, WasmModulesDir: filepath.Join(dir, "modules")}, slog.Default(), st, nil, nil, nil, nil, nil, nil)
		if err := receiver.ImportWasmMigration(ctx, "sb-clone-mismatch", "gen-wrong", bytes.NewReader(tarBuf.Bytes())); err == nil || !strings.Contains(err.Error(), "fenced") {
			t.Fatalf("ImportWasmMigration clone mismatch = %v", err)
		}
	})
}

func TestEvacuateLocalWasmSandboxesForDrainBranchCoverage(t *testing.T) {
	ctx := context.Background()

	t.Run("no-op branches", func(t *testing.T) {
		disabled := &Service{cfg: config.Config{EnableWasm: false}}
		if err := disabled.EvacuateLocalWasmSandboxesForDrain(ctx); err != nil {
			t.Fatalf("disabled service: %v", err)
		}

		noCluster := &Service{
			cfg:    config.Config{EnableWasm: true},
			wasm:   &recordingRuntime{},
			store:  &store.Store{},
			logger: slog.Default(),
		}
		if err := noCluster.EvacuateLocalWasmSandboxesForDrain(ctx); err != nil {
			t.Fatalf("no cluster service: %v", err)
		}
	})

	t.Run("store list error", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&recordingRuntime{})
		svc.AttachCluster(&wasmMigrationTargetClusterStub{
			Noop:    cluster.NewNoop("node-a", "http://self", ""),
			owner:   cluster.OwnerInfo{NodeID: "node-a", IsSelf: true},
			members: []cluster.Member{{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker}},
			drained: map[string]bool{},
		})
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if err := svc.EvacuateLocalWasmSandboxesForDrain(ctx); err == nil {
			t.Fatal("expected list error")
		}
	})

	t.Run("no target", func(t *testing.T) {
		now := time.Now().UTC()
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&recordingRuntime{})
		svc.AttachCluster(&wasmMigrationTargetClusterStub{
			Noop:    cluster.NewNoop("node-a", "http://self", ""),
			owner:   cluster.OwnerInfo{NodeID: "node-a", IsSelf: true},
			members: []cluster.Member{{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker}},
			drained: map[string]bool{},
		})
		if err := st.Create(ctx, &models.Sandbox{
			ID:         "sb-no-target",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusPassivated,
			Durability: models.DurabilityDurable,
			ModuleRef:  "file:///tmp/no-target.wasm",
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("Create sandbox: %v", err)
		}
		if err := svc.EvacuateLocalWasmSandboxesForDrain(ctx); err == nil || !strings.Contains(err.Error(), "no evacuation target") {
			t.Fatalf("no target evacuation = %v", err)
		}
	})

	t.Run("migration failure", func(t *testing.T) {
		now := time.Now().UTC()
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&recordingRuntime{})
		svc.AttachCluster(&wasmMigrationTargetClusterStub{
			Noop:    cluster.NewNoop("node-a", "http://self", ""),
			owner:   cluster.OwnerInfo{NodeID: "node-a", IsSelf: true},
			members: []cluster.Member{{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker}, {NodeID: "node-b", APIURL: "http://target", Alive: true, Role: config.NodeRoleWorker}},
			drained: map[string]bool{},
		})
		if err := st.Create(ctx, &models.Sandbox{
			ID:         "sb-migrate-fail",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusPassivated,
			Durability: models.DurabilityDurable,
			ModuleRef:  "file:///tmp/migrate-fail.wasm",
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("Create sandbox: %v", err)
		}
		if err := svc.EvacuateLocalWasmSandboxesForDrain(ctx); err == nil || !strings.Contains(err.Error(), "export:") {
			t.Fatalf("migrate failure evacuation = %v", err)
		}
	})
}
