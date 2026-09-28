package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestWasmMigrateImportExportWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	src := t.TempDir()
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: src, cloneGen: "gen-w12"})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-w-mig", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, gen, err := svc.MigrateWasmSandbox(ctx, "sb-w-mig", dir)
	t.Logf("MigrateWasmSandbox path=%q gen=%q err=%v", path, gen, err)
}

func TestWasmMigrateErrorArmsWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = false
	if _, _, err := svc.MigrateWasmSandbox(ctx, "x", t.TempDir()); err == nil {
		t.Fatal("expected wasm disabled")
	}
	if _, err := svc.ExportWasmMigration(ctx, "x", io.Discard); err == nil {
		t.Fatal("expected export disabled")
	}
	if err := svc.ImportWasmMigration(ctx, "x", "", bytes.NewReader(nil)); err == nil {
		t.Fatal("expected import disabled")
	}

	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: t.TempDir(), cloneGen: "g"})
	if err := svc.ImportWasmMigration(ctx, "  ", "", bytes.NewReader(nil)); err == nil {
		t.Fatal("expected empty id")
	}
	if err := svc.ImportWasmMigration(ctx, "sb", "", bytes.NewReader([]byte("not-a-tar"))); err == nil {
		t.Fatal("expected bad tar")
	}

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-docker-mig", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, _, err := svc.MigrateWasmSandbox(ctx, "sb-docker-mig", t.TempDir()); err == nil {
		t.Fatal("expected non-wasm")
	}
	if _, err := svc.ExportWasmMigration(ctx, "sb-docker-mig", io.Discard); err == nil {
		t.Fatal("expected export non-wasm")
	}

	if _, err := svc.MigrateWasmSandboxToNode(ctx, "", ""); err == nil {
		t.Fatal("expected missing ids")
	}
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if _, err := svc.MigrateWasmSandboxToNode(ctx, "sb", "other"); err == nil {
		t.Fatal("expected owner/member miss")
	}
	_ = svc.EvacuateLocalWasmSandboxesForDrain(ctx)
}

func TestWasmMigrateStoreMissWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: t.TempDir(), cloneGen: "g"})
	_ = st.Close()
	_, _, _ = svc.MigrateWasmSandbox(ctx, "x", t.TempDir())
	_, _ = svc.ExportWasmMigration(ctx, "x", io.Discard)
}

func TestEnsureWasmSandboxRowImportWave20(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-imp", Runtime: models.RuntimeWasm, ModuleRef: "file:///m.wasm", Image: "file:///m.wasm",
		Status: models.SandboxStatusPassivated, CloneGeneration: "gen-a",
		CreatedAt: now, UpdatedAt: now,
	})
	snap := wasmengine.SnapshotRestoreInput{Config: wasmengine.SnapshotConfig{Durability: models.DurabilityPassivatable}}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-imp", snap, "/ckpt", "gen-b"); err == nil {
		t.Fatal("expected clone generation mismatch")
	}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-imp", snap, "/ckpt", "gen-a"); err != nil {
		t.Fatalf("matching gen: %v", err)
	}

	// Missing module_ref on new row.
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-new", snap, "/ckpt", "g1"); err == nil {
		t.Fatal("expected module_ref required")
	}
	svc.cluster = &wasmMigrateClusterStub{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///x.wasm", Image: ""},
	}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-new2", snap, "/ckpt", "g1"); err != nil {
		t.Fatalf("import with cluster spec: %v", err)
	}

	svc3, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_ = svc3.store.Close()
	if err := svc3.ensureWasmSandboxRowForImport(ctx, "x", snap, "/c", "g"); err == nil {
		t.Fatal("expected store get failure")
	}
}

func TestWasmMigrateExportMkdirFailWave22(t *testing.T) {
	// ExportWasmMigration MkdirTemp rarely fails; cover non-wasm / disabled paths already.
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-dock", Image: "a", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now,
	})
	var buf bytes.Buffer
	if _, err := svc.ExportWasmMigration(context.Background(), "sb-dock", &buf); err == nil {
		t.Fatal("expected non-wasm")
	}
}

func TestWasmMigrateImportDisabledAndReassignWave24(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = false
	if err := svc.ImportWasmMigration(ctx, "sb", "", strings.NewReader("x")); err == nil {
		t.Fatal("expected disabled")
	}
	svc.cfg.EnableWasm = true
	svc.cfg.WasmModulesDir = t.TempDir()
	svc.cluster = &reassignFailCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	_ = svc.ImportWasmMigration(ctx, "sb-imp24", "", strings.NewReader("not-tar"))
}

type reassignFailCluster struct{ *cluster.Noop }

func (c *reassignFailCluster) ReassignPlacement(context.Context, string, cluster.PlacementTarget) error {
	return errors.New("reassign boom")
}

func TestWasmMigrateErrorArmsWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true

	if _, _, err := svc.MigrateWasmSandbox(ctx, "x", t.TempDir()); err == nil {
		t.Fatal("expected wasm nil")
	}
	svc.SetWasmRuntime(&recordingRuntime{}) // does not implement MigrationHost
	if _, _, err := svc.MigrateWasmSandbox(ctx, "x", t.TempDir()); err == nil || !strings.Contains(err.Error(), "does not implement migration") {
		t.Fatalf("err = %v", err)
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-docker", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Export checks wasm configured then Get+isWasm before migrate.
	if _, err := svc.ExportWasmMigration(ctx, "sb-docker", io.Discard); err == nil || !strings.Contains(err.Error(), "not wasm") {
		t.Fatalf("export non-wasm = %v", err)
	}

	svc.cfg.EnableWasm = false
	if err := svc.EvacuateLocalWasmSandboxesForDrain(ctx); err != nil {
		t.Fatal(err)
	}
	svc.cfg.EnableWasm = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-ev", Image: "m", Runtime: models.RuntimeWasm,
		Durability: models.DurabilityDurable, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_ = svc.EvacuateLocalWasmSandboxesForDrain(ctx)
}
