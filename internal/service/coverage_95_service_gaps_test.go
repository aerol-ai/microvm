package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestStartSandboxEgressPolicyRequiresContainerRuntime(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.docker = noContainerRuntime{}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-egress", Image: "alpine", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeDocker, ContainerID: "ctr-egress",
		NetworkAllowOut: []string{"10.0.0.0/8"},
		CreatedAt:       now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.StartSandbox(ctx, "sb-egress")
	if err == nil || !strings.Contains(err.Error(), "selective egress") {
		t.Fatalf("StartSandbox = %v, want selective egress error", err)
	}
}

func TestFacadeUpdateTagsMissingSandbox(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.UpdateTags(context.Background(), "missing", map[string]string{"a": "b"}); err == nil {
		t.Fatal("UpdateTags missing sandbox should fail")
	}
}

func TestLocalReadyWasmModuleInventoryListFailureUsesCache(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-1", ModuleRef: "file:///tmp/mod-1.wasm",
		Status: string(models.WasmModuleStatusReady),
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	refs, known := svc.LocalReadyWasmModuleInventory(ctx)
	if !known || len(refs) == 0 {
		t.Fatalf("inventory = %v known=%v", refs, known)
	}
	_ = st.Close()
	// Force cache expiry so the closed store's ListReadyWasmModuleRefs errors
	// and the failure path returns the previous cache.
	svc.localReadyWasmModuleIDsExpires = time.Now().Add(-time.Second)
	refs2, known2 := svc.LocalReadyWasmModuleInventory(ctx)
	if !known2 || len(refs2) == 0 {
		t.Fatalf("cache fallback = %v known=%v", refs2, known2)
	}
}

func TestRunTemplateGCReferencedAndCleanup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newHealthHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)

	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-old", Image: "x", Status: models.TemplateStatusReady,
		CreatedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-ref", Image: "y", Status: models.TemplateStatusReady,
		CreatedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-uses-tpl", Image: "y", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeFirecracker, TemplateID: "tpl-ref",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	svc.runTemplateGC(ctx, now)
	if _, err := st.GetTemplate(ctx, "tpl-old"); err == nil {
		t.Fatal("unreferenced old template should be GC'd")
	}
	if _, err := st.GetTemplate(ctx, "tpl-ref"); err != nil {
		t.Fatalf("referenced template GC'd: %v", err)
	}
}

func TestDeletePlatformVolumeInUseAndByNameMiss(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "vol1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.store.Create(ctx, &models.Sandbox{
		ID: "sb-vol", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		VolumeID: v.ID, SandboxID: "sb-vol", Target: "/data", Tenant: v.Tenant, Source: v.Source,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePlatformVolume(ctx, v.ID); err == nil || !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("delete attached = %v, want ErrPlatformVolumeInUse", err)
	}
	if _, err := s.GetPlatformVolumeByName(ctx, "no-such-vol"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by name miss = %v", err)
	}
}

func TestApplyInFluxRouteHelpers(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	p := cluster.Placement{SandboxID: "sb-flux", OwnerNodeID: "self"}
	if err := svc.applyInFluxSandboxRoute(context.Background(), p); err != nil {
		t.Fatalf("applyInFluxSandboxRoute: %v", err)
	}
	if err := svc.applyInFluxPortRoute(context.Background(), p, 8080); err != nil {
		t.Fatalf("applyInFluxPortRoute: %v", err)
	}
	if err := svc.applyInFluxRoute(context.Background(), p); err != nil {
		t.Fatalf("applyInFluxRoute: %v", err)
	}
}

func TestSealClusterSecretEnvelopeRandFailure(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	binding := secrets.SealBinding{SandboxID: "sb", Ref: secrets.FormatRef("sb", 1), Version: 1, Generation: 1}
	if _, err := secrets.SealRawEnvelopeBound(s.cipher, []byte(`{}`), []string{"node-a"}, binding); err == nil {
		t.Fatal("expected rand failure")
	}
}

func TestCreateIsolateStoreFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	// Use the full harness (supports isolate in Admitter), then close the store
	// after wiring so createIsolateSandbox's store.Create fails and rolls back.
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	driver := &recordingRuntime{}
	svc.SetIsolateRuntime(driver)
	_ = st.Close()

	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "sb-iso-store-fail")
	if err == nil {
		t.Fatal("expected store failure")
	}
	if driver.createCalls == 0 {
		t.Fatalf("driver never reached: %v", err)
	}
	if len(driver.destroyIDs) == 0 {
		t.Fatalf("store create failure must Destroy the driver sandbox; err=%v", err)
	}
}

func TestMountHelpersCoverage(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cipher = newTestCipher(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-mnt", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	specs := []models.MountSpec{{
		Type: models.MountTypeNFS, Target: "/data", Source: "nfs:/export",
	}}
	sealed, err := svc.sealMounts(specs)
	if err != nil || len(sealed) == 0 {
		t.Fatalf("sealMounts: %v", err)
	}
	if err := st.PutMounts(ctx, "sb-mnt", sealed); err != nil {
		t.Fatal(err)
	}
	got, err := svc.loadMounts(ctx, "sb-mnt")
	if err != nil || len(got) != 1 {
		t.Fatalf("loadMounts = %v, %v", got, err)
	}
	listed, err := svc.ListMounts(ctx, "sb-mnt")
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListMounts = %v, %v", listed, err)
	}
	empty, err := svc.sealMounts(nil)
	if err != nil || empty != nil {
		t.Fatalf("empty sealMounts = %v, %v", empty, err)
	}
}
