package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWasmModuleCatalogueCRUD(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	readyAt := time.Now().UTC().Add(-time.Hour)
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID:              "mod-a",
		ModuleRef:       "hello.wasm",
		Status:          "ready",
		ModulePath:      "/data/hello.wasm",
		ModuleSizeBytes: 4096,
		Digest:          "sha256:abc",
		Entrypoint:      "_start",
		HasWarm:         true,
		ReadyAt:         &readyAt,
		CreatedAt:       readyAt,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	got, err := st.GetWasmModule(ctx, "mod-a")
	if err != nil {
		t.Fatalf("GetWasmModule: %v", err)
	}
	if got.ModuleRef != "hello.wasm" || got.Status != "ready" || !got.HasWarm || got.ReadyAt == nil {
		t.Fatalf("GetWasmModule = %+v", got)
	}

	old := time.Now().UTC().Add(-48 * time.Hour)
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID:        "mod-old",
		ModuleRef: "stale.wasm",
		Status:    "failed",
		CreatedAt: old,
	}); err != nil {
		t.Fatalf("UpsertWasmModule old: %v", err)
	}

	refs, err := st.ListReadyWasmModuleRefs(ctx)
	if err != nil {
		t.Fatalf("ListReadyWasmModuleRefs: %v", err)
	}
	if len(refs) != 1 || refs[0] != "hello.wasm" {
		t.Fatalf("ListReadyWasmModuleRefs = %v", refs)
	}

	// UpsertWasmModule always stamps updated_at to now; use a future cutoff so
	// every catalogue row qualifies without reaching into the private DB handle.
	stale, err := st.ListWasmModulesOlderThan(ctx, time.Now().UTC().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("ListWasmModulesOlderThan: %v", err)
	}
	if len(stale) < 2 {
		t.Fatalf("ListWasmModulesOlderThan = %d rows, want >= 2", len(stale))
	}

	all, err := st.ListWasmModules(ctx)
	if err != nil {
		t.Fatalf("ListWasmModules: %v", err)
	}
	if len(all) < 2 {
		t.Fatalf("ListWasmModules = %d rows, want >= 2", len(all))
	}

	catalogued, err := st.IsWasmDigestCatalogued(ctx, "sha256:abc")
	if err != nil || !catalogued {
		t.Fatalf("IsWasmDigestCatalogued = %v err=%v", catalogued, err)
	}
	catalogued, err = st.IsWasmDigestCatalogued(ctx, "")
	if err != nil || catalogued {
		t.Fatalf("empty digest = %v err=%v", catalogued, err)
	}
	catalogued, err = st.IsWasmDigestCatalogued(ctx, "missing")
	if err != nil || catalogued {
		t.Fatalf("missing digest = %v err=%v", catalogued, err)
	}

	if err := st.DeleteWasmModule(ctx, "mod-a"); err != nil {
		t.Fatalf("DeleteWasmModule: %v", err)
	}
	if _, err := st.GetWasmModule(ctx, "mod-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWasmModule after delete = %v, want ErrNotFound", err)
	}
	if err := st.DeleteWasmModule(ctx, "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteWasmModule missing = %v, want ErrNotFound", err)
	}
	if _, err := st.GetWasmModule(ctx, ""); err == nil {
		t.Fatal("GetWasmModule empty id should error")
	}
	if err := st.DeleteWasmModule(ctx, ""); err == nil {
		t.Fatal("DeleteWasmModule empty id should error")
	}
}

func TestWasmCheckpointPushHistory(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	sb := sampleSandbox("sb-push")
	sb.Runtime = models.RuntimeWasm
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	id1, err := st.InsertWasmCheckpointPush(ctx, sb.ID, "aocr://sb-push:v1", "digest-1")
	if err != nil || id1 <= 0 {
		t.Fatalf("InsertWasmCheckpointPush first = id %d err %v", id1, err)
	}
	id2, err := st.InsertWasmCheckpointPush(ctx, sb.ID, "aocr://sb-push:v2", "digest-2")
	if err != nil || id2 <= id1 {
		t.Fatalf("InsertWasmCheckpointPush second = id %d err %v", id2, err)
	}

	pushes, err := st.ListWasmCheckpointPushes(ctx, sb.ID)
	if err != nil {
		t.Fatalf("ListWasmCheckpointPushes: %v", err)
	}
	if len(pushes) != 2 || pushes[0].Digest != "digest-2" {
		t.Fatalf("ListWasmCheckpointPushes = %+v", pushes)
	}

	if err := st.DeleteWasmCheckpointPush(ctx, id1); err != nil {
		t.Fatalf("DeleteWasmCheckpointPush: %v", err)
	}
	pushes, err = st.ListWasmCheckpointPushes(ctx, sb.ID)
	if err != nil {
		t.Fatalf("ListWasmCheckpointPushes after delete: %v", err)
	}
	if len(pushes) != 1 || pushes[0].ID != id2 {
		t.Fatalf("after single delete = %+v", pushes)
	}

	if err := st.DeleteAllWasmCheckpointPushes(ctx, sb.ID); err != nil {
		t.Fatalf("DeleteAllWasmCheckpointPushes: %v", err)
	}
	pushes, err = st.ListWasmCheckpointPushes(ctx, sb.ID)
	if err != nil {
		t.Fatalf("ListWasmCheckpointPushes after delete all: %v", err)
	}
	if len(pushes) != 0 {
		t.Fatalf("expected no pushes, got %+v", pushes)
	}
	if err := st.DeleteAllWasmCheckpointPushes(ctx, ""); err != nil {
		t.Fatalf("DeleteAllWasmCheckpointPushes empty id: %v", err)
	}
}

func TestEnsureWasmCheckpointCleanupRefIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	first, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb-cleanup", "aocr://sb-cleanup:latest")
	if err != nil || first <= 0 {
		t.Fatalf("first ensure = id %d err %v", first, err)
	}
	second, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb-cleanup", "aocr://sb-cleanup:latest")
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if second != first {
		t.Fatalf("second ensure id = %d, want existing id %d", second, first)
	}
	pushes, err := st.ListWasmCheckpointPushes(ctx, "sb-cleanup")
	if err != nil {
		t.Fatalf("list pushes: %v", err)
	}
	if len(pushes) != 1 || pushes[0].Digest != "cleanup-only" {
		t.Fatalf("cleanup rows = %+v, want one cleanup-only row", pushes)
	}
}

func TestWasmStateKVDeleteAll(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const sandboxID = "sb-kv-all"

	if err := st.PutWasmStateKV(ctx, sandboxID, "a", []byte("1")); err != nil {
		t.Fatalf("PutWasmStateKV a: %v", err)
	}
	if err := st.PutWasmStateKV(ctx, sandboxID, "b", []byte("2")); err != nil {
		t.Fatalf("PutWasmStateKV b: %v", err)
	}
	if err := st.PutWasmStateKV(ctx, "", "k", []byte("x")); err == nil {
		t.Fatal("PutWasmStateKV empty sandbox id should error")
	}

	if err := st.DeleteAllWasmStateKV(ctx, sandboxID); err != nil {
		t.Fatalf("DeleteAllWasmStateKV: %v", err)
	}
	keys, err := st.ListWasmStateKVKeys(ctx, sandboxID)
	if err != nil {
		t.Fatalf("ListWasmStateKVKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys after delete all = %v", keys)
	}
	if err := st.DeleteAllWasmStateKV(ctx, ""); err != nil {
		t.Fatalf("DeleteAllWasmStateKV empty id: %v", err)
	}
}

func TestWasmRegistryPushRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	sb := sampleSandbox("sb-reg")
	sb.Runtime = models.RuntimeWasm
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.UpdateWasmRegistryPush(ctx, sb.ID, "aocr://sb-reg:latest", "sha256:dead"); err != nil {
		t.Fatalf("UpdateWasmRegistryPush: %v", err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.WasmRegistryRef != "aocr://sb-reg:latest" || got.WasmRegistryDigest != "sha256:dead" {
		t.Fatalf("registry fields = ref %q digest %q", got.WasmRegistryRef, got.WasmRegistryDigest)
	}
}

func TestCompareCloneGenerationEdgeCases(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.CompareCloneGeneration(ctx, "missing", "gen"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CompareCloneGeneration missing sandbox = %v, want ErrNotFound", err)
	}

	sb := sampleSandbox("sb-gen")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.CompareCloneGeneration(ctx, sb.ID, ""); err != nil {
		t.Fatalf("CompareCloneGeneration empty snapshot gen: %v", err)
	}
	if err := st.CompareCloneGeneration(ctx, sb.ID, "any"); err != nil {
		t.Fatalf("CompareCloneGeneration empty row gen: %v", err)
	}
}

func TestScanSandboxGPUAndNetQuotaFields(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	sb := sampleSandbox("sb-scan-fields")
	sb.GPUs = &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 1}
	now := time.Now().UTC()
	sb.NetworkQuotaExceeded = true
	sb.NetworkQuotaExceededAt = &now
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GPUs == nil || got.GPUs.Count != 1 {
		t.Fatalf("GPUs = %+v, want count 1", got.GPUs)
	}
	if !got.NetworkQuotaExceeded || got.NetworkQuotaExceededAt == nil {
		t.Fatalf("quota fields = exceeded %v at %v", got.NetworkQuotaExceeded, got.NetworkQuotaExceededAt)
	}

	// Mark via store path so scanSandbox decodes net_quota_exceeded_at.
	if err := st.MarkNetworkQuotaExceeded(ctx, sb.ID, now); err != nil {
		t.Fatalf("MarkNetworkQuotaExceeded: %v", err)
	}
	got, err = st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get after mark: %v", err)
	}
	if got.NetworkQuotaExceededAt == nil {
		t.Fatal("NetworkQuotaExceededAt should be set after MarkNetworkQuotaExceeded")
	}
}
