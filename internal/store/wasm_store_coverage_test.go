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

	id1, err := st.InsertWasmCheckpointPush(ctx, sb.ID, "", "aocr://sb-push:v1", "digest-1")
	if err != nil || id1 <= 0 {
		t.Fatalf("InsertWasmCheckpointPush first = id %d err %v", id1, err)
	}
	id2, err := st.InsertWasmCheckpointPush(ctx, sb.ID, "", "aocr://sb-push:v2", "digest-2")
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
	sb.AuditIncarnationID = "inc-reg-1"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	applied, err := st.UpdateWasmRegistryPush(ctx, sb.ID, sb.AuditIncarnationID, "aocr://sb-reg:latest", "sha256:dead")
	if err != nil || !applied {
		t.Fatalf("UpdateWasmRegistryPush = applied %v, err %v", applied, err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.WasmRegistryRef != "aocr://sb-reg:latest" || got.WasmRegistryDigest != "sha256:dead" {
		t.Fatalf("registry fields = ref %q digest %q", got.WasmRegistryRef, got.WasmRegistryDigest)
	}

	// A push that lands after the id was re-created belongs to a dead
	// lifecycle: it must not overwrite the live row's checkpoint pointer.
	if _, err := st.UpdateWasmRegistryPush(ctx, sb.ID, "inc-reg-0", "aocr://stale:latest", "sha256:stale"); err != nil {
		t.Fatalf("stale UpdateWasmRegistryPush error = %v", err)
	}
	if applied, err := st.UpdateWasmRegistryPush(ctx, sb.ID, "inc-reg-0", "aocr://stale:latest", "sha256:stale"); err != nil || applied {
		t.Fatalf("stale UpdateWasmRegistryPush = applied %v, err %v; want applied=false", applied, err)
	}
	got, err = st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get after stale push: %v", err)
	}
	if got.WasmRegistryRef != "aocr://sb-reg:latest" || got.WasmRegistryDigest != "sha256:dead" {
		t.Fatalf("stale push overwrote the live lifecycle: ref %q digest %q", got.WasmRegistryRef, got.WasmRegistryDigest)
	}
	if _, err := st.UpdateWasmRegistryPush(ctx, sb.ID, "  ", "aocr://x", "sha256:x"); err == nil {
		t.Fatal("UpdateWasmRegistryPush accepted an empty incarnation")
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

// A row is orphaned when no LIVE lifetime owns it, not merely when the id is
// gone: a destroyed sandbox's id can be re-created, and the rejected pushes of
// the dead lifetime must still be reclaimable.
func TestOrphanedWasmCheckpointPushesRespectIncarnation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-orphan-inc")
	sb.Runtime = models.RuntimeWasm
	sb.AuditIncarnationID = "inc-live"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	live, _ := st.InsertWasmCheckpointPush(ctx, sb.ID, "inc-live", "reg/sb:live", "sha256:live")
	dead, _ := st.InsertWasmCheckpointPush(ctx, sb.ID, "inc-dead", "reg/sb:dead", "sha256:dead")
	gone, _ := st.InsertWasmCheckpointPush(ctx, "sb-gone", "inc-x", "reg/gone:x", "sha256:x")
	cleanup, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb-gone-2", "reg/gone2:latest")
	if err != nil {
		t.Fatal(err)
	}
	liveCleanup, err := st.EnsureWasmCheckpointCleanupRef(ctx, sb.ID, "reg/sb:latest")
	if err != nil {
		t.Fatal(err)
	}

	orphans, err := st.ListOrphanedWasmCheckpointPushes(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{}
	for _, o := range orphans {
		got[o.ID] = true
	}
	for id, want := range map[int64]bool{live: false, dead: true, gone: true, cleanup: true, liveCleanup: false} {
		if got[id] != want {
			t.Fatalf("row %d orphaned=%v, want %v (orphans=%+v)", id, got[id], want, orphans)
		}
	}

	scoped, err := st.ListWasmCheckpointPushesForIncarnation(ctx, sb.ID, "inc-live")
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].ID != live || scoped[0].IncarnationID != "inc-live" {
		t.Fatalf("incarnation-scoped history = %+v", scoped)
	}
}

// Deleting a checkpoint ref deletes its MANIFEST. WasmCheckpointRefInUse is the
// guard every deleter consults, so each way a dead lifetime's row can share the
// live lifetime's manifest has to be recognised — and a dead row must never
// protect anything, or two dead rows sharing a manifest could never be freed.
func TestWasmCheckpointRefInUse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-inuse")
	sb.Runtime = models.RuntimeWasm
	sb.AuditIncarnationID = "inc-live"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateWasmRegistryPush(ctx, sb.ID, "inc-live", "reg/sb:d-current", "sha256:current"); err != nil {
		t.Fatal(err)
	}
	liveHistory, _ := st.InsertWasmCheckpointPush(ctx, sb.ID, "inc-live", "reg/sb:d-kept", "sha256:kept")
	deadA, _ := st.InsertWasmCheckpointPush(ctx, sb.ID, "inc-dead", "reg/sb:d-shared-dead", "sha256:shared-dead")
	_, _ = st.InsertWasmCheckpointPush(ctx, sb.ID, "inc-dead", "reg/sb:d-shared-dead", "sha256:shared-dead")

	for _, tc := range []struct {
		name    string
		sandbox string
		exclude int64
		ref     string
		digest  string
		want    bool
	}{
		{"no live sandbox: nothing to protect", "sb-absent", 0, "reg/x:latest", "sha256:x", false},
		{"rolling :latest resolves to the live checkpoint", sb.ID, 0, "reg/sb:latest", "", true},
		{"the live row's own ref", sb.ID, 0, "reg/sb:d-current", "sha256:other", true},
		{"a different tag for the live row's manifest", sb.ID, 0, "reg/sb:d-alias", "sha256:current", true},
		{"a manifest the live lifetime still retains", sb.ID, 0, "reg/sb:d-kept", "", true},
		{"a live history row does not protect itself", sb.ID, liveHistory, "reg/sb:d-kept", "sha256:kept", false},
		{"dead rows sharing a manifest protect nothing", sb.ID, deadA, "reg/sb:d-shared-dead", "sha256:shared-dead", false},
		{"cleanup-only is not a digest", sb.ID, 0, "reg/sb:d-unrelated", "cleanup-only", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.WasmCheckpointRefInUse(ctx, tc.sandbox, tc.exclude, tc.ref, tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("in use = %v, want %v", got, tc.want)
			}
		})
	}
}
