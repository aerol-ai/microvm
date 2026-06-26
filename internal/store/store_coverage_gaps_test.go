package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestListAttachesPortsAndCustomDomains(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	sbA := sampleSandbox("sb-list-a")
	sbB := sampleSandbox("sb-list-b")
	for _, sb := range []*models.Sandbox{sbA, sbB} {
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create %s: %v", sb.ID, err)
		}
	}

	for i, sb := range []*models.Sandbox{sbA, sbB} {
		port := 8080 + i
		if err := st.UpsertPort(ctx, models.ExposedPort{
			SandboxID: sb.ID,
			Port:      port,
			Protocol:  models.ExposedPortProtocolHTTP,
			HostPort:  32000 + i,
			PublicURL: "https://example.com",
			CreatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertPort: %v", err)
		}
		if err := st.AddCustomDomain(ctx, sb.ID, "app"+sb.ID+".example.com", port); err != nil {
			t.Fatalf("AddCustomDomain: %v", err)
		}
	}

	all, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	byID := map[string]*models.Sandbox{}
	for _, sb := range all {
		byID[sb.ID] = sb
	}
	for _, id := range []string{sbA.ID, sbB.ID} {
		sb, ok := byID[id]
		if !ok {
			t.Fatalf("List missing %s", id)
		}
		if len(sb.ExposedPorts) != 1 {
			t.Fatalf("%s ExposedPorts = %d, want 1", id, len(sb.ExposedPorts))
		}
		if len(sb.CustomDomains) != 1 {
			t.Fatalf("%s CustomDomains = %d, want 1", id, len(sb.CustomDomains))
		}
	}

	got, err := st.Get(ctx, sbA.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.ExposedPorts) != 1 || len(got.CustomDomains) != 1 {
		t.Fatalf("Get attachments = ports %d domains %d", len(got.ExposedPorts), len(got.CustomDomains))
	}
}

func TestPendingImageGCListWithLimit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	for _, img := range []string{"img-a", "img-b", "img-c"} {
		if err := st.SchedulePendingImageGC(ctx, img, now.Add(-time.Hour)); err != nil {
			t.Fatalf("SchedulePendingImageGC %s: %v", img, err)
		}
	}

	due, err := st.ListPendingImageGCDue(ctx, now, 2)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("limited due = %d, want 2", len(due))
	}

	active, err := st.HasActiveImageRef(ctx, "")
	if err != nil || !active {
		t.Fatalf("HasActiveImageRef(\"\") = %v err=%v, want true", active, err)
	}

	sb := sampleSandbox("sb-destroyed")
	sb.Image = "gone-image"
	sb.Status = models.SandboxStatusDestroyed
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create destroyed: %v", err)
	}
	active, err = st.HasActiveImageRef(ctx, "gone-image")
	if err != nil || active {
		t.Fatalf("HasActiveImageRef(destroyed-only) = %v err=%v, want false", active, err)
	}
}

func TestUpsertWasmModuleUpdatesExisting(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID: "mod-up", ModuleRef: "v1.wasm", Status: "pending", CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule insert: %v", err)
	}
	readyAt := now.Add(time.Minute)
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID: "mod-up", ModuleRef: "v2.wasm", Status: "ready", HasWarm: true, ReadyAt: &readyAt,
	}); err != nil {
		t.Fatalf("UpsertWasmModule update: %v", err)
	}
	got, err := st.GetWasmModule(ctx, "mod-up")
	if err != nil {
		t.Fatalf("GetWasmModule: %v", err)
	}
	if got.ModuleRef != "v2.wasm" || got.Status != "ready" || !got.HasWarm {
		t.Fatalf("updated module = %+v", got)
	}
}

func TestReopenExistingStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reopen.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-reopen")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	got, err := st2.Get(ctx, "sb-reopen")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.ID != "sb-reopen" {
		t.Fatalf("Get = %+v", got)
	}
}

func TestTryReserveHostPortCollisionReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	sbA := sampleSandbox("sb-port-a")
	sbB := sampleSandbox("sb-port-b")
	for _, sb := range []*models.Sandbox{sbA, sbB} {
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	r, err := st.TryReserveHostPort(ctx, sbA.ID, 80, 33001, models.ExposedPortProtocolTCP, "tcp://a", now)
	if err != nil || !r.Reserved {
		t.Fatalf("first reserve = %+v err %v", r, err)
	}

	// Different sandbox/port but same host_port — INSERT OR IGNORE no-ops and
	// getPort for sbB:6379 misses, yielding an empty result (not an error).
	r, err = st.TryReserveHostPort(ctx, sbB.ID, 6379, 33001, models.ExposedPortProtocolTCP, "tcp://b", now)
	if err != nil {
		t.Fatalf("collision reserve err = %v", err)
	}
	if r.Reserved || r.Existing != nil {
		t.Fatalf("collision reserve = %+v, want empty result", r)
	}

	if _, err := st.TryReserveHostPort(ctx, sbA.ID, 80, 0, models.ExposedPortProtocolTCP, "", now); err == nil {
		t.Fatal("expected error for non-positive host port")
	}
}

func TestFirecrackerVMMValidationAndListPaths(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "", "/a", "/b", 3, now); err == nil {
		t.Fatal("expected error for empty slot id")
	}
	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "x", "", "/b", 3, now); err == nil {
		t.Fatal("expected error for empty api socket")
	}
	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "x", "/a", "/b", 2, now); err == nil {
		t.Fatal("expected error for reserved vsock cid")
	}
	if err := st.MarkFirecrackerVMMSlotFailed(ctx, "", "boom", now); err == nil {
		t.Fatal("expected error for empty slot id on fail")
	}
	if err := st.DeleteFirecrackerVMMSlot(ctx, ""); err == nil {
		t.Fatal("expected error for empty slot id on delete")
	}
	if _, err := st.GetFirecrackerVMMPoolStats(ctx, ""); err == nil {
		t.Fatal("expected error for empty template id on stats")
	}
	if _, err := st.ListFirecrackerVMMSlotsForRefill(ctx, ""); err == nil {
		t.Fatal("expected error for empty template id on list")
	}
	if _, err := st.AllocateFirecrackerVMMSlot(ctx, "", "sb", now); err == nil {
		t.Fatal("expected error for empty template id on allocate")
	}
	if _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl", "", now); err == nil {
		t.Fatal("expected error for empty sandbox id on allocate")
	}
	if _, err := st.GetFirecrackerVMMSlotBySandbox(ctx, ""); err == nil {
		t.Fatal("expected error for empty sandbox id on get-by-sandbox")
	}
	if _, err := st.GetFirecrackerVMMSlotByID(ctx, ""); err == nil {
		t.Fatal("expected error for empty slot id on get-by-id")
	}
	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "missing", "/a", "/b", 3, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark loaded missing = %v, want ErrNotFound", err)
	}

	if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "vmms-val", TemplateID: "tpl-val"}, now); err != nil {
		t.Fatalf("insert: %v", err)
	}
	longErr := strings.Repeat("x", 1500)
	if err := st.MarkFirecrackerVMMSlotFailed(ctx, "vmms-val", longErr, now); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	got, err := st.GetFirecrackerVMMSlotByID(ctx, "vmms-val")
	if err != nil || got == nil {
		t.Fatalf("get failed slot: %v %+v", err, got)
	}
	if len(got.LastError) != 1024 {
		t.Fatalf("last_error len = %d, want 1024", len(got.LastError))
	}
	if got.ReleasedAt.IsZero() {
		t.Fatal("released_at should be set on failed slot")
	}

	released, err := st.ListReleasedFirecrackerVMMSlots(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ListReleasedFirecrackerVMMSlots: %v", err)
	}
	if len(released) != 1 || released[0].ID != "vmms-val" {
		t.Fatalf("released list = %+v", released)
	}

	if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "vmms-live", TemplateID: "tpl-val"}, now); err != nil {
		t.Fatalf("insert live: %v", err)
	}
	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "vmms-live", "/sock", "/run", 7, now); err != nil {
		t.Fatalf("mark loaded: %v", err)
	}
	slot, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-val", "sb-val", now)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if slot.AllocatedAt.IsZero() {
		t.Fatal("allocated_at should be set")
	}
	byID, err := st.GetFirecrackerVMMSlotByID(ctx, "vmms-live")
	if err != nil || byID == nil || byID.SandboxID != "sb-val" || byID.AllocatedAt.IsZero() {
		t.Fatalf("get by id after allocate = %+v err %v", byID, err)
	}
	refill, err := st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl-val")
	if err != nil {
		t.Fatalf("ListFirecrackerVMMSlotsForRefill: %v", err)
	}
	if len(refill) != 1 || refill[0].Status != FirecrackerVMMSlotStatusAllocated || refill[0].SandboxID != "sb-val" {
		t.Fatalf("refill list = %+v", refill)
	}

	stats, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl-val")
	if err != nil {
		t.Fatalf("GetFirecrackerVMMPoolStats: %v", err)
	}
	if stats.Released < 1 || stats.Allocated < 1 {
		t.Fatalf("stats = %+v, want released and allocated counts", stats)
	}
}

func TestClusterSecretUpsertUpdate(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	rec := ClusterSecretRecord{
		Ref:           "cluster-secret://sandbox/sb-upsert/v1",
		SandboxID:     "sb-upsert",
		Version:       1,
		Recipients:    []string{"node-a"},
		SealedPayload: []byte("v1"),
	}
	if err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("PutClusterSecret insert: %v", err)
	}
	rec.Version = 2
	rec.Recipients = []string{"node-b"}
	rec.SealedPayload = []byte("v2")
	if err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("PutClusterSecret update: %v", err)
	}
	got, err := st.GetClusterSecret(ctx, rec.Ref)
	if err != nil {
		t.Fatalf("GetClusterSecret: %v", err)
	}
	if got.Version != 2 || got.Recipients[0] != "node-b" || string(got.SealedPayload) != "v2" {
		t.Fatalf("updated secret = %+v", got)
	}
}

func TestFirecrackerTapValidation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	if _, err := st.AllocateFirecrackerTapSlot(ctx, "", now); err == nil {
		t.Fatal("expected error for empty sandbox id on tap allocate")
	}
	if err := st.ReleaseFirecrackerTapSlot(ctx, ""); err == nil {
		t.Fatal("expected error for empty sandbox id on tap release")
	}
	if _, err := st.GetFirecrackerTapSlotBySandbox(ctx, ""); err == nil {
		t.Fatal("expected error for empty sandbox id on tap get")
	}
	if err := st.ReleaseFirecrackerVMMSlot(ctx, "", now); err == nil {
		t.Fatal("expected error for empty sandbox id on vmm release")
	}

	stats, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl-none")
	if err != nil {
		t.Fatalf("stats for empty template: %v", err)
	}
	if stats.Total != 0 {
		t.Fatalf("stats = %+v, want zero", stats)
	}
}

func TestPutClusterSecretValidation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{}); err == nil {
		t.Fatal("expected validation error for empty record")
	}
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		SandboxID: "sb", Version: 1, SealedPayload: []byte("x"),
	}); err == nil {
		t.Fatal("expected validation error for empty ref")
	}
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "ref", Version: 1, SealedPayload: []byte("x"),
	}); err == nil {
		t.Fatal("expected validation error for empty sandbox id")
	}
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "ref", SandboxID: "sb", Version: 0, SealedPayload: []byte("x"),
	}); err == nil {
		t.Fatal("expected validation error for non-positive version")
	}
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "ref", SandboxID: "sb", Version: 1,
	}); err == nil {
		t.Fatal("expected validation error for empty sealed payload")
	}
}

func TestGetClusterSecretInvalidRecipientsJSON(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	_, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secrets (ref, sandbox_id, version, recipients_json, sealed_payload, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "ref://bad-json", "sb-bad", 1, "not-json", []byte("sealed"), now, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := st.GetClusterSecret(ctx, "ref://bad-json"); err == nil {
		t.Fatal("expected recipients unmarshal error")
	}
	if _, err := st.GetClusterSecret(ctx, "  "); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty ref = %v, want ErrNotFound", err)
	}
	if err := st.DeleteClusterSecretsForSandbox(ctx, ""); err != nil {
		t.Fatalf("DeleteClusterSecretsForSandbox empty id: %v", err)
	}
}

func TestSandboxFailoverPolicyHelper(t *testing.T) {
	if got := sandboxFailoverPolicy(&models.Sandbox{
		Failover: &models.Failover{Policy: models.FailoverPolicyNone},
	}); got != "" {
		t.Fatalf("none policy = %q, want empty", got)
	}
	if got := sandboxFailoverPolicy(&models.Sandbox{
		Failover: &models.Failover{Policy: "not-valid"},
	}); got != "" {
		t.Fatalf("invalid policy = %q, want empty", got)
	}
}

func TestWasmStoreClosedDBErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.Close()

	_ = st.UpsertWasmModule(ctx, WasmModuleRecord{ID: "m", ModuleRef: "r", Status: "ready"})
	_ = st.UpdateWasmCheckpoint(ctx, "sb", "s", "/p", "g", "")
	_ = st.PutWasmStateKV(ctx, "sb", "k", []byte("v"))
	_, _, _ = st.GetWasmStateKV(ctx, "sb", "k")
	_ = st.DeleteWasmStateKV(ctx, "sb", "k")
	_ = st.DeleteAllWasmStateKV(ctx, "sb")
	_, _ = st.ListWasmStateKVKeys(ctx, "sb")
	_, _ = st.InsertWasmCheckpointPush(ctx, "sb", "ref", "dig")
	_, _ = st.ListWasmCheckpointPushes(ctx, "sb")
	_ = st.DeleteWasmCheckpointPush(ctx, 1)
	_ = st.DeleteAllWasmCheckpointPushes(ctx, "sb")
	_ = st.UpdateWasmRegistryPush(ctx, "sb", "ref", "dig")
	_, _ = st.ListReadyWasmModuleRefs(ctx)
	_, _ = st.ListWasmModulesOlderThan(ctx, time.Now())
	_, _ = st.IsWasmDigestCatalogued(ctx, "dig")
	_, _ = st.GetWasmModule(ctx, "id")
	_, _ = st.ListWasmModules(ctx)
	_ = st.DeleteWasmModule(ctx, "id")
	_, _ = st.IsWasmModuleReferenced(ctx, "id", "ref", "dig")
	_, _ = st.WasmDigestsInUse(ctx, []string{"dig"})
	_, _ = st.ReleaseOrphanedFirecrackerVMMSlots(ctx, time.Now())
	_ = st.MarkFirecrackerVMMSlotLoaded(ctx, "slot", "/a", "/b", 3, time.Now())
	_ = st.MarkFirecrackerVMMSlotFailed(ctx, "slot", "err", time.Now())
}

func TestMiscStoreCoverageGaps(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.SchedulePendingImageGC(ctx, "", time.Now()); err != nil {
		t.Fatalf("SchedulePendingImageGC empty: %v", err)
	}

	sb := sampleSandbox("sb-fleet")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.SetFleetSuspended(ctx, sb.ID, true); err != nil {
		t.Fatalf("SetFleetSuspended: %v", err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil || !got.FleetSuspended {
		t.Fatalf("fleet_suspended = %v err %v", got.FleetSuspended, err)
	}

	if err := st.UpsertCompatState(ctx, "", "e2b", `{}`); err == nil {
		t.Fatal("expected error for empty sandbox id on compat state")
	}
	if err := st.UpsertCompatState(ctx, sb.ID, "", `{}`); err == nil {
		t.Fatal("expected error for empty facade on compat state")
	}
	if err := st.UpsertCompatState(ctx, sb.ID, "e2b", ""); err != nil {
		t.Fatalf("UpsertCompatState empty body: %v", err)
	}
	if err := st.UpsertCompatState(ctx, sb.ID, "e2b", `{"v":1}`); err != nil {
		t.Fatalf("UpsertCompatState update: %v", err)
	}
	state, err := st.GetCompatState(ctx, sb.ID, "e2b")
	if err != nil || state.StateJSON != `{"v":1}` {
		t.Fatalf("compat state = %+v err %v", state, err)
	}

	if err := st.AddCustomDomain(ctx, sb.ID, "app.example.com", 8080); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	if err := st.AddCustomDomain(ctx, sb.ID, "app.example.com", 9090); !errors.Is(err, ErrCustomDomainPortMismatch) {
		t.Fatalf("port mismatch = %v, want ErrCustomDomainPortMismatch", err)
	}

	if err := st.CompleteIdempotentRequest(ctx, "missing-scope", "missing-fp", "id", time.Now(), time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CompleteIdempotentRequest missing = %v, want ErrNotFound", err)
	}
	if err := st.DeleteIdempotentRequest(ctx, "missing-scope", "missing-fp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteIdempotentRequest missing = %v, want ErrNotFound", err)
	}
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{}); err == nil {
		t.Fatal("expected error for empty snapshot alias")
	}
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "only-alias"}); err == nil {
		t.Fatal("expected error for missing snapshot name on alias")
	}

	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Fatalf("Close on nil store = %v, want nil", err)
	}

	verified := time.Now().UTC()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:            "snap-verified",
		Image:           "img:verified",
		SourceSandboxID: sb.ID,
		CreatedAt:       time.Now().UTC(),
		Entrypoint:      []string{"/bin/sh"},
		ImageVerifiedAt: &verified,
	}); err != nil {
		t.Fatalf("CreateSnapshot with verified at: %v", err)
	}
	dup := &models.SandboxSnapshot{
		Name:            "snap-dup",
		Image:           "img:dup",
		SourceSandboxID: sb.ID,
		CreatedAt:       time.Now().UTC(),
	}
	if err := st.CreateSnapshot(ctx, dup); err != nil {
		t.Fatalf("CreateSnapshot first: %v", err)
	}
	if err := st.CreateSnapshot(ctx, dup); !errors.Is(err, ErrSnapshotNameConflict) {
		t.Fatalf("duplicate snapshot = %v, want ErrSnapshotNameConflict", err)
	}
}
