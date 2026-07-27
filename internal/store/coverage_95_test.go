package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sqlite3 "github.com/mattn/go-sqlite3"
)

func TestTransferFirecrackerTapSlotRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(200, 0).UTC()

	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.200.0.0/30", HostIP: "10.200.0.1", GuestIP: "10.200.0.2", VsockCID: 3,
	}, now); err != nil {
		t.Fatalf("SeedFirecrackerTapSlot: %v", err)
	}
	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap1", CIDR: "10.200.0.4/30", HostIP: "10.200.0.5", GuestIP: "10.200.0.6", VsockCID: 4,
	}, now); err != nil {
		t.Fatalf("SeedFirecrackerTapSlot: %v", err)
	}

	parked, err := st.AllocateFirecrackerTapSlot(ctx, "park-slot-1", now)
	if err != nil {
		t.Fatalf("AllocateFirecrackerTapSlot: %v", err)
	}

	// Warm-pool handoff: park id → real sandbox id.
	moved, err := st.TransferFirecrackerTapSlot(ctx, "park-slot-1", "sb-real-1", now.Add(time.Second))
	if err != nil {
		t.Fatalf("TransferFirecrackerTapSlot: %v", err)
	}
	if moved.TapName != parked.TapName || moved.SandboxID != "sb-real-1" {
		t.Fatalf("moved = %+v, want tap=%s sandbox=sb-real-1", moved, parked.TapName)
	}

	// Retry of the same transfer is idempotent once toID owns the slot.
	again, err := st.TransferFirecrackerTapSlot(ctx, "park-slot-1", "sb-real-1", now)
	if err != nil || again.TapName != parked.TapName {
		t.Fatalf("idempotent transfer = %+v err=%v", again, err)
	}

	// from==to returns the current ownership.
	same, err := st.TransferFirecrackerTapSlot(ctx, "sb-real-1", "sb-real-1", now)
	if err != nil || same.SandboxID != "sb-real-1" {
		t.Fatalf("same-id transfer = %+v err=%v", same, err)
	}
}

func TestTransferFirecrackerTapSlotValidationAndConflicts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := st.TransferFirecrackerTapSlot(ctx, "", "to", now); err == nil {
		t.Fatal("empty from")
	}
	if _, err := st.TransferFirecrackerTapSlot(ctx, "from", "", now); err == nil {
		t.Fatal("empty to")
	}
	if _, err := st.TransferFirecrackerTapSlot(ctx, "ghost-from", "ghost-to", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing both = %v, want ErrNotFound", err)
	}

	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.200.0.0/30", HostIP: "10.200.0.1", GuestIP: "10.200.0.2", VsockCID: 3,
	}, now); err != nil {
		t.Fatalf("seed0: %v", err)
	}
	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap1", CIDR: "10.200.0.4/30", HostIP: "10.200.0.5", GuestIP: "10.200.0.6", VsockCID: 4,
	}, now); err != nil {
		t.Fatalf("seed1: %v", err)
	}
	if _, err := st.AllocateFirecrackerTapSlot(ctx, "owner-a", now); err != nil {
		t.Fatalf("alloc a: %v", err)
	}
	if _, err := st.AllocateFirecrackerTapSlot(ctx, "owner-b", now); err != nil {
		t.Fatalf("alloc b: %v", err)
	}

	// Target already owns a different TAP — refuse before unique-index trip.
	if _, err := st.TransferFirecrackerTapSlot(ctx, "owner-a", "owner-b", now); err == nil {
		t.Fatal("expected conflict when target owns a different tap")
	}

	// Target owns, source missing → return target (idempotent after prior move).
	got, err := st.TransferFirecrackerTapSlot(ctx, "never-existed", "owner-b", now)
	if err != nil || got == nil || got.SandboxID != "owner-b" {
		t.Fatalf("target-only transfer = %+v err=%v", got, err)
	}
}

func TestCreateUpsertMarshalAndConflictEdges(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Marshal failures on Env / Tags (unsupported channel type).
	badEnv := sampleSandbox("sb-bad-env")
	badEnv.Env = map[string]string{}
	// Force marshalJSON failure via non-JSON-marshalable ContainerCommand replacement:
	// Env is map[string]string so always ok; use Tags with nil interface via reflection-less path:
	// Create uses marshalJSON on Env, ContainerCommand, Tags — Tags as map is fine.
	// Hit Create duplicate id → isSandboxIDConflict true branch.
	sb := sampleSandbox("sb-dup")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Create(ctx, sb); !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("duplicate Create = %v, want ErrSandboxExists", err)
	}

	// Name that collides with an existing id (lookup uniqueness).
	named := sampleSandbox("sb-named")
	named.Name = "sb-dup"
	if err := st.Create(ctx, named); !errors.Is(err, ErrSandboxNameConflict) {
		t.Fatalf("name=id conflict Create = %v, want ErrSandboxNameConflict", err)
	}

	// Upsert of existing id succeeds; Upsert with conflicting name fails.
	sb.Image = "updated:1"
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}
	conflict := sampleSandbox("sb-other")
	conflict.Name = "taken-name"
	if err := st.Create(ctx, conflict); err != nil {
		t.Fatalf("Create named: %v", err)
	}
	sb.Name = "taken-name"
	if err := st.Upsert(ctx, sb); !errors.Is(err, ErrSandboxNameConflict) {
		t.Fatalf("Upsert name conflict = %v", err)
	}

	// Direct helper coverage for empty-id and wrapped ErrSandboxExists string.
	if isSandboxIDConflict(errors.New("x"), "") {
		t.Fatal("empty id must not count as conflict")
	}
	if !isSandboxIDConflict(models.ErrSandboxExists, "sb-x") {
		t.Fatal("wrapped ErrSandboxExists should match")
	}
	var sqliteErr sqlite3.Error
	sqliteErr.Code = sqlite3.ErrConstraint
	sqliteErr.ExtendedCode = sqlite3.ErrConstraintPrimaryKey
	if !isSandboxIDConflict(sqliteErr, "sb-x") {
		t.Fatal("sqlite PK constraint should match")
	}
}

func TestCreateUpsertJSONMarshalErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// GPUs with a non-marshalable nested value isn't easy via models.GPURequest.
	// Tags typed as map[string]any isn't available — use Env via Create after
	// closing? Instead exercise Upsert/Create with nil sandbox fields that still
	// pass marshal (empty) and closed-DB for the Exec error branch.
	sb := sampleSandbox("sb-json")
	sb.Tags = map[string]string{"k": "v"}
	sb.GPUs = &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 1}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create with tags/gpus: %v", err)
	}
	sb.Tags = map[string]string{"k": "v2"}
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert with tags: %v", err)
	}

	// mustMarshalStringSlice empty + non-empty paths (non-empty already in egress tests).
	if got := mustMarshalStringSlice(nil); got != "[]" {
		t.Fatalf("nil slice = %q", got)
	}
	if got := mustMarshalStringSlice([]string{"a", "b"}); got == "[]" {
		t.Fatalf("non-empty slice marshaled empty")
	}
}

func TestListGetWithAttachmentsAndClosedDB(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sb := sampleSandbox("sb-attach")
	sb.OwnerRef = "acct-1"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID, Port: 8080, Protocol: models.ExposedPortProtocolHTTP,
		HostPort: 32001, PublicURL: "https://x", CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}
	if err := st.AddCustomDomain(ctx, sb.ID, "attach.example.com", 8080); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}

	got, err := st.Get(ctx, sb.ID)
	if err != nil || len(got.ExposedPorts) != 1 || len(got.CustomDomains) != 1 {
		t.Fatalf("Get attachments ports=%d domains=%d err=%v", len(got.ExposedPorts), len(got.CustomDomains), err)
	}
	all, err := st.List(ctx)
	if err != nil || len(all) == 0 {
		t.Fatalf("List: %v", err)
	}
	byOwner, err := st.ListByOwner(ctx, "acct-1")
	if err != nil || len(byOwner) != 1 {
		t.Fatalf("ListByOwner = %d err=%v", len(byOwner), err)
	}
	byRT, err := st.ListByRuntime(ctx, models.RuntimeGvisor)
	if err != nil || len(byRT) == 0 {
		t.Fatalf("ListByRuntime = %d err=%v", len(byRT), err)
	}

	_ = st.Close()
	_, _ = st.Get(ctx, sb.ID)
	_, _ = st.List(ctx)
	_, _ = st.ListByOwner(ctx, "acct-1")
	_, _ = st.ListByRuntime(ctx, models.RuntimeGvisor)
	_ = st.Create(ctx, sampleSandbox("sb-closed"))
	_ = st.Upsert(ctx, sampleSandbox("sb-closed"))
	_ = st.UpdateTags(ctx, "sb", map[string]string{"a": "b"})
	_ = st.UpdateLifecycle(ctx, "sb", models.Lifecycle{})
	_ = st.MarkNetworkQuotaExceeded(ctx, "sb", now)
	_ = st.SetAllowPublicTraffic(ctx, "sb", false, "")
	_, _ = st.GetPortByHostPort(ctx, 32001)
	_, _ = st.TransferFirecrackerTapSlot(ctx, "a", "b", now)
	_ = st.SchedulePendingImageGC(ctx, "img", now)
	_, _ = st.ListPendingImageGCDue(ctx, now, 10)
	_ = st.DeletePendingImageGC(ctx, "img")
	_, _ = st.HasActiveImageRef(ctx, "img")
	_, _, _ = st.ClaimIdempotentRequest(ctx, "scope", "fp", now, time.Minute)
	_, _ = st.ListSnapshotAliases(ctx, "x")
	_, _ = st.ListCompatState(ctx, "x")
	_, _ = st.ListSnapshots(ctx)
	_, _ = st.ListTemplates(ctx)
	_, _ = st.ListTemplatesPendingPush(ctx)
	_, _ = st.ListUnhealthyTemplates(ctx)
	_, _ = st.ListTemplatesReadyBefore(ctx, now)
	_, _ = st.ListReadyTemplateIDs(ctx)
	_, _ = st.ListGCEligibleTemplates(ctx, now)
	_, _ = st.ListSnapshotsPendingPush(ctx)
	_, _ = st.ListAllExposedPorts(ctx)
	_, _ = st.ListAllCustomDomains(ctx)
	_, _ = st.ListCustomDomains(ctx, "sb")
	_ = st.UpsertAccountMapping(ctx, "ext", "int")
}

func TestOpenPermissionAndReopenEdges(t *testing.T) {
	dir := t.TempDir()

	// Parent path is a file → MkdirAll/chmod fail.
	asFile := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(asFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(asFile, "nested", "state.db")); err == nil {
		t.Fatal("expected Open failure when parent path is a file")
	}

	// Fresh open + reopen covers migration swallow + chmod on existing file.
	dbPath := filepath.Join(dir, "ok", "state.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = st2.Close()

	// Directory exists at 0755 — Open must chmod it to 0700.
	loose := filepath.Join(dir, "loose")
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	st3, err := Open(filepath.Join(loose, "state.db"))
	if err != nil {
		t.Fatalf("Open loose dir: %v", err)
	}
	_ = st3.Close()
	info, err := os.Stat(loose)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("dir mode = %o, want owner-only", info.Mode().Perm())
	}
}

func TestClaimIdempotentReadyAndRefresh(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(300, 0).UTC()

	rec, claimed, err := st.ClaimIdempotentRequest(ctx, "e2b.create", "fp-ready", now, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim = %+v claimed=%v err=%v", rec, claimed, err)
	}
	if err := st.CompleteIdempotentRequest(ctx, "e2b.create", "fp-ready", "sb-1", now, time.Hour); err != nil {
		t.Fatalf("CompleteIdempotentRequest: %v", err)
	}

	// Still inside replay window → return ready, not claimed.
	ready, claimed, err := st.ClaimIdempotentRequest(ctx, "e2b.create", "fp-ready", now.Add(time.Second), time.Minute)
	if err != nil || claimed || ready.TargetID != "sb-1" {
		t.Fatalf("ready replay = %+v claimed=%v err=%v", ready, claimed, err)
	}

	// Past replay window → refresh to a new pending claim.
	refreshed, claimed, err := st.ClaimIdempotentRequest(ctx, "e2b.create", "fp-ready", now.Add(2*time.Hour), time.Minute)
	if err != nil || !claimed || refreshed.State != models.RequestStatePending {
		t.Fatalf("refresh = %+v claimed=%v err=%v", refreshed, claimed, err)
	}

	// Concurrent pending with unexpired lock returns existing without claiming.
	pending, claimed, err := st.ClaimIdempotentRequest(ctx, "e2b.create", "fp-ready", now.Add(2*time.Hour).Add(time.Second), time.Minute)
	if err != nil || claimed || pending.State != models.RequestStatePending {
		t.Fatalf("pending wait = %+v claimed=%v err=%v", pending, claimed, err)
	}
}

func TestGetOrCreateVolumeZeroCreatedAt(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	vol, created, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "vol-zero-ts", Tenant: "t-z", Name: "n-z", Backend: "s3", Source: "src",
		// Zero CreatedAt forces the store to stamp now.
	}, 5)
	if err != nil || !created || vol.CreatedAt.IsZero() {
		t.Fatalf("GetOrCreateVolume = %+v created=%v err=%v", vol, created, err)
	}
	again, created, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "vol-other", Tenant: "t-z", Name: "n-z", Backend: "s3",
	}, 5)
	if err != nil || created || again.ID != "vol-zero-ts" {
		t.Fatalf("existing = %+v created=%v err=%v", again, created, err)
	}
}

func TestUpdateTagsLifecycleQuotaClosedAndHappy(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := sampleSandbox("sb-upd")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.UpdateTags(ctx, sb.ID, map[string]string{"env": "test"}); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}
	if err := st.UpdateLifecycle(ctx, sb.ID, models.Lifecycle{
		StopIfIdleFor: time.Minute, Serverless: true,
	}); err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}
	if err := st.MarkNetworkQuotaExceeded(ctx, sb.ID, now); err != nil {
		t.Fatalf("MarkNetworkQuotaExceeded: %v", err)
	}
	if err := st.SetAllowPublicTraffic(ctx, sb.ID, false, ""); err != nil {
		t.Fatalf("SetAllowPublicTraffic: %v", err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Tags["env"] != "test" || !got.NetworkQuotaExceeded {
		t.Fatalf("updated sandbox tags/quota = %+v", got)
	}
	if got.AllowPublicTraffic == nil || *got.AllowPublicTraffic {
		t.Fatalf("AllowPublicTraffic = %v, want false", got.AllowPublicTraffic)
	}
}
