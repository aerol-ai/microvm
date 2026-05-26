package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestTemplates_CRUD walks the full Create→Get→List→UpdateStatus→Delete
// path on a single template row, plus PK-collision detection. Mirrors
// the snapshot store coverage — the template janitor relies on every
// one of these working, so a regression here cascades into stuck
// PENDING rows and orphan rootfs.ext4 files on disk.
func TestTemplates_CRUD(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Now().UTC().Round(time.Second)
	tpl := &models.Template{
		ID:         "tpl-aaaaaaaa",
		Image:      "docker://alpine:3.19",
		Status:     models.TemplateStatusPending,
		MinSizeMiB: 256,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate() error = %v", err)
	}

	// Re-insert with the same id must surface ErrTemplateIDConflict so the
	// API can map it to a 409 rather than a generic 500.
	if err := st.CreateTemplate(ctx, tpl); !errors.Is(err, ErrTemplateIDConflict) {
		t.Fatalf("duplicate CreateTemplate() error = %v, want ErrTemplateIDConflict", err)
	}

	got, err := st.GetTemplate(ctx, tpl.ID)
	if err != nil {
		t.Fatalf("GetTemplate() error = %v", err)
	}
	if got.ID != tpl.ID || got.Image != tpl.Image || got.Status != models.TemplateStatusPending {
		t.Fatalf("GetTemplate() = %+v, want id=%s image=%s status=pending", got, tpl.ID, tpl.Image)
	}
	if got.MinSizeMiB != 256 {
		t.Fatalf("GetTemplate().MinSizeMiB = %d, want 256", got.MinSizeMiB)
	}

	list, err := st.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("ListTemplates() error = %v", err)
	}
	if len(list) != 1 || list[0].ID != tpl.ID {
		t.Fatalf("ListTemplates() = %+v, want exactly tpl-aaaaaaaa", list)
	}

	if err := st.UpdateTemplateStatus(ctx, tpl.ID, models.TemplateStatusReady, "/var/lib/aerolvm/templates/tpl-aaaaaaaa/rootfs.ext4", "", 1<<28); err != nil {
		t.Fatalf("UpdateTemplateStatus() error = %v", err)
	}
	after, err := st.GetTemplate(ctx, tpl.ID)
	if err != nil {
		t.Fatalf("GetTemplate() after update error = %v", err)
	}
	if after.Status != models.TemplateStatusReady {
		t.Fatalf("after update status = %s, want ready", after.Status)
	}
	if after.RootfsSizeBytes != 1<<28 {
		t.Fatalf("after update size = %d, want %d", after.RootfsSizeBytes, 1<<28)
	}
	if after.ReadyAt == nil {
		t.Fatalf("after update ReadyAt = nil, want non-nil")
	}

	if err := st.DeleteTemplate(ctx, tpl.ID); err != nil {
		t.Fatalf("DeleteTemplate() error = %v", err)
	}
	if _, err := st.GetTemplate(ctx, tpl.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetTemplate() after delete error = %v, want ErrNotFound", err)
	}
	if err := st.DeleteTemplate(ctx, tpl.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteTemplate() repeat error = %v, want ErrNotFound", err)
	}
}

// TestTemplates_IsReferenced confirms the DELETE-time guard: a sandbox
// row pointing at a template must block the template's removal so a
// live Firecracker guest doesn't lose its rootfs mid-flight. The
// scanSandbox + Create path must round-trip TemplateID for this to
// work — that contract is what this test pins.
func TestTemplates_IsReferenced(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tpl := &models.Template{
		ID: "tpl-ref-1", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	// No sandbox yet → not referenced.
	ref, err := st.IsTemplateReferenced(ctx, tpl.ID)
	if err != nil {
		t.Fatalf("IsTemplateReferenced (no sb) error = %v", err)
	}
	if ref {
		t.Fatalf("IsTemplateReferenced before sandbox = true, want false")
	}

	sb := sampleSandbox("sb-tpl-1")
	sb.Runtime = models.RuntimeFirecracker
	sb.TemplateID = tpl.ID
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	ref, err = st.IsTemplateReferenced(ctx, tpl.ID)
	if err != nil {
		t.Fatalf("IsTemplateReferenced (with sb) error = %v", err)
	}
	if !ref {
		t.Fatalf("IsTemplateReferenced after sandbox = false, want true")
	}

	// Round-trip the sandbox row so the TemplateID column survives the
	// SELECT path too — without this we'd be testing INSERT only.
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get sandbox: %v", err)
	}
	if got.TemplateID != tpl.ID {
		t.Fatalf("Get sandbox TemplateID = %q, want %q", got.TemplateID, tpl.ID)
	}

	// Another template id with no sandbox stays unreferenced — confirms
	// the filter is scoped by id, not a "any sandbox at all" check.
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-ref-2", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateTemplate tpl-ref-2: %v", err)
	}
	ref2, err := st.IsTemplateReferenced(ctx, "tpl-ref-2")
	if err != nil {
		t.Fatalf("IsTemplateReferenced tpl-ref-2 error = %v", err)
	}
	if ref2 {
		t.Fatalf("IsTemplateReferenced tpl-ref-2 = true, want false")
	}
}

// TestTemplates_GCQuery exercises the janitor's "what's eligible"
// query. Pending rows never qualify (build is in flight), referenced
// rows never qualify (live sandbox owns the file), and only rows older
// than the cutoff land in the result. The double-check inside
// runTemplateGC depends on this filter being tight — if it loosens, the
// GC can race CreateSandbox(template_id=t.id) and free the rootfs out
// from under the guest.
func TestTemplates_GCQuery(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Now().UTC().Truncate(time.Second)

	mustInsert := func(id string, status models.TemplateStatus, updatedAt time.Time) {
		t.Helper()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: id, Image: "docker://alpine:3.19",
			Status: status, CreatedAt: updatedAt, UpdatedAt: updatedAt,
		}); err != nil {
			t.Fatalf("CreateTemplate %s: %v", id, err)
		}
		// CreateTemplate honors the caller-supplied updated_at directly, so
		// no extra UPDATE needed.
	}

	// Stale ready row — should qualify.
	mustInsert("tpl-stale", models.TemplateStatusReady, now.Add(-48*time.Hour))
	// Stale pending row — should NOT qualify (build goroutine may still
	// be writing).
	mustInsert("tpl-pending", models.TemplateStatusPending, now.Add(-48*time.Hour))
	// Fresh ready row — should NOT qualify (under cutoff).
	mustInsert("tpl-fresh", models.TemplateStatusReady, now.Add(-1*time.Hour))
	// Stale ready row WITH a sandbox referencing it — should NOT qualify.
	mustInsert("tpl-busy", models.TemplateStatusReady, now.Add(-48*time.Hour))
	sb := sampleSandbox("sb-busy")
	sb.Runtime = models.RuntimeFirecracker
	sb.TemplateID = "tpl-busy"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create busy sandbox: %v", err)
	}

	cutoff := now.Add(-24 * time.Hour)
	rows, err := st.ListGCEligibleTemplates(ctx, cutoff)
	if err != nil {
		t.Fatalf("ListGCEligibleTemplates() error = %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "tpl-stale" {
		ids := make([]string, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		t.Fatalf("ListGCEligibleTemplates() = %v, want exactly [tpl-stale]", ids)
	}
}

// TestTemplates_GCQuery_ExcludesBuildingRootfs pins the Phase 3 widening
// of the gc-eligible filter: building_rootfs and snapshotting must be
// treated like pending — the build goroutine still owns the dir, and
// the janitor must not race it.
func TestTemplates_GCQuery_ExcludesBuildingRootfs(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	mustInsert := func(id string, status models.TemplateStatus) {
		t.Helper()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: id, Image: "x", Status: status,
			CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour),
		}); err != nil {
			t.Fatalf("CreateTemplate %s: %v", id, err)
		}
	}
	mustInsert("tpl-rootfs", models.TemplateStatusBuildingRootfs)
	mustInsert("tpl-snap", models.TemplateStatusSnapshotting)
	mustInsert("tpl-ready", models.TemplateStatusReady)
	mustInsert("tpl-rno", models.TemplateStatusReadyNoSnapshot)

	rows, err := st.ListGCEligibleTemplates(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("ListGCEligibleTemplates: %v", err)
	}
	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.ID] = true
	}
	if ids["tpl-rootfs"] || ids["tpl-snap"] {
		t.Errorf("intermediate-state templates leaked into GC list: %v", ids)
	}
	if !ids["tpl-ready"] || !ids["tpl-rno"] {
		t.Errorf("terminal-state templates missing from GC list: %v", ids)
	}
}

// TestUpdateTemplateSnapshotReady pins the round-trip on every
// snapshot column the Phase 3 store schema introduced. A read after
// write must see exactly what we wrote — a regression here cascades
// into the driver picking up stale paths or zero checksums and
// silently cold-booting instead of snapshot-loading.
func TestUpdateTemplateSnapshotReady(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Now().UTC().Round(time.Second)
	tpl := &models.Template{
		ID: "tpl-snap-ok", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusSnapshotting, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	if err := st.UpdateTemplateSnapshotReady(ctx, tpl.ID,
		"/var/lib/aerolvm/templates/tpl-snap-ok/snapshot.memory",
		"/var/lib/aerolvm/templates/tpl-snap-ok/snapshot.state",
		1<<24, "sha256:deadbeef|sha256:cafef00d", 42, true,
	); err != nil {
		t.Fatalf("UpdateTemplateSnapshotReady: %v", err)
	}

	got, err := st.GetTemplate(ctx, tpl.ID)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if !got.HasSnapshot {
		t.Errorf("HasSnapshot = false, want true")
	}
	if !got.HasOverlay {
		t.Errorf("HasOverlay = false, want true")
	}
	if got.SnapshotMemoryPath != "/var/lib/aerolvm/templates/tpl-snap-ok/snapshot.memory" {
		t.Errorf("SnapshotMemoryPath = %q", got.SnapshotMemoryPath)
	}
	if got.SnapshotStatePath != "/var/lib/aerolvm/templates/tpl-snap-ok/snapshot.state" {
		t.Errorf("SnapshotStatePath = %q", got.SnapshotStatePath)
	}
	if got.SnapshotSizeBytes != 1<<24 {
		t.Errorf("SnapshotSizeBytes = %d, want %d", got.SnapshotSizeBytes, 1<<24)
	}
	if got.SnapshotChecksum != "sha256:deadbeef|sha256:cafef00d" {
		t.Errorf("SnapshotChecksum = %q", got.SnapshotChecksum)
	}
	if got.SnapshotVsockCID != 42 {
		t.Errorf("SnapshotVsockCID = %d, want 42", got.SnapshotVsockCID)
	}
	// snapshot_error must be cleared on a successful capture — a stale
	// error string from a prior failed attempt would confuse operators
	// inspecting the row.
	if got.SnapshotError != "" {
		t.Errorf("SnapshotError = %q, want empty after success", got.SnapshotError)
	}
}

// TestUpdateTemplateSnapshotFailed pins the negative path: the
// snapshot_error column is populated, snapshot fields stay zero/empty,
// has_snapshot stays false. The terminal status (ready_no_snapshot)
// is set by a separate UpdateTemplateStatus call — this test focuses
// only on what the failure helper itself writes.
func TestUpdateTemplateSnapshotFailed(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Now().UTC().Round(time.Second)
	tpl := &models.Template{
		ID: "tpl-snap-bad", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusSnapshotting, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	if err := st.UpdateTemplateSnapshotFailed(ctx, tpl.ID, "vmm boot timed out"); err != nil {
		t.Fatalf("UpdateTemplateSnapshotFailed: %v", err)
	}

	got, err := st.GetTemplate(ctx, tpl.ID)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got.SnapshotError != "vmm boot timed out" {
		t.Errorf("SnapshotError = %q, want %q", got.SnapshotError, "vmm boot timed out")
	}
	if got.HasSnapshot {
		t.Errorf("HasSnapshot = true, want false on failure")
	}
	if got.SnapshotMemoryPath != "" || got.SnapshotStatePath != "" {
		t.Errorf("snapshot paths populated on failure: mem=%q state=%q", got.SnapshotMemoryPath, got.SnapshotStatePath)
	}
}
