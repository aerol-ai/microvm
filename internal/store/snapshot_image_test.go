package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// GetSnapshotsByImage finds every snapshot holding an image, under any of
// the spellings asked for, in name order.
func TestGetSnapshotsByImage(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, snap := range []*models.SandboxSnapshot{
		{Name: "b-alias", Image: "aerolvm-snapshot/abc:latest", OwnerRef: "acme", CreatedAt: now},
		{Name: "a-commit", Image: "aerolvm-snapshot/abc:latest", SourceSandboxID: "sb-1", OwnerRef: "acme", CreatedAt: now},
		{Name: "other", Image: "aerolvm-snapshot/def:latest", SourceSandboxID: "sb-2", CreatedAt: now},
	} {
		if err := st.CreateSnapshot(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.GetSnapshotsByImage(ctx, []string{"docker.io/aerolvm-snapshot/abc:latest", "aerolvm-snapshot/abc:latest"})
	if err != nil || len(got) != 2 || got[0].Name != "a-commit" || got[1].Name != "b-alias" {
		t.Fatalf("by image = %v, %v; want a-commit, b-alias", names(got), err)
	}
	if got, err := st.GetSnapshotsByImage(ctx, []string{"python:3.12"}); err != nil || len(got) != 0 {
		t.Fatalf("unheld image = %v, %v", names(got), err)
	}
	if got, err := st.GetSnapshotsByImage(ctx, nil); err != nil || got != nil {
		t.Fatalf("no images = %v, %v", got, err)
	}
	if _, err := st.db.Exec(`INSERT INTO sandbox_snapshots(name, image, source_sandbox_id, created_at, memory_mb) VALUES ('unreadable', 'aerolvm-snapshot/def:latest', 'sb-3', CURRENT_TIMESTAMP, 'lots')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSnapshotsByImage(ctx, []string{"aerolvm-snapshot/def:latest"}); err == nil {
		t.Fatal("a row the store cannot read was skipped instead of failing the lookup")
	}
	_ = st.Close()
	if _, err := st.GetSnapshotsByImage(ctx, []string{"x"}); err == nil {
		t.Fatal("a closed store answered")
	}
}

// An image a snapshot holds is in use even with no sandbox running it: the
// image janitors must not take it out from under the snapshot.
func TestHasActiveImageRefCountsSnapshots(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "s", Image: "aerolvm-snapshot/abc:latest", SourceSandboxID: "sb-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for image, want := range map[string]bool{"aerolvm-snapshot/abc:latest": true, "aerolvm-build/x:latest": false} {
		if got, err := st.HasActiveImageRef(ctx, image); err != nil || got != want {
			t.Errorf("HasActiveImageRef(%q) = %v, %v; want %v", image, got, err, want)
		}
	}
}

// Both lookups by image run on every create or GC pass that needs them, so
// they seek an index rather than scanning.
func TestImageLookupsSeekTheirIndex(t *testing.T) {
	st := newTestStore(t)
	plan := queryPlan(t, st, snapshotsByImageSQL(2), []any{"a", "b", maxSnapshotsByImage})
	if !strings.Contains(plan, "idx_sandbox_snapshots_image") || strings.Contains(plan, "SCAN sandbox_snapshots") {
		t.Errorf("by-image plan %q, want a seek of idx_sandbox_snapshots_image", plan)
	}
	plan = queryPlan(t, st, hasActiveImageRefSQL, []any{"a", "destroyed", "a"})
	for _, index := range []string{"idx_sandboxes_image", "idx_sandbox_snapshots_image"} {
		if !strings.Contains(plan, index) {
			t.Errorf("active-ref plan %q, want a seek of %s", plan, index)
		}
	}
}

func names(snapshots []*models.SandboxSnapshot) []string {
	out := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		out = append(out, snapshot.Name)
	}
	return out
}
