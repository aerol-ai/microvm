package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestPendingImageGCRekeyMigration pins the warm-upgrade path for the
// engine-aware image ledger. SQLite cannot widen a primary key in place, so an
// existing database keeps the old single-column table until Open rebuilds it.
// Rows must survive that rebuild (they are scheduled cleanups; losing them
// leaks disk), and the rebuilt table must accept the same image under two
// engines, which the old key could not represent at all.
func TestPendingImageGCRekeyMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build a database with the pre-migration ledger shape.
	raw, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE pending_image_gc (
		image TEXT PRIMARY KEY,
		scheduled_at DATETIME NOT NULL
	);`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	scheduled := time.Now().UTC().Add(-time.Hour).Round(time.Second)
	if _, err := raw.ExecContext(ctx, `INSERT INTO pending_image_gc (image, scheduled_at) VALUES (?, ?)`,
		"legacy:latest", scheduled); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	entries, err := st.ListPendingImageGCDue(ctx, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue: %v", err)
	}
	if len(entries) != 1 || entries[0].Image != "legacy:latest" {
		t.Fatalf("rows after rekey = %+v, want the legacy row preserved", entries)
	}
	// Pre-migration rows carry no engine: they mean "this host's engine",
	// which is what they always implicitly meant.
	if entries[0].Engine != "" {
		t.Fatalf("legacy row engine = %q, want empty", entries[0].Engine)
	}

	// The widened key admits the same image under two engines.
	now := time.Now().UTC()
	if err := st.SchedulePendingImageGC(ctx, "docker", "shared:latest", now); err != nil {
		t.Fatalf("schedule docker row: %v", err)
	}
	if err := st.SchedulePendingImageGC(ctx, "containerd", "shared:latest", now); err != nil {
		t.Fatalf("schedule containerd row: %v", err)
	}
	entries, err = st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue after schedule: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("rows = %d, want 3 (legacy + one per engine)", len(entries))
	}

	// Deleting one engine's row leaves the other engine's cleanup pending.
	if err := st.DeletePendingImageGC(ctx, "docker", "shared:latest"); err != nil {
		t.Fatalf("DeletePendingImageGC: %v", err)
	}
	entries, err = st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue after delete: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("rows after per-engine delete = %d, want 2", len(entries))
	}

	// Re-opening is a no-op: the key is already widened.
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	entries, err = reopened.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue after reopen: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("rows after reopen = %d, want 2", len(entries))
	}
}
