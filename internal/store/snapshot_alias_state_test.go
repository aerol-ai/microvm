package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestSnapshotAliasStateJSONRoundTrip pins snapshot_aliases.state_json: the
// facade-private blob is stored verbatim, replaced on upsert, and absent
// (empty) for facades that never set it.
func TestSnapshotAliasStateJSONRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, sampleSandbox("sb-state")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, name := range []string{"snap-state-a", "snap-state-b"} {
		if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: name, SourceSandboxID: "sb-state", Image: name}); err != nil {
			t.Fatalf("CreateSnapshot: %v", err)
		}
	}
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "snp-a", SnapshotName: "snap-state-a", Facade: models.FacadeRunloop, StateJSON: `{"name":"first"}`}); err != nil {
		t.Fatalf("UpsertSnapshotAlias: %v", err)
	}
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "e2b-b", SnapshotName: "snap-state-b", Facade: models.FacadeE2B}); err != nil {
		t.Fatalf("UpsertSnapshotAlias e2b: %v", err)
	}

	got, err := st.GetSnapshotAlias(ctx, "snp-a")
	if err != nil || got.StateJSON != `{"name":"first"}` {
		t.Fatalf("GetSnapshotAlias = %+v, %v", got, err)
	}
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "snp-a", SnapshotName: "snap-state-a", Facade: models.FacadeRunloop, StateJSON: `{"name":"second"}`}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	listed, err := st.ListSnapshotAliases(ctx, models.FacadeRunloop)
	if err != nil || listed["snp-a"].StateJSON != `{"name":"second"}` || len(listed) != 1 {
		t.Fatalf("ListSnapshotAliases = %+v, %v", listed, err)
	}
	other, err := st.GetSnapshotAlias(ctx, "e2b-b")
	if err != nil || other.StateJSON != "" {
		t.Fatalf("e2b alias state = %q, %v", other.StateJSON, err)
	}
}

// TestSnapshotAliasStateJSONWarmUpgrade opens a database whose
// snapshot_aliases table predates state_json: Open must add the column
// and existing rows must read back with an empty state.
func TestSnapshotAliasStateJSONWarmUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `CREATE TABLE snapshot_aliases (
		alias TEXT PRIMARY KEY,
		snapshot_name TEXT NOT NULL,
		facade TEXT NOT NULL,
		extra_names_json TEXT NOT NULL DEFAULT '[]',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.ExecContext(ctx, `INSERT INTO snapshot_aliases (alias, snapshot_name, facade, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy", "snap-legacy", models.FacadeE2B, now, now); err != nil {
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
	got, err := st.GetSnapshotAlias(ctx, "legacy")
	if err != nil {
		t.Fatalf("GetSnapshotAlias after upgrade: %v", err)
	}
	if got.StateJSON != "" || got.SnapshotName != "snap-legacy" {
		t.Fatalf("legacy row = %+v", got)
	}
}
