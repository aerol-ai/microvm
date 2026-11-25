package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// warmOf reads a sandbox's stored warm value back through Get.
func warmOf(t *testing.T, st *Store, id string) string {
	t.Helper()
	got, err := st.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	return got.Warm
}

// TestUpsertNeverWritesWarm: warm says how a sandbox's create started, so
// only the create's INSERT writes it. A whole-row write from any read (a
// stop, a start, a write whose copy says something else) keeps the stored
// value, and a row Upsert makes itself has none recorded.
func TestUpsertNeverWritesWarm(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-warm")
	sb.Warm = models.WarmPoolKindParked
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := warmOf(t, st, "sb-warm"); got != models.WarmPoolKindParked {
		t.Fatalf("after Create warm = %q, want parked", got)
	}
	for _, tc := range []struct {
		name   string
		warm   string
		status models.SandboxStatus
	}{
		{"a stop from a copy that says snapshot", models.WarmPoolKindSnapshot, models.SandboxStatusStopped},
		{"a start from a copy with nothing", "", models.SandboxStatusStarted},
		{"a write from a copy that says none", models.WarmPoolKindNone, models.SandboxStatusStarted},
	} {
		row, err := st.Get(ctx, "sb-warm")
		if err != nil {
			t.Fatalf("%s: Get: %v", tc.name, err)
		}
		row.Warm, row.Status = tc.warm, tc.status
		if err := st.Upsert(ctx, row); err != nil {
			t.Fatalf("%s: Upsert: %v", tc.name, err)
		}
		if got := warmOf(t, st, "sb-warm"); got != models.WarmPoolKindParked {
			t.Fatalf("%s: warm = %q, want the create's parked", tc.name, got)
		}
	}

	fresh := sampleSandbox("sb-upserted")
	fresh.Warm = models.WarmPoolKindParked
	if err := st.Upsert(ctx, fresh); err != nil {
		t.Fatalf("Upsert a new row: %v", err)
	}
	if got := warmOf(t, st, "sb-upserted"); got != "" {
		t.Fatalf("a row Upsert made has warm %q, want none recorded", got)
	}
}

// TestWarmMigration: migration 16 adds the column with "" for older rows,
// tolerates a column that is already there, and stops the open on any
// other failure.
func TestWarmMigration(t *testing.T) {
	var m16 *schemaMigration
	for i := range newerSchemaMigrations {
		if newerSchemaMigrations[i].number == 16 {
			m16 = &newerSchemaMigrations[i]
		}
	}
	if m16 == nil || !m16.n1Safe || m16.applyTx == nil {
		t.Fatalf("migration 16 = %+v, want an n1Safe applyTx migration", m16)
	}

	t.Run("any other error stops the open", func(t *testing.T) {
		db := rawDB(t, filepath.Join(t.TempDir(), "no-sandboxes.db"))
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback()
		if err := m16.applyTx(context.Background(), tx); err == nil || strings.Contains(err.Error(), "duplicate column name") {
			t.Fatalf("migration 16 on a database without sandboxes = %v, want its error", err)
		}
	})

	t.Run("a column already there is kept", func(t *testing.T) {
		st := newTestStore(t)
		tx, err := st.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback()
		if err := m16.applyTx(context.Background(), tx); err != nil {
			t.Fatalf("migration 16 over an existing column = %v, want nil", err)
		}
	})

	t.Run("an older database gets the column, its rows read none", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "old.db")
		st, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := st.Create(ctx, sampleSandbox("sb-old")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		// Back to the previous release's shape: no column, no record of 16.
		raw := rawDB(t, path)
		for _, stmt := range []string{
			`ALTER TABLE sandboxes DROP COLUMN warm`,
			`DELETE FROM schema_migrations WHERE number = 16`,
		} {
			if _, err := raw.Exec(stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		st, err = Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if got := warmOf(t, st, "sb-old"); got != "" {
			t.Fatalf("an older row's warm = %q, want none recorded", got)
		}
	})
}
