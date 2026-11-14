package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The numbered schema history (schema_migrations.go) is what lets a node roll
// back before finalize: open runs only n1Safe migrations, one-way ones wait
// for RunOneWayMigrations, and a build refuses a database a newer build has
// changed one way. These tests pin each of those promises.

// rawDB opens path without the store, as a test's stand-in for an older or
// newer sandboxd.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func appliedOf(t *testing.T, db *sql.DB) map[int]bool {
	t.Helper()
	applied, err := appliedSchemaMigrations(context.Background(), db)
	if err != nil {
		t.Fatalf("appliedSchemaMigrations: %v", err)
	}
	return applied
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return exists
}

// legacyFlags is the history every database records for the legacy steps.
func legacyFlags() map[int]bool {
	flags := map[int]bool{}
	for _, m := range legacySchemaMigrations(nil, nil, nil) {
		flags[m.number] = m.n1Safe
	}
	return flags
}

// openFlags is what Open records with the production list: every legacy
// step, and each newer migration that runs at open (n1Safe; a one-way one
// waits for RunOneWayMigrations).
func openFlags() map[int]bool {
	flags := legacyFlags()
	for _, m := range newerSchemaMigrations {
		if m.n1Safe {
			flags[m.number] = true
		}
	}
	return flags
}

// countingMigration returns a newer migration that creates table and counts
// how often it ran.
func countingMigration(number int, n1Safe bool, table string, runs *int) schemaMigration {
	return schemaMigration{number: number, name: "create_" + table, n1Safe: n1Safe,
		applyTx: func(ctx context.Context, tx *sql.Tx) error {
			*runs++
			_, err := tx.ExecContext(ctx, `CREATE TABLE `+table+` (id INTEGER PRIMARY KEY)`)
			return err
		}}
}

func TestSchemaMigrationsDefaultListIsWellFormed(t *testing.T) {
	legacy := legacySchemaMigrations(nil, nil, nil)
	for i, m := range legacy {
		if m.number != i+1 || m.applyDB == nil {
			t.Fatalf("legacy migration %d = %+v, want number %d with applyDB", i, m, i+1)
		}
	}
	if got := legacy[len(legacy)-1].number; got != legacyMigrationBaseline {
		t.Fatalf("last legacy migration = %d, want legacyMigrationBaseline %d", got, legacyMigrationBaseline)
	}
	if err := validateSchemaMigrations(append(legacy, newerSchemaMigrations...)); err != nil {
		t.Fatalf("default migrations: %v", err)
	}
	for _, m := range newerSchemaMigrations {
		if m.number <= legacyMigrationBaseline {
			t.Fatalf("newer migration %d (%s) is not above the legacy baseline", m.number, m.name)
		}
	}
	if got := OneWayMigrations(); got == nil {
		t.Fatal("OneWayMigrations() = nil, want an empty list (release.json writes [])")
	}
}

// release.json's one_way_migrations: newer one-way entries only. The legacy
// steps' one-way work runs at open and never waits for finalize.
func TestOneWayNumbers(t *testing.T) {
	apply := func(context.Context, *sql.Tx) error { return nil }
	list := append(legacySchemaMigrations(nil, nil, nil),
		schemaMigration{number: legacyMigrationBaseline + 1, name: "added", n1Safe: true, applyTx: apply},
		schemaMigration{number: legacyMigrationBaseline + 2, name: "rebuilt", applyTx: apply},
		schemaMigration{number: legacyMigrationBaseline + 4, name: "backfilled", applyTx: apply},
	)
	want := []int{legacyMigrationBaseline + 2, legacyMigrationBaseline + 4}
	if got := oneWayNumbers(list); !slices.Equal(got, want) {
		t.Fatalf("oneWayNumbers = %v, want %v", got, want)
	}
	if got := oneWayNumbers(nil); got == nil || len(got) != 0 {
		t.Fatalf("oneWayNumbers(nil) = %#v, want an empty non-nil list", got)
	}
}

func TestValidateSchemaMigrations(t *testing.T) {
	apply := func(*sql.DB) error { return nil }
	applyTx := func(context.Context, *sql.Tx) error { return nil }
	tests := []struct {
		name    string
		list    []schemaMigration
		wantErr string
	}{
		{"ordered", []schemaMigration{{number: 1, name: "a", applyDB: apply}, {number: 3, name: "b", applyTx: applyTx}}, ""},
		{"duplicate number", []schemaMigration{{number: 1, name: "a", applyDB: apply}, {number: 1, name: "b", applyDB: apply}}, "not numbered after 1"},
		{"out of order", []schemaMigration{{number: 2, name: "a", applyDB: apply}, {number: 1, name: "b", applyDB: apply}}, "not numbered after 2"},
		{"zero", []schemaMigration{{number: 0, name: "a", applyDB: apply}}, "not numbered after 0"},
		{"no name", []schemaMigration{{number: 1, applyDB: apply}}, "has no name"},
		{"no apply", []schemaMigration{{number: 1, name: "a"}}, "exactly one of"},
		{"both applies", []schemaMigration{{number: 1, name: "a", applyDB: apply, applyTx: applyTx}}, "exactly one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSchemaMigrations(tt.list)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// A fresh database records every legacy step with its flag and has nothing
// pending.
func TestSchemaMigrationsFreshDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if got, want := appliedOf(t, st.db), openFlags(); !maps.Equal(got, want) {
		t.Fatalf("applied = %v, want %v", got, want)
	}
	pending, err := st.PendingOneWayMigrations(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("PendingOneWayMigrations = %v, %v; want none", pending, err)
	}
	if err := st.RunOneWayMigrations(context.Background()); err != nil {
		t.Fatalf("RunOneWayMigrations with nothing pending: %v", err)
	}
}

// A database from before schema versioning (no schema_migrations table)
// records the whole legacy history at its first open, and the legacy steps
// still do their work on an old shape.
func TestSchemaMigrationsRecordHistoryOnUpgrade(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, path string)
		check func(t *testing.T, st *Store)
	}{
		{
			name: "fully migrated database from the previous release",
			setup: func(t *testing.T, path string) {
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if err := st.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				// The previous release never made this table.
				if _, err := rawDB(t, path).Exec(`DROP TABLE schema_migrations`); err != nil {
					t.Fatalf("drop schema_migrations: %v", err)
				}
			},
		},
		{
			name: "old image-GC ledger shape",
			setup: func(t *testing.T, path string) {
				if _, err := rawDB(t, path).Exec(`CREATE TABLE pending_image_gc (image TEXT PRIMARY KEY, scheduled_at DATETIME NOT NULL);`); err != nil {
					t.Fatalf("create legacy table: %v", err)
				}
			},
			check: func(t *testing.T, st *Store) {
				inKey, err := columnInPrimaryKey(st.db, "pending_image_gc", "engine")
				if err != nil || !inKey {
					t.Fatalf("engine in pending_image_gc key = %v, %v; want the legacy step to have rebuilt it", inKey, err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.db")
			tt.setup(t, path)
			st, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = st.Close() })
			if got, want := appliedOf(t, st.db), openFlags(); !maps.Equal(got, want) {
				t.Fatalf("applied = %v, want %v", got, want)
			}
			if tt.check != nil {
				tt.check(t, st)
			}
		})
	}
}

// Numbers this build does not know: n1Safe ones are a newer build's additive
// changes and are ignored; a single one-way one refuses the open before
// anything is written.
func TestSchemaMigrationsUnknownNumbers(t *testing.T) {
	tests := []struct {
		name        string
		rows        map[int]bool // number -> n1_safe, written by a "newer build"
		wantRefused []int
	}{
		{name: "known numbers only", rows: map[int]bool{1: true, 2: false}},
		{name: "unknown n1_safe numbers", rows: map[int]bool{90: true, 91: true}},
		{name: "unknown one-way number", rows: map[int]bool{90: true, 91: false}, wantRefused: []int{91}},
		{name: "several unknown one-way numbers", rows: map[int]bool{92: false, 90: false, 91: true}, wantRefused: []int{90, 92}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "newer.db")
			raw := rawDB(t, path)
			if _, err := raw.Exec(schemaMigrationsDDL); err != nil {
				t.Fatalf("create schema_migrations: %v", err)
			}
			for number, n1Safe := range tt.rows {
				if _, err := raw.Exec(`INSERT INTO schema_migrations (number, name, n1_safe, applied_at) VALUES (?, 'newer', ?, CURRENT_TIMESTAMP)`, number, n1Safe); err != nil {
					t.Fatalf("seed %d: %v", number, err)
				}
			}

			st, err := Open(path)
			if tt.wantRefused == nil {
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				_ = st.Close()
				return
			}
			if err == nil {
				_ = st.Close()
				t.Fatal("Open succeeded on a database with an unknown one-way migration")
			}
			if !errors.Is(err, ErrSchemaFromNewerRelease) {
				t.Fatalf("err = %v, want ErrSchemaFromNewerRelease", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tt.wantRefused)) {
				t.Fatalf("err = %v, want it to name %v", err, tt.wantRefused)
			}
			// Refused before any write: the base schema never ran.
			if tableExists(t, raw, "sandboxes") {
				t.Fatal("a refused open created the sandboxes table")
			}
		})
	}
}

// The rollback promise end to end: a release adds an n1Safe and a one-way
// migration; until RunOneWayMigrations the previous release (which knows
// neither) still opens the database; once the one-way step has run it
// refuses.
func TestSchemaMigrationsOneWayWaitsForRunOneWayMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rollout.db")
	var addRuns, oneWayRuns, laterRuns int
	next := []schemaMigration{
		countingMigration(legacyMigrationBaseline+1, true, "added_table", &addRuns),
		countingMigration(legacyMigrationBaseline+2, false, "rebuilt_table", &oneWayRuns),
		// An n1Safe migration after a pending one-way one still runs at open.
		countingMigration(legacyMigrationBaseline+3, true, "later_table", &laterRuns),
	}

	st, err := openWith(path, nil, next)
	if err != nil {
		t.Fatalf("open new build: %v", err)
	}
	if addRuns != 1 || laterRuns != 1 || oneWayRuns != 0 {
		t.Fatalf("runs at open: add=%d later=%d one-way=%d, want 1 1 0", addRuns, laterRuns, oneWayRuns)
	}
	if tableExists(t, st.db, "rebuilt_table") {
		t.Fatal("the one-way migration ran at open")
	}
	pending, err := st.PendingOneWayMigrations(ctx)
	if err != nil || !slices.Equal(pending, []int{legacyMigrationBaseline + 2}) {
		t.Fatalf("PendingOneWayMigrations = %v, %v; want [%d]", pending, err, legacyMigrationBaseline+2)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Roll back before finalize: the previous release opens it.
	prev, err := openWith(path, nil, nil)
	if err != nil {
		t.Fatalf("previous release before finalize: %v", err)
	}
	_ = prev.Close()

	// Finalize.
	st, err = openWith(path, nil, next)
	if err != nil {
		t.Fatalf("reopen new build: %v", err)
	}
	if err := st.RunOneWayMigrations(ctx); err != nil {
		t.Fatalf("RunOneWayMigrations: %v", err)
	}
	if err := st.RunOneWayMigrations(ctx); err != nil {
		t.Fatalf("second RunOneWayMigrations: %v", err)
	}
	if oneWayRuns != 1 || !tableExists(t, st.db, "rebuilt_table") {
		t.Fatalf("one-way runs = %d (table %v), want exactly 1", oneWayRuns, tableExists(t, st.db, "rebuilt_table"))
	}
	if n1Safe, ok := appliedOf(t, st.db)[legacyMigrationBaseline+2]; !ok || n1Safe {
		t.Fatalf("one-way record = (n1_safe=%v, present=%v), want present with n1_safe=0", n1Safe, ok)
	}
	pending, err = st.PendingOneWayMigrations(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("PendingOneWayMigrations after finalize = %v, %v; want none", pending, err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After finalize the previous release must not open it.
	if prev, err := openWith(path, nil, nil); !errors.Is(err, ErrSchemaFromNewerRelease) {
		if prev != nil {
			_ = prev.Close()
		}
		t.Fatalf("previous release after finalize: err = %v, want ErrSchemaFromNewerRelease", err)
	}
}

// Reopening applies nothing twice and keeps the first record of each step.
func TestSchemaMigrationsReopenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")
	var runs int
	next := []schemaMigration{countingMigration(legacyMigrationBaseline+1, true, "once_table", &runs)}

	readRecords := func(db *sql.DB) map[int]string {
		rows, err := db.Query(`SELECT number, applied_at FROM schema_migrations`)
		if err != nil {
			t.Fatalf("read records: %v", err)
		}
		defer rows.Close()
		out := map[int]string{}
		for rows.Next() {
			var n int
			var at string
			if err := rows.Scan(&n, &at); err != nil {
				t.Fatalf("scan record: %v", err)
			}
			out[n] = at
		}
		return out
	}

	var first map[int]string
	for i := range 3 {
		st, err := openWith(path, nil, next)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		records := readRecords(st.db)
		if i == 0 {
			first = records
		} else if !maps.Equal(records, first) {
			t.Fatalf("open %d records = %v, want unchanged %v", i, records, first)
		}
		_ = st.Close()
	}
	if runs != 1 {
		t.Fatalf("n1Safe migration ran %d times over three opens, want 1", runs)
	}
	if len(first) != legacyMigrationBaseline+1 {
		t.Fatalf("records = %d, want %d", len(first), legacyMigrationBaseline+1)
	}
}

// A failed migration leaves no record: an n1Safe one fails the open, a
// one-way one fails RunOneWayMigrations and the next call retries it. An
// applyTx failure rolls back its own writes.
func TestSchemaMigrationsFailuresAreNotRecorded(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")

	t.Run("n1Safe failure fails the open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fail-open.db")
		next := []schemaMigration{{number: legacyMigrationBaseline + 1, name: "half_done", n1Safe: true,
			applyTx: func(ctx context.Context, tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `CREATE TABLE half_done (id INTEGER)`); err != nil {
					return err
				}
				return boom
			}}}
		if st, err := openWith(path, nil, next); !errors.Is(err, boom) {
			if st != nil {
				_ = st.Close()
			}
			t.Fatalf("open err = %v, want boom", err)
		}
		raw := rawDB(t, path)
		if tableExists(t, raw, "half_done") {
			t.Fatal("a failed applyTx left its table behind")
		}
		if _, ok := appliedOf(t, raw)[legacyMigrationBaseline+1]; ok {
			t.Fatal("a failed migration was recorded")
		}
	})

	t.Run("one-way failure is retried", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fail-oneway.db")
		fail := true
		var runs int
		next := []schemaMigration{{number: legacyMigrationBaseline + 1, name: "flaky", applyDB: func(db *sql.DB) error {
			runs++
			if fail {
				return boom
			}
			_, err := db.Exec(`CREATE TABLE IF NOT EXISTS flaky (id INTEGER)`)
			return err
		}}}
		st, err := openWith(path, nil, next)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.RunOneWayMigrations(ctx); !errors.Is(err, boom) || !strings.Contains(err.Error(), "flaky") {
			t.Fatalf("RunOneWayMigrations err = %v, want boom naming the migration", err)
		}
		if pending, _ := st.PendingOneWayMigrations(ctx); len(pending) != 1 {
			t.Fatalf("pending after failure = %v, want the failed migration", pending)
		}
		fail = false
		if err := st.RunOneWayMigrations(ctx); err != nil {
			t.Fatalf("retry: %v", err)
		}
		if runs != 2 || !tableExists(t, st.db, "flaky") {
			t.Fatalf("runs = %d, want 2 with the table made", runs)
		}
		if pending, _ := st.PendingOneWayMigrations(ctx); len(pending) != 0 {
			t.Fatalf("pending after retry = %v, want none", pending)
		}
	})

	t.Run("malformed list fails the open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "malformed.db")
		next := []schemaMigration{{number: legacyMigrationBaseline, name: "reused_number", applyTx: func(context.Context, *sql.Tx) error { return nil }}}
		if st, err := openWith(path, nil, next); err == nil {
			_ = st.Close()
			t.Fatal("open accepted a migration numbered inside the legacy range")
		}
	})
}

func TestSchemaMigrationsClosedStore(t *testing.T) {
	ctx := context.Background()
	var nilStore *Store
	if err := nilStore.RunOneWayMigrations(ctx); err == nil {
		t.Fatal("RunOneWayMigrations on a nil store succeeded")
	}
	if _, err := nilStore.PendingOneWayMigrations(ctx); err == nil {
		t.Fatal("PendingOneWayMigrations on a nil store succeeded")
	}

	st, err := openWith(filepath.Join(t.TempDir(), "closed.db"), nil, []schemaMigration{
		{number: legacyMigrationBaseline + 1, name: "pending", applyTx: func(context.Context, *sql.Tx) error { return nil }},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = st.Close()
	if err := st.RunOneWayMigrations(ctx); err == nil {
		t.Fatal("RunOneWayMigrations on a closed store succeeded")
	}
	if _, err := st.PendingOneWayMigrations(ctx); err == nil {
		t.Fatal("PendingOneWayMigrations on a closed store succeeded")
	}
}

// AppliedOneWayMigrations reads the record: the finalize-gated one-way
// numbers, whoever wrote them, never the legacy steps or n1Safe ones. The
// node upgrader diffs a database and its backup through it.
func TestAppliedOneWayMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	raw := rawDB(t, path)
	if got, err := AppliedOneWayMigrations(ctx, raw); err != nil || len(got) != 0 || got == nil {
		t.Fatalf("no table = %#v, %v; want an empty list", got, err)
	}
	st, err := openWith(path, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = st.Close()
	for number, n1Safe := range map[int]bool{legacyMigrationBaseline + 7: false, legacyMigrationBaseline + 1: true, legacyMigrationBaseline + 2: false} {
		if _, err := raw.Exec(`INSERT INTO schema_migrations (number, name, n1_safe, applied_at) VALUES (?, 'newer', ?, CURRENT_TIMESTAMP)`, number, n1Safe); err != nil {
			t.Fatalf("seed %d: %v", number, err)
		}
	}
	got, err := AppliedOneWayMigrations(ctx, raw)
	if err != nil || !slices.Equal(got, []int{legacyMigrationBaseline + 2, legacyMigrationBaseline + 7}) {
		t.Fatalf("AppliedOneWayMigrations = %v, %v", got, err)
	}
	_ = raw.Close()
	if _, err := AppliedOneWayMigrations(ctx, raw); err == nil {
		t.Fatal("a closed database answered")
	}
}
