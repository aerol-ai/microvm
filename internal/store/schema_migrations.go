package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Schema versioning (plans/kubectl-style-cluster-ops.md §6.5, CEO D16).
//
// Every schema change is a numbered migration with an n1Safe flag. n1Safe
// means the migration only adds tables or columns the previous release
// ignores; a migration that rebuilds a table or rewrites, backfills or drops
// data is one-way. schema_migrations records each applied number with its
// flag, and that record is what makes an upgrade reversible:
//
//   - Open applies every n1Safe migration this build knows.
//   - A one-way migration numbered above legacyMigrationBaseline waits for
//     RunOneWayMigrations. The cluster calls it once the new version is
//     finalized; a single node with cluster mode off calls it right after
//     Open. Until then the previous release can still open the database, so
//     rolling a node back always works. Code that ships a one-way migration
//     must keep working on the old schema until it has run
//     (PendingOneWayMigrations says when).
//   - A build that finds an applied number it does not know refuses to open,
//     unless every such number is recorded as n1Safe: a newer build's
//     additive change that this one can ignore. One unknown one-way number
//     means the data has a shape this build has never seen.
//
// Migrations 1..legacyMigrationBaseline are the steps Open ran before this
// table existed. Each detects for itself whether it still has work to do
// (duplicate-column ALTERs, PRAGMA checks before a rebuild), and they still
// run at every open, exactly as before: the release that can be rolled back
// to knows nothing of schema_migrations and may write rows in the old way
// (backfillSnapshotOwners exists for that), and tests downgrade a table and
// reopen to prove a rebuild. They are recorded for the history only, and
// their n1Safe flag is informational: every build that reads this table
// knows them. They predate finalize gating, so their one-way steps keep
// running at open.
//
// To change the schema, append to newerSchemaMigrations with the next
// number. Never renumber, reorder or remove an entry: the number is what a
// database records.

// legacyMigrationBaseline is the last migration that predates
// schema_migrations. See legacySchemaMigrations.
const legacyMigrationBaseline = 12

// schemaMigration is one numbered schema change. Exactly one of applyTx and
// applyDB is set.
type schemaMigration struct {
	number int
	name   string
	n1Safe bool
	// applyTx runs inside the transaction that also records the number, so
	// the migration and its record commit together or not at all. Newer
	// migrations should use it.
	applyTx func(ctx context.Context, tx *sql.Tx) error
	// applyDB manages its own transactions (the legacy steps do, and some
	// need PRAGMAs a transaction cannot change). The record is written after
	// it returns, so a crash in between runs it again: it must detect that
	// its work is already done.
	applyDB func(db *sql.DB) error
}

// newerSchemaMigrations lists the migrations added after schema versioning,
// numbered from legacyMigrationBaseline+1. Empty today.
var newerSchemaMigrations = []schemaMigration{}

// ErrSchemaFromNewerRelease is Open's error for a database on which a newer
// sandboxd applied a one-way migration this build does not know.
var ErrSchemaFromNewerRelease = errors.New("store: database has one-way schema migrations from a newer sandboxd")

const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	number INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	n1_safe INTEGER NOT NULL,
	applied_at DATETIME NOT NULL
);`

// legacySchemaMigrations wraps the steps Open ran before schema versioning,
// in their original order and with their original errors. baseSchema is the
// CREATE ... IF NOT EXISTS list and columnMigrations the duplicate-tolerant
// ALTER list (which also holds the sandbox_env backfill); both stay inline in
// open so their history reads as it always has.
func legacySchemaMigrations(baseSchema, columnMigrations []string, secretCipher *secrets.Cipher) []schemaMigration {
	return []schemaMigration{
		{number: 1, name: "base_schema", n1Safe: true, applyDB: func(db *sql.DB) error {
			for _, stmt := range baseSchema {
				if _, err := db.Exec(stmt); err != nil {
					return fmt.Errorf("run schema statement: %w", err)
				}
			}
			return nil
		}},
		// One-way only because of the sandbox_env backfill among the ALTERs.
		{number: 2, name: "added_columns_and_env_backfill", applyDB: func(db *sql.DB) error {
			for _, stmt := range columnMigrations {
				if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
					return fmt.Errorf("apply schema migration %q: %w", stmt, err)
				}
			}
			return nil
		}},
		// The image-GC ledger predates engine awareness with `image` as its
		// sole primary key, and SQLite cannot widen a primary key in place.
		// Rebuild it once so a node that holds the same image under two
		// engines can carry a cleanup row for each.
		{number: 3, name: "pending_image_gc_engine_key", applyDB: migratePendingImageGCKey},
		// owner_ref is a compatibility column, so the per-owner name index
		// can only be built after the ALTERs in 2.
		{number: 4, name: "sandbox_name_index_per_owner", applyDB: migrateSandboxNameIndex},
		{number: 5, name: "snapshot_owner_backfill", applyDB: backfillSnapshotOwners},
		// Widen the snapshot primary key from (name) to (owner_ref, name) so
		// two tenants can hold a same-named snapshot and one cannot learn or
		// pre-claim another's names. Runs AFTER the owner backfill so
		// owner_ref is populated before it leads the key. SQLite cannot widen
		// a PK in place, so this rebuilds sandbox_snapshots and
		// snapshot_aliases (whose FK depends on it). A no-op once the
		// composite key is in place.
		{number: 6, name: "snapshot_owner_pk", applyDB: migrateSnapshotOwnerPK},
		{number: 7, name: "snapshot_push_queue_shape", n1Safe: true, applyDB: ensureSnapshotPushQueueShape},
		// Widen the WASM catalogue key from (id) to (owner_ref, id) so a
		// second tenant registering the same module bytes gets its own
		// digest-id row. Runs after 2, which adds owner_ref to pre-#724
		// tables.
		{number: 8, name: "wasm_module_owner_pk", applyDB: migrateWasmModuleOwnerPK},
		// Partial unique index on host_port (only enforced when host_port >
		// 0). This is the load-bearing primitive of the random-first
		// allocator: two concurrent ExposePort calls race to INSERT a
		// host_port row, and only one wins per port. SQLite's single writer
		// keeps the contest serialized. One-way: a constraint, not something
		// an older build can ignore.
		{number: 9, name: "exposed_ports_host_port_unique_index", applyDB: func(db *sql.DB) error {
			if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_exposed_ports_host_port ON exposed_ports(host_port) WHERE host_port > 0;`); err != nil {
				return fmt.Errorf("create exposed_ports host_port index: %w", err)
			}
			return nil
		}},
		{number: 10, name: "sandbox_lookup_indexes", n1Safe: true, applyDB: createSandboxLookupIndexes},
		{number: 11, name: "legacy_plaintext_secrets", applyDB: func(db *sql.DB) error {
			return migrateLegacyPlaintextSecrets(db, secretCipher)
		}},
		{number: 12, name: "env_binding", applyDB: func(db *sql.DB) error {
			return migrateEnvBinding(db, secretCipher)
		}},
	}
}

// createSandboxLookupIndexes builds the partial indexes over columns the
// ALTERs in migration 2 add.
func createSandboxLookupIndexes(db *sql.DB) error {
	for _, ix := range []struct{ ddl, what string }{
		// Keeps the auto-import reconciler scan O(pending), not
		// O(sandboxes). Steady-state count is zero so the index footprint is
		// negligible; spikes happen when AOCR is briefly unreachable.
		{`CREATE INDEX IF NOT EXISTS idx_sandboxes_auto_import_pending ON sandboxes(id) WHERE auto_import_pending = 1;`, "auto_import_pending"},
		// Same shape for the rollback-pending reconcile scan: zero rows in the
		// steady state, so every reconcile pass is one empty index probe.
		{`CREATE INDEX IF NOT EXISTS idx_sandboxes_rollback_pending ON sandboxes(id) WHERE rollback_pending = 1;`, "rollback_pending"},
		// The template GC and DELETE-template both call IsTemplateReferenced
		// (a SELECT 1 ... WHERE template_id = ? LIMIT 1), which becomes an
		// index probe instead of a table scan. The predicate keeps the index
		// empty for Docker sandboxes and for Firecracker sandboxes built from
		// ad-hoc images.
		{`CREATE INDEX IF NOT EXISTS idx_sandboxes_template_id ON sandboxes(template_id) WHERE template_id <> '';`, "template_id"},
		// WASM module GC checks whether any sandbox still references a
		// catalogue row by module_ref or module_digest.
		{`CREATE INDEX IF NOT EXISTS idx_sandboxes_module_ref ON sandboxes(module_ref) WHERE module_ref <> '';`, "module_ref"},
		{`CREATE INDEX IF NOT EXISTS idx_sandboxes_module_digest ON sandboxes(module_digest) WHERE module_digest <> '';`, "module_digest"},
		// The create-time check that a new id is not another sandbox's name
		// (see sandboxNameLookupIndexDDL). Open ran it right here before
		// schema versioning, so it stays in this legacy step rather than
		// becoming a newer migration.
		{sandboxNameLookupIndexDDL, "name lookup"},
	} {
		if _, err := db.Exec(ix.ddl); err != nil {
			return fmt.Errorf("create sandboxes %s index: %w", ix.what, err)
		}
	}
	return nil
}

// validateSchemaMigrations rejects a malformed migration list: a programming
// error, caught at the first open of a build that has it.
func validateSchemaMigrations(migrations []schemaMigration) error {
	prev := 0
	for _, m := range migrations {
		switch {
		case m.number <= prev:
			return fmt.Errorf("store: schema migration %d (%s) is not numbered after %d", m.number, m.name, prev)
		case m.name == "":
			return fmt.Errorf("store: schema migration %d has no name", m.number)
		case (m.applyTx == nil) == (m.applyDB == nil):
			return fmt.Errorf("store: schema migration %d (%s) must set exactly one of applyTx and applyDB", m.number, m.name)
		}
		prev = m.number
	}
	return nil
}

// migrateSchema brings db to this build's schema at open: it refuses a
// database a newer build made one-way changes to, then runs the legacy
// steps and every newer n1Safe migration not yet applied. Newer one-way
// migrations are left for RunOneWayMigrations.
func migrateSchema(db *sql.DB, migrations []schemaMigration) error {
	if err := validateSchemaMigrations(migrations); err != nil {
		return err
	}
	ctx := context.Background()
	// Read before writing anything, so a refused database is left exactly
	// as the newer build left it.
	applied, err := appliedSchemaMigrations(ctx, db)
	if err != nil {
		return err
	}
	if err := checkUnknownSchemaMigrations(applied, migrations); err != nil {
		return err
	}
	if _, err := db.Exec(schemaMigrationsDDL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	for _, m := range migrations {
		if m.number <= legacyMigrationBaseline {
			if err := m.applyDB(db); err != nil {
				return err
			}
			if err := recordSchemaMigration(ctx, db, m); err != nil {
				return err
			}
			continue
		}
		if _, done := applied[m.number]; done || m.waitsForFinalize() {
			continue
		}
		if err := applySchemaMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

// RunOneWayMigrations applies this build's one-way migrations that have not
// run yet, in number order, each recorded as it commits. The cluster calls it
// after the leader commits the new active version (finalize), so a rollback
// before then finds the database the previous release can read; with cluster
// mode off, the daemon calls it right after Open. Safe to call again and
// from concurrent callers: applied migrations are skipped. On an error the
// migrations before the failed one stay applied and the next call resumes at
// the failed one.
func (s *Store) RunOneWayMigrations(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("store: not open")
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	applied, err := appliedSchemaMigrations(ctx, s.db)
	if err != nil {
		return err
	}
	for _, m := range s.migrations {
		if _, done := applied[m.number]; done || !m.waitsForFinalize() {
			continue
		}
		if err := applySchemaMigration(ctx, s.db, m); err != nil {
			return err
		}
	}
	return nil
}

// PendingOneWayMigrations lists the one-way migrations this build knows that
// have not run on this database. Empty once RunOneWayMigrations has
// finished; a feature that needs one of them stays off until then.
func (s *Store) PendingOneWayMigrations(ctx context.Context) ([]int, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("store: not open")
	}
	applied, err := appliedSchemaMigrations(ctx, s.db)
	if err != nil {
		return nil, err
	}
	var pending []int
	for _, number := range oneWayNumbers(s.migrations) {
		if _, done := applied[number]; !done {
			pending = append(pending, number)
		}
	}
	return pending, nil
}

// AppliedOneWayMigrations lists the finalize-gated one-way migrations
// recorded on db, sorted: numbers above the legacy steps whose record says
// not n1Safe. It reads the record, not this build's list, so it also
// answers for a database a newer build migrated. The node upgrader
// compares a database with its backup through it: a number the backup
// lacks is a one-way change made since, which an older build that does
// not know it refuses (ErrSchemaFromNewerRelease).
func AppliedOneWayMigrations(ctx context.Context, db *sql.DB) ([]int, error) {
	applied, err := appliedSchemaMigrations(ctx, db)
	if err != nil {
		return nil, err
	}
	out := []int{}
	for number, n1Safe := range applied {
		if number > legacyMigrationBaseline && !n1Safe {
			out = append(out, number)
		}
	}
	slices.Sort(out)
	return out, nil
}

// OneWayMigrations lists the numbers of this build's one-way migrations
// that wait for finalize (newer than legacyMigrationBaseline and not
// n1Safe). release.json carries it as one_way_migrations.
func OneWayMigrations() []int {
	return oneWayNumbers(newerSchemaMigrations)
}

// oneWayNumbers lists the numbers in migrations that wait for finalize,
// never nil.
func oneWayNumbers(migrations []schemaMigration) []int {
	nums := []int{}
	for _, m := range migrations {
		if m.waitsForFinalize() {
			nums = append(nums, m.number)
		}
	}
	return nums
}

// waitsForFinalize reports whether m runs only through RunOneWayMigrations:
// one-way and newer than the legacy steps, whose one-way work still runs at
// open.
func (m schemaMigration) waitsForFinalize() bool {
	return m.number > legacyMigrationBaseline && !m.n1Safe
}

// appliedSchemaMigrations reads schema_migrations as number -> n1_safe. A
// database from before schema versioning has no table and reads as empty.
func appliedSchemaMigrations(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("inspect schema_migrations: %w", err)
	}
	applied := map[int]bool{}
	if !exists {
		return applied, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT number, n1_safe FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var number int
		var n1Safe bool
		if err := rows.Scan(&number, &n1Safe); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[number] = n1Safe
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return applied, nil
}

// checkUnknownSchemaMigrations refuses applied numbers this build does not
// know, unless every one of them is n1Safe.
func checkUnknownSchemaMigrations(applied map[int]bool, migrations []schemaMigration) error {
	known := make(map[int]struct{}, len(migrations))
	highest := 0
	for _, m := range migrations {
		known[m.number] = struct{}{}
		highest = max(highest, m.number)
	}
	var oneWay []int
	for number, n1Safe := range applied {
		if _, ok := known[number]; !ok && !n1Safe {
			oneWay = append(oneWay, number)
		}
	}
	if len(oneWay) == 0 {
		return nil
	}
	slices.Sort(oneWay)
	return fmt.Errorf("%w: migration(s) %v are applied and this build knows migrations up to %d only; run that newer sandboxd (or a later one), or restore the database backup taken before the upgrade",
		ErrSchemaFromNewerRelease, oneWay, highest)
}

// applySchemaMigration runs one newer migration and records it.
func applySchemaMigration(ctx context.Context, db *sql.DB, m schemaMigration) error {
	if m.applyDB != nil {
		if err := m.applyDB(db); err != nil {
			return fmt.Errorf("schema migration %d (%s): %w", m.number, m.name, err)
		}
		return recordSchemaMigration(ctx, db, m)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("schema migration %d (%s): begin: %w", m.number, m.name, err)
	}
	defer tx.Rollback()
	if err := m.applyTx(ctx, tx); err != nil {
		return fmt.Errorf("schema migration %d (%s): %w", m.number, m.name, err)
	}
	if err := recordSchemaMigration(ctx, tx, m); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("schema migration %d (%s): commit: %w", m.number, m.name, err)
	}
	return nil
}

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// recordSchemaMigration records m as applied. INSERT OR IGNORE keeps the
// first applied_at of a legacy step that runs at every open.
func recordSchemaMigration(ctx context.Context, exec sqlExecer, m schemaMigration) error {
	if _, err := exec.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations (number, name, n1_safe, applied_at) VALUES (?, ?, ?, ?)`,
		m.number, m.name, m.n1Safe, time.Now().UTC()); err != nil {
		return fmt.Errorf("record schema migration %d (%s): %w", m.number, m.name, err)
	}
	return nil
}
