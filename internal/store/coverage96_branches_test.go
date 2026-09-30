package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// These tests reach error branches that a closed database cannot: failures
// that happen after a query or statement has already succeeded. They inject
// faults with SQLite itself rather than a fake driver:
//   - RAISE(ABORT) triggers make one specific statement fail;
//   - a trigger that leaves a DEFERRABLE foreign-key violation behind lets
//     every statement succeed and makes COMMIT fail;
//   - a view whose WHERE clause errors while stepping surfaces through
//     rows.Err() instead of Query or Scan;
//   - a FLOAT or BLOB in a DATETIME column, or TEXT in an INTEGER column,
//     fails Scan (go-sqlite3 maps unparsable DATETIME *text* to the zero
//     time, so garbage strings alone do not).
//
// Unreachable with go-sqlite3 and therefore not covered: RowsAffected and
// LastInsertId errors (the driver never returns one), json.Marshal of plain
// string slices/maps, AES-GCM seal failures, rows.Close errors, PRAGMA
// table_info scan/iteration errors, sql.Open errors for a registered driver,
// and chmod of a file the process just created.

type cov96bCase struct {
	name   string
	setup  func(t *testing.T, st *Store)
	call   func(st *Store) error
	wantOK bool
}

func runCov96bCases(t *testing.T, cases []cov96bCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			if tc.setup != nil {
				tc.setup(t, st)
			}
			err := tc.call(st)
			if tc.wantOK && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func cov96bExec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
}

func cov96bTriggerName(prefix, timing, table string) string {
	return prefix + "_" + strings.ToLower(strings.ReplaceAll(timing, " ", "_")) + "_" + table
}

// cov96bFailOn aborts every row operation matching timing ("BEFORE INSERT",
// "BEFORE DELETE", ...) on table.
func cov96bFailOn(t *testing.T, st *Store, timing, table string) {
	t.Helper()
	cov96bExec(t, st.db, fmt.Sprintf(
		`CREATE TRIGGER %s %s ON %s BEGIN SELECT RAISE(ABORT, 'cov96b injected failure'); END`,
		cov96bTriggerName("cov96b_fail", timing, table), timing, table))
}

// cov96bFailCommitOn leaves a deferred FK violation behind every matching row
// operation: the statement itself succeeds, the enclosing COMMIT fails.
func cov96bFailCommitOn(t *testing.T, st *Store, timing, table string) {
	t.Helper()
	cov96bExec(t, st.db,
		`CREATE TABLE IF NOT EXISTS cov96b_parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS cov96b_child (pid INTEGER REFERENCES cov96b_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		fmt.Sprintf(`CREATE TRIGGER %s %s ON %s BEGIN INSERT INTO cov96b_child VALUES (999); END`,
			cov96bTriggerName("cov96b_commit", timing, table), timing, table))
}

// cov96bReplaceWithView renames table to <table>_cov96b_real and installs a
// view under the original name. selectSQL may read from the renamed table.
func cov96bReplaceWithView(t *testing.T, st *Store, table, selectSQL string) {
	t.Helper()
	cov96bExec(t, st.db,
		fmt.Sprintf(`ALTER TABLE %s RENAME TO %s_cov96b_real`, table, table),
		fmt.Sprintf(`CREATE VIEW %s AS %s`, table, selectSQL))
}

// cov96bBreakRows swaps table for a view that errors on the first step, so
// the caller sees the failure from rows.Next/rows.Err.
func cov96bBreakRows(t *testing.T, st *Store, table string) {
	t.Helper()
	cov96bReplaceWithView(t, st, table, fmt.Sprintf(
		`SELECT * FROM %s_cov96b_real WHERE json_extract('not json', '$') IS NULL`, table))
}

func cov96bRawDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", sqliteDSN(filepath.Join(t.TempDir(), "raw.db")))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func cov96bClosedDB(t *testing.T) *sql.DB {
	t.Helper()
	db := cov96bRawDB(t)
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	return db
}

func cov96bCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// cov96bHoldTx leaves the store's single pooled connection inside an open
// transaction, so the next BeginTx fails with "cannot start a transaction
// within a transaction" while plain queries still work.
func cov96bHoldTx(t *testing.T, db *sql.DB) (release func()) {
	t.Helper()
	cov96bExec(t, db, `BEGIN`)
	return func() { _, _ = db.Exec(`ROLLBACK`) }
}

func cov96bCreate(t *testing.T, st *Store, sb *models.Sandbox) {
	t.Helper()
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("create %s: %v", sb.ID, err)
	}
}

func TestCov96bEnvBindingMigrationBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("closed db", func(t *testing.T) {
		if err := migrateEnvBinding(cov96bClosedDB(t), nil); err == nil {
			t.Fatal("expected schema inspection error")
		}
	})

	dropMarker := func(t *testing.T, st *Store) {
		t.Helper()
		cov96bExec(t, st.db, `ALTER TABLE sandbox_env DROP COLUMN binding_version`)
	}
	seedLegacy := func(t *testing.T, st *Store, cipher *secrets.Cipher, inc string) {
		t.Helper()
		sb := testSandbox("a", nil)
		sb.AuditIncarnationID = inc
		legacy, err := cipher.Encrypt([]byte(`{"K":"V"}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CreateWithSealedEnv(ctx, sb, legacy); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name   string
		setup  func(t *testing.T, st *Store, cipher *secrets.Cipher) (cleanup func())
		wantOK bool
	}{
		{
			name: "begin fails",
			setup: func(t *testing.T, st *Store, _ *secrets.Cipher) func() {
				dropMarker(t, st)
				return cov96bHoldTx(t, st.db)
			},
		},
		{
			name: "batch query fails",
			setup: func(t *testing.T, st *Store, _ *secrets.Cipher) func() {
				cov96bReplaceWithView(t, st, "sandbox_env", `SELECT sandbox_id FROM sandbox_env_cov96b_real`)
				return nil
			},
		},
		{
			name: "batch iteration fails",
			setup: func(t *testing.T, st *Store, cipher *secrets.Cipher) func() {
				seedLegacy(t, st, cipher, "inc-a")
				dropMarker(t, st)
				cov96bBreakRows(t, st, "sandbox_env")
				return nil
			},
		},
		{
			name: "orphan drop fails",
			setup: func(t *testing.T, st *Store, cipher *secrets.Cipher) func() {
				legacy, err := cipher.Encrypt([]byte(`{"K":"V"}`))
				if err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `PRAGMA foreign_keys = OFF`)
				if _, err := st.db.Exec(`INSERT INTO sandbox_env (sandbox_id, sealed_blob, created_at) VALUES ('ghost', ?, CURRENT_TIMESTAMP)`, legacy); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `PRAGMA foreign_keys = ON`)
				dropMarker(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "sandbox_env")
				return nil
			},
		},
		{
			name: "lifecycle read fails",
			setup: func(t *testing.T, st *Store, cipher *secrets.Cipher) func() {
				seedLegacy(t, st, cipher, "inc-a")
				dropMarker(t, st)
				cov96bReplaceWithView(t, st, "sandboxes", `SELECT id, NULL AS audit_incarnation_id FROM sandboxes_cov96b_real`)
				return nil
			},
		},
		{
			name: "row already bound is kept",
			setup: func(t *testing.T, st *Store, cipher *secrets.Cipher) func() {
				sb := testSandbox("a", nil)
				sb.AuditIncarnationID = "inc-a"
				bound, err := cipher.EncryptWithAAD([]byte(`{"K":"V"}`), secrets.EnvAAD("a", "inc-a"))
				if err != nil {
					t.Fatal(err)
				}
				if err := st.CreateWithSealedEnv(ctx, sb, bound); err != nil {
					t.Fatal(err)
				}
				dropMarker(t, st)
				return nil
			},
			wantOK: true,
		},
		{
			name: "rebind write fails",
			setup: func(t *testing.T, st *Store, cipher *secrets.Cipher) func() {
				seedLegacy(t, st, cipher, "inc-a")
				dropMarker(t, st)
				cov96bFailOn(t, st, "BEFORE UPDATE", "sandbox_env")
				return nil
			},
		},
		{
			name: "marker column add fails",
			setup: func(t *testing.T, st *Store, _ *secrets.Cipher) func() {
				cov96bReplaceWithView(t, st, "sandbox_env", `SELECT sandbox_id, sealed_blob FROM sandbox_env_cov96b_real WHERE 0`)
				return nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			cipher := cov96bCipher(t)
			cleanup := tc.setup(t, st, cipher)
			err := migrateEnvBinding(st.db, cipher)
			if cleanup != nil {
				cleanup()
			}
			if tc.wantOK != (err == nil) {
				t.Fatalf("migrateEnvBinding() error = %v, wantOK %v", err, tc.wantOK)
			}
		})
	}
}

func TestCov96bLegacySecretMigrationBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("closed db", func(t *testing.T) {
		db := cov96bClosedDB(t)
		if err := migrateLegacyPlaintextSecrets(db, nil); err == nil {
			t.Fatal("migrateLegacyPlaintextSecrets: expected error")
		}
		if _, err := inspectLegacySecretColumns(db); err == nil {
			t.Fatal("inspectLegacySecretColumns: expected error")
		}
		if err := migratePendingImageGCKey(db); err == nil {
			t.Fatal("migratePendingImageGCKey: expected error")
		}
	})

	addEnv := `ALTER TABLE sandboxes ADD COLUMN env_json TEXT NOT NULL DEFAULT '{}'`
	addToken := `ALTER TABLE sandboxes ADD COLUMN toolbox_token TEXT NOT NULL DEFAULT ''`
	storeCases := []struct {
		name    string
		setup   func(t *testing.T, st *Store) (cleanup func())
		wantMsg string
	}{
		{
			name: "begin fails",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addEnv)
				return cov96bHoldTx(t, st.db)
			},
			wantMsg: "begin legacy secret migration",
		},
		{
			name: "token already sealed",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addToken)
				sb := testSandbox("a", nil)
				sb.ToolboxTokenSealed = []byte("sealed")
				cov96bCreate(t, st, sb)
				cov96bExec(t, st.db, `UPDATE sandboxes SET toolbox_token = 'tok'`)
				return nil
			},
			wantMsg: "sealed value already exists",
		},
		{
			name: "env scrub fails",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addEnv)
				cov96bCreate(t, st, testSandbox("a", nil))
				cov96bFailOn(t, st, "BEFORE UPDATE", "sandboxes")
				return nil
			},
			wantMsg: "scrub legacy sandbox env",
		},
		{
			name: "env column drop fails",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addEnv, `CREATE INDEX cov96b_env_idx ON sandboxes(env_json)`)
				return nil
			},
			wantMsg: "drop legacy sandbox env column",
		},
		{
			name: "token scrub fails",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addToken)
				cov96bCreate(t, st, testSandbox("a", nil))
				cov96bFailOn(t, st, "BEFORE UPDATE", "sandboxes")
				return nil
			},
			wantMsg: "scrub legacy toolbox tokens",
		},
		{
			name: "token column drop fails",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addToken, `CREATE INDEX cov96b_token_idx ON sandboxes(toolbox_token)`)
				return nil
			},
			wantMsg: "drop legacy toolbox token column",
		},
		{
			name: "commit fails",
			setup: func(t *testing.T, st *Store) func() {
				cov96bExec(t, st.db, addEnv)
				cov96bCreate(t, st, testSandbox("a", nil))
				cov96bFailCommitOn(t, st, "AFTER UPDATE", "sandboxes")
				return nil
			},
			wantMsg: "commit legacy secret migration",
		},
	}
	for _, tc := range storeCases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			cleanup := tc.setup(t, st)
			err := migrateLegacyPlaintextSecrets(st.db, cov96bCipher(t))
			if cleanup != nil {
				cleanup()
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("migrateLegacyPlaintextSecrets() error = %v, want %q", err, tc.wantMsg)
			}
		})
	}

	failingView := `CREATE VIEW sandboxes AS SELECT 'a' AS id, '{}' AS env_json, 'tok' AS toolbox_token, X'' AS toolbox_token_sealed WHERE json_extract('not json', '$') IS NULL`
	rowCases := []struct {
		name   string
		schema []string
		run    func(tx *sql.Tx, cipher *secrets.Cipher) error
	}{
		{"env query fails", []string{`CREATE TABLE sandboxes (id TEXT)`}, cov96bEnvRows},
		{"env scan fails", []string{`CREATE TABLE sandboxes (id TEXT, env_json TEXT)`, `INSERT INTO sandboxes VALUES ('a', NULL)`}, cov96bEnvRows},
		{"env iteration fails", []string{failingView}, cov96bEnvRows},
		{"env lifecycle read fails", []string{`CREATE TABLE sandboxes (id TEXT, env_json TEXT)`, `INSERT INTO sandboxes VALUES ('a', '{"K":"V"}')`}, cov96bEnvRows},
		{"env store fails", []string{`CREATE TABLE sandboxes (id TEXT, env_json TEXT, audit_incarnation_id TEXT)`, `INSERT INTO sandboxes VALUES ('a', '{"K":"V"}', 'inc')`}, cov96bEnvRows},
		{"token query fails", []string{`CREATE TABLE sandboxes (id TEXT)`}, cov96bTokenRows},
		{"token scan fails", []string{`CREATE TABLE sandboxes (id TEXT, toolbox_token TEXT, toolbox_token_sealed BLOB)`, `INSERT INTO sandboxes VALUES ('a', NULL, X'')`}, cov96bTokenRows},
		{"token iteration fails", []string{failingView}, cov96bTokenRows},
		{"token store fails", []string{
			`CREATE TABLE sandboxes (id TEXT, toolbox_token TEXT, toolbox_token_sealed BLOB)`,
			`INSERT INTO sandboxes VALUES ('a', 'tok', X'')`,
			`CREATE TRIGGER cov96b_no_update BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cov96b injected failure'); END`,
		}, cov96bTokenRows},
	}
	for _, tc := range rowCases {
		t.Run(tc.name, func(t *testing.T) {
			db := cov96bRawDB(t)
			cov96bExec(t, db, tc.schema...)
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := tc.run(tx, cov96bCipher(t)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func cov96bEnvRows(tx *sql.Tx, cipher *secrets.Cipher) error {
	return migrateLegacyEnvRows(context.Background(), tx, cipher, time.Now().UTC())
}

func cov96bTokenRows(tx *sql.Tx, cipher *secrets.Cipher) error {
	return migrateLegacyToolboxTokenRows(context.Background(), tx, cipher)
}

func TestCov96bPendingImageGCKeyMigrationBranches(t *testing.T) {
	downgrade := func(t *testing.T, db *sql.DB) {
		t.Helper()
		cov96bExec(t, db,
			`DROP TABLE pending_image_gc`,
			`CREATE TABLE pending_image_gc (engine TEXT NOT NULL DEFAULT '', image TEXT PRIMARY KEY, scheduled_at DATETIME NOT NULL)`,
			`INSERT INTO pending_image_gc (image, scheduled_at) VALUES ('img', CURRENT_TIMESTAMP)`)
	}
	cases := []struct {
		name    string
		setup   func(t *testing.T, st *Store) (cleanup func())
		wantMsg string
	}{
		{
			name: "begin fails",
			setup: func(t *testing.T, st *Store) func() {
				downgrade(t, st.db)
				return cov96bHoldTx(t, st.db)
			},
			wantMsg: "begin pending_image_gc key migration",
		},
		{
			name: "rebuild statement fails",
			setup: func(t *testing.T, st *Store) func() {
				downgrade(t, st.db)
				cov96bExec(t, st.db, `CREATE TABLE pending_image_gc_rekeyed (x)`)
				return nil
			},
			wantMsg: "migrate pending_image_gc key",
		},
		{
			// Dropping the old table orphans a deferred child reference, which
			// only surfaces at COMMIT.
			name: "commit fails",
			setup: func(t *testing.T, st *Store) func() {
				downgrade(t, st.db)
				cov96bExec(t, st.db,
					`CREATE TABLE cov96b_gc_child (image TEXT REFERENCES pending_image_gc(image) DEFERRABLE INITIALLY DEFERRED)`,
					`INSERT INTO cov96b_gc_child VALUES ('img')`)
				return nil
			},
			wantMsg: "commit pending_image_gc key migration",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			cleanup := tc.setup(t, st)
			err := migratePendingImageGCKey(st.db)
			if cleanup != nil {
				cleanup()
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("migratePendingImageGCKey() error = %v, want %q", err, tc.wantMsg)
			}
		})
	}

	t.Run("open surfaces failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.db")
		st, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		downgrade(t, st.db)
		cov96bExec(t, st.db, `CREATE TABLE pending_image_gc_rekeyed (x)`)
		_ = st.Close()
		if reopened, err := Open(path); err == nil {
			_ = reopened.Close()
			t.Fatal("Open() succeeded over a blocked pending_image_gc rebuild")
		}
	})
}

func TestCov96bOpenChmodDirectoryFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root user on a POSIX host so chmod of a root-owned directory is refused")
	}
	// /dev exists and is root-owned, so MkdirAll is a no-op and Chmod fails
	// with EPERM before anything is opened or created.
	if st, err := Open("/dev/cov96b-never-created.db"); err == nil {
		_ = st.Close()
		t.Fatal("Open() succeeded with an un-chmoddable directory")
	} else if !strings.Contains(err.Error(), "chmod db directory") {
		t.Fatalf("Open() error = %v, want chmod db directory", err)
	}
}

func cov96bIndexChunk(t *testing.T, offsets ...int64) SecretAuditIndexChunk {
	t.Helper()
	entries := make([]auditlog.IndexEntry, 0, len(offsets))
	for _, off := range offsets {
		entries = append(entries, auditlog.IndexEntry{Offset: off, Length: 5, TimeNano: 100 + off})
	}
	c, err := NewSecretAuditIndexChunk(SecretAuditIndexKey{SandboxID: "sb", IncarnationID: "inc"}, 1, entries)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCov96bSecretAuditIndexChunkEdges(t *testing.T) {
	key := SecretAuditIndexKey{SandboxID: "sb"}
	if _, err := NewSecretAuditIndexChunk(key, 1, []auditlog.IndexEntry{
		{Offset: 10, Length: 5},
		{Offset: 5, Length: 5},
	}); err == nil {
		t.Fatal("NewSecretAuditIndexChunk accepted an entry before the chunk base")
	}
	c := cov96bIndexChunk(t, 0, 10)
	before := c
	if err := c.Append(nil); err != nil {
		t.Fatalf("Append(nil) = %v", err)
	}
	if c.N != before.N || c.LastOffset != before.LastOffset {
		t.Fatalf("Append(nil) changed the chunk: %+v -> %+v", before, c)
	}
}

func TestCov96bSecretAuditIndexStoreFailures(t *testing.T) {
	ctx := context.Background()
	key := SecretAuditIndexKey{SandboxID: "sb", IncarnationID: "inc"}
	meta := SecretAuditIndexMeta{Generation: "g"}
	reset := func(t *testing.T, st *Store) {
		t.Helper()
		if err := st.ResetSecretAuditIndex(ctx, meta); err != nil {
			t.Fatal(err)
		}
	}
	writeChunk := func(t *testing.T, st *Store, c SecretAuditIndexChunk) {
		t.Helper()
		if err := st.WriteSecretAuditIndex(ctx, meta, meta, []SecretAuditIndexChunk{c}); err != nil {
			t.Fatal(err)
		}
	}
	badNRow := `INSERT INTO secret_audit_index VALUES ('sb', 'inc', 1, 0, 10, 0, 200, 200, 'x', X'00')`
	viewDelete := `CREATE TRIGGER cov96b_view_delete INSTEAD OF DELETE ON secret_audit_index BEGIN SELECT 1; END`
	shift := func(st *Store) error { return st.ShiftSecretAuditIndex(ctx, 5, 1, meta) }
	write := func(st *Store) error {
		return st.WriteSecretAuditIndex(ctx, meta, meta, []SecretAuditIndexChunk{cov96bIndexChunk(t, 0, 10)})
	}
	metaFails := func(t *testing.T, st *Store) {
		reset(t, st)
		cov96bFailOn(t, st, "BEFORE INSERT", "secret_audit_index_meta")
		cov96bFailOn(t, st, "BEFORE UPDATE", "secret_audit_index_meta")
	}
	metaCommitFails := func(t *testing.T, st *Store) {
		reset(t, st)
		cov96bFailCommitOn(t, st, "AFTER INSERT", "secret_audit_index_meta")
		cov96bFailCommitOn(t, st, "AFTER UPDATE", "secret_audit_index_meta")
	}

	runCov96bCases(t, []cov96bCase{
		{
			name:  "reset meta write fails",
			setup: func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "secret_audit_index_meta") },
			call:  func(st *Store) error { return st.ResetSecretAuditIndex(ctx, meta) },
		},
		{
			name: "reset delete fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				writeChunk(t, st, cov96bIndexChunk(t, 0, 10))
				cov96bFailOn(t, st, "BEFORE DELETE", "secret_audit_index")
			},
			call: func(st *Store) error { return st.ResetSecretAuditIndex(ctx, meta) },
		},
		{
			name:  "reset commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "secret_audit_index_meta") },
			call:  func(st *Store) error { return st.ResetSecretAuditIndex(ctx, meta) },
		},
		{
			name:  "latest chunk scan fails",
			setup: func(t *testing.T, st *Store) { cov96bExec(t, st.db, badNRow) },
			call: func(st *Store) error {
				_, err := st.LatestSecretAuditIndexChunks(ctx, []SecretAuditIndexKey{key})
				return err
			},
		},
		{
			name: "write meta read fails",
			setup: func(t *testing.T, st *Store) {
				cov96bExec(t, st.db, `INSERT INTO secret_audit_index_meta (id, generation, updated_at) VALUES (1, 'g', X'00')`)
			},
			call: func(st *Store) error { return st.WriteSecretAuditIndex(ctx, meta, meta, nil) },
		},
		{
			name: "write prepare fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bReplaceWithView(t, st, "secret_audit_index", `SELECT * FROM secret_audit_index_cov96b_real`)
			},
			call: write,
		},
		{
			name: "write chunk fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bFailOn(t, st, "BEFORE INSERT", "secret_audit_index")
			},
			call: write,
		},
		{
			name:  "write meta fails",
			setup: metaFails,
			call:  func(st *Store) error { return st.WriteSecretAuditIndex(ctx, meta, meta, nil) },
		},
		{
			name:  "write commit fails",
			setup: metaCommitFails,
			call:  func(st *Store) error { return st.WriteSecretAuditIndex(ctx, meta, meta, nil) },
		},
		{
			name: "read query fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bExec(t, st.db, `DROP TABLE secret_audit_index`)
			},
			call: func(st *Store) error {
				_, _, _, err := st.ReadSecretAuditIndex(ctx, key, 0)
				return err
			},
		},
		{
			name: "read scan fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bExec(t, st.db, badNRow)
			},
			call: func(st *Store) error {
				_, _, _, err := st.ReadSecretAuditIndex(ctx, key, 0)
				return err
			},
		},
		{
			name: "read iteration fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bBreakRows(t, st, "secret_audit_index")
			},
			call: func(st *Store) error {
				_, _, _, err := st.ReadSecretAuditIndex(ctx, key, 0)
				return err
			},
		},
		{
			name: "shift prune fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				writeChunk(t, st, cov96bIndexChunk(t, 0))
				cov96bFailOn(t, st, "BEFORE DELETE", "secret_audit_index")
			},
			call: shift,
		},
		{
			name: "shift straddle query fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bReplaceWithView(t, st, "secret_audit_index", `SELECT last_offset FROM secret_audit_index_cov96b_real`)
				cov96bExec(t, st.db, viewDelete)
			},
			call: shift,
		},
		{
			name: "shift straddle scan fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				cov96bExec(t, st.db, badNRow)
			},
			call: shift,
		},
		{
			name: "shift straddle iteration fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				writeChunk(t, st, cov96bIndexChunk(t, 0, 10))
				cov96bReplaceWithView(t, st, "secret_audit_index", `
					SELECT sandbox_id, incarnation_id, chunk_seq, first_offset, last_offset, min_time, max_time, last_time,
						json_extract('not json', '$') AS n, entries
					FROM secret_audit_index_cov96b_real`)
				cov96bExec(t, st.db, viewDelete)
			},
			call: shift,
		},
		{
			name: "shift re-encode fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				// Decodes fine, but the surviving entry's length overflows to
				// a negative int64 that the encoder refuses.
				var blob []byte
				blob = binary.AppendUvarint(blob, 0)
				blob = binary.AppendUvarint(blob, 5)
				blob = binary.AppendVarint(blob, 0)
				blob = append(blob, 0)
				blob = binary.AppendUvarint(blob, 10)
				blob = binary.AppendUvarint(blob, 1<<63)
				blob = binary.AppendVarint(blob, 0)
				blob = append(blob, 0)
				if _, err := st.db.Exec(`INSERT INTO secret_audit_index VALUES ('sb', 'inc', 1, 0, 10, 0, 0, 0, 2, ?)`, blob); err != nil {
					t.Fatal(err)
				}
			},
			call: shift,
		},
		{
			name: "shift trim write fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				writeChunk(t, st, cov96bIndexChunk(t, 0, 10))
				cov96bFailOn(t, st, "BEFORE UPDATE", "secret_audit_index")
			},
			call: shift,
		},
		{
			name: "shift offsets update fails",
			setup: func(t *testing.T, st *Store) {
				reset(t, st)
				writeChunk(t, st, cov96bIndexChunk(t, 10, 20))
				cov96bFailOn(t, st, "BEFORE UPDATE", "secret_audit_index")
			},
			call: shift,
		},
		{name: "shift meta fails", setup: metaFails, call: shift},
		{name: "shift commit fails", setup: metaCommitFails, call: shift},
	})
}

func TestCov96bSandboxStoreFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	sandboxA := func() *models.Sandbox { return testSandbox("a", nil) }
	withA := func(t *testing.T, st *Store) { cov96bCreate(t, st, sandboxA()) }
	auditView := `SELECT id, NULL AS audit_incarnation_id FROM sandboxes_cov96b_real`
	claim := func(at time.Time) func(st *Store) error {
		return func(st *Store) error {
			_, _, err := st.ClaimIdempotentRequest(ctx, "scope", "fp", at, time.Minute)
			return err
		}
	}
	claimFirst := func(t *testing.T, st *Store) {
		t.Helper()
		if err := claim(now)(st); err != nil {
			t.Fatal(err)
		}
	}

	runCov96bCases(t, []cov96bCase{
		{
			name:  "create env row fails",
			setup: func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "sandbox_env") },
			call:  func(st *Store) error { return st.Create(ctx, sandboxA()) },
		},
		{
			name:  "create commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "sandbox_env") },
			call:  func(st *Store) error { return st.Create(ctx, sandboxA()) },
		},
		{
			name:  "create with sealed env commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "sandbox_env") },
			call:  func(st *Store) error { return st.CreateWithSealedEnv(ctx, sandboxA(), []byte("sealed")) },
		},
		{
			name:  "upsert env row fails",
			setup: func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "sandbox_env") },
			call:  func(st *Store) error { return st.Upsert(ctx, sandboxA()) },
		},
		{
			name:  "upsert commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "sandbox_env") },
			call: func(st *Store) error {
				sb := sandboxA()
				sb.AuditIncarnationID = "inc"
				return st.Upsert(ctx, sb)
			},
		},
		{
			name:  "list iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandboxes") },
			call:  func(st *Store) error { _, err := st.List(ctx); return err },
		},
		{
			name:  "list by owner iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandboxes") },
			call:  func(st *Store) error { _, err := st.ListByOwner(ctx, "owner"); return err },
		},
		{
			name:  "list by runtime iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandboxes") },
			call:  func(st *Store) error { _, err := st.ListByRuntime(ctx, "docker"); return err },
		},
		{
			name: "list ports iteration fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bBreakRows(t, st, "exposed_ports")
			},
			call: func(st *Store) error { _, err := st.List(ctx); return err },
		},
		{
			name: "list custom domains iteration fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bBreakRows(t, st, "sandbox_custom_domains")
			},
			call: func(st *Store) error { _, err := st.List(ctx); return err },
		},
		{
			name: "get ports iteration fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bBreakRows(t, st, "exposed_ports")
			},
			call: func(st *Store) error { _, err := st.Get(ctx, "a"); return err },
		},
		{
			name:  "all exposed ports iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "exposed_ports") },
			call:  func(st *Store) error { _, err := st.ListAllExposedPorts(ctx); return err },
		},
		{
			name:  "custom domains iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandbox_custom_domains") },
			call:  func(st *Store) error { _, err := st.ListCustomDomains(ctx, "a"); return err },
		},
		{
			name:  "all custom domains iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandbox_custom_domains") },
			call:  func(st *Store) error { _, err := st.ListAllCustomDomains(ctx); return err },
		},
		{
			name: "custom domain disambiguation scan fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				if err := st.AddCustomDomain(ctx, "a", "cov.example.com", 80); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `UPDATE sandbox_custom_domains SET target_port = 'x'`)
			},
			call: func(st *Store) error { return st.AddCustomDomain(ctx, "a", "cov.example.com", 80) },
		},
		{
			name:  "host port reservation insert fails",
			setup: func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "exposed_ports") },
			call: func(st *Store) error {
				_, err := st.TryReserveHostPort(ctx, "a", 80, 30080, "tcp", "tcp://cov", now)
				return err
			},
		},
		{
			name: "pending image gc scan fails",
			setup: func(t *testing.T, st *Store) {
				if err := st.SchedulePendingImageGC(ctx, "", "img", now.Add(-time.Hour)); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `UPDATE pending_image_gc SET scheduled_at = 1.5`)
			},
			call: func(st *Store) error { _, err := st.ListPendingImageGCDue(ctx, now, 0); return err },
		},
		{
			name:  "pending image gc iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "pending_image_gc") },
			call:  func(st *Store) error { _, err := st.ListPendingImageGCDue(ctx, now, 10); return err },
		},
		{
			name: "auto import id scan fails",
			setup: func(t *testing.T, st *Store) {
				cov96bReplaceWithView(t, st, "sandboxes", `SELECT NULL AS id, 1 AS auto_import_pending, 0 AS updated_at`)
			},
			call: func(st *Store) error { _, err := st.ListAutoImportPendingIDs(ctx); return err },
		},
		{
			name: "create rollback commit fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bFailCommitOn(t, st, "AFTER DELETE", "sandboxes")
			},
			call: func(st *Store) error { return st.RollbackSandboxCreate(ctx, "a", "inc") },
		},
		{
			name:  "compat state iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandbox_compat_state") },
			call:  func(st *Store) error { _, err := st.ListCompatState(ctx, "daytona"); return err },
		},
		{
			name:  "snapshot aliases iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "snapshot_aliases") },
			call:  func(st *Store) error { _, err := st.ListSnapshotAliases(ctx, ""); return err },
		},
		{
			name:  "snapshot aliases by facade iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "snapshot_aliases") },
			call:  func(st *Store) error { _, err := st.ListSnapshotAliases(ctx, "daytona"); return err },
		},
		{
			name:  "snapshots iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandbox_snapshots") },
			call:  func(st *Store) error { _, err := st.ListSnapshots(ctx); return err },
		},
		{
			name:  "snapshots pending push iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "sandbox_snapshots") },
			call:  func(st *Store) error { _, err := st.ListSnapshotsPendingPush(ctx); return err },
		},
		{
			name:  "templates iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_templates") },
			call:  func(st *Store) error { _, err := st.ListTemplates(ctx); return err },
		},
		{
			name:  "templates pending push iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_templates") },
			call:  func(st *Store) error { _, err := st.ListTemplatesPendingPush(ctx); return err },
		},
		{
			name:  "unhealthy templates iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_templates") },
			call:  func(st *Store) error { _, err := st.ListUnhealthyTemplates(ctx); return err },
		},
		{
			name:  "templates ready before iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_templates") },
			call:  func(st *Store) error { _, err := st.ListTemplatesReadyBefore(ctx, now); return err },
		},
		{
			name:  "gc eligible templates iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_templates") },
			call:  func(st *Store) error { _, err := st.ListGCEligibleTemplates(ctx, now); return err },
		},
		{
			name: "template inventory scan fails",
			setup: func(t *testing.T, st *Store) {
				cov96bReplaceWithView(t, st, "firecracker_templates", `SELECT 'tpl' AS id, NULL AS status`)
			},
			call: func(st *Store) error { _, _, err := st.ListTemplateInventoryIDs(ctx); return err },
		},
		{
			name:  "template inventory iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_templates") },
			call:  func(st *Store) error { _, _, err := st.ListTemplateInventoryIDs(ctx); return err },
		},
		{
			name: "audit acl live incarnation read fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bReplaceWithView(t, st, "sandboxes", auditView)
			},
			call: func(st *Store) error { return st.UpsertSandboxAuditACL(ctx, "a", "owner", "inc") },
		},
		{
			name: "audit acl write fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bFailOn(t, st, "BEFORE INSERT", "sandbox_audit_acl")
			},
			call: func(st *Store) error { return st.UpsertSandboxAuditACL(ctx, "a", "owner", "inc") },
		},
		{
			name: "audit acl commit fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bFailCommitOn(t, st, "AFTER INSERT", "sandbox_audit_acl")
			},
			call: func(st *Store) error { return st.UpsertSandboxAuditACL(ctx, "a", "owner", "inc") },
		},
		{
			name: "audit incarnations scan fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bReplaceWithView(t, st, "sandboxes", auditView)
			},
			call: func(st *Store) error { _, err := st.SandboxAuditIncarnations(ctx, []string{"a"}); return err },
		},
		{
			name: "audit incarnations iteration fails",
			setup: func(t *testing.T, st *Store) {
				withA(t, st)
				cov96bBreakRows(t, st, "sandboxes")
			},
			call: func(st *Store) error { _, err := st.SandboxAuditIncarnations(ctx, []string{"a"}); return err },
		},
		{
			name:  "idempotency claim insert commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "request_idempotency") },
			call:  claim(now),
		},
		{
			name: "idempotency row missing after conflict",
			setup: func(t *testing.T, st *Store) {
				cov96bExec(t, st.db, `CREATE TRIGGER cov96b_ignore BEFORE INSERT ON request_idempotency BEGIN SELECT RAISE(IGNORE); END`)
			},
			call: claim(now),
		},
		{
			name: "idempotency ready replay commit fails",
			setup: func(t *testing.T, st *Store) {
				claimFirst(t, st)
				if _, err := st.db.Exec(`UPDATE request_idempotency SET state = ?, target_id = 'target', replay_until = ?`,
					models.RequestStateReady, now.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				cov96bFailCommitOn(t, st, "BEFORE INSERT", "request_idempotency")
			},
			call: claim(now),
		},
		{
			name: "idempotency pending commit fails",
			setup: func(t *testing.T, st *Store) {
				claimFirst(t, st)
				cov96bFailCommitOn(t, st, "BEFORE INSERT", "request_idempotency")
			},
			call: claim(now),
		},
		{
			name: "idempotency refresh commit fails",
			setup: func(t *testing.T, st *Store) {
				claimFirst(t, st)
				cov96bFailCommitOn(t, st, "BEFORE INSERT", "request_idempotency")
			},
			call: claim(now.Add(time.Hour)),
		},
		{
			name: "env identity for missing sandbox is not found",
			call: func(st *Store) error {
				if _, _, _, _, err := st.GetEnvWithIdentity(ctx, "missing"); !errors.Is(err, ErrNotFound) {
					return fmt.Errorf("GetEnvWithIdentity(missing) = %v, want ErrNotFound", err)
				}
				return nil
			},
			wantOK: true,
		},
	})
}

func cov96bSecretRecord(gen int64) ClusterSecretRecord {
	return ClusterSecretRecord{
		Ref:            secrets.FormatRef("sb", "inc", secrets.RefVersion),
		SandboxID:      "sb",
		Version:        secrets.RefVersion,
		Recipients:     []string{"n1"},
		SealedPayload:  []byte("payload"),
		SealGeneration: gen,
	}
}

func TestCov96bClusterSecretFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	ref := secrets.FormatRef("sb", "inc", secrets.RefVersion)
	put := func(t *testing.T, st *Store, rec ClusterSecretRecord) {
		t.Helper()
		if _, err := st.PutClusterSecret(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	withSecret := func(t *testing.T, st *Store) { put(t, st, cov96bSecretRecord(1)) }
	withDeleteOutbox := func(t *testing.T, st *Store) {
		t.Helper()
		if err := st.UpsertSecretDeleteOutbox(ctx, "sb", "inc", []string{"n1"}, 1); err != nil {
			t.Fatal(err)
		}
	}
	withPutOutbox := func(t *testing.T, st *Store) {
		t.Helper()
		if err := st.UpsertSecretPutOutbox(ctx, "sb", "inc", 1, []string{"n1"}); err != nil {
			t.Fatal(err)
		}
	}
	withBadProvenance := func(t *testing.T, st *Store) {
		withDeleteOutbox(t, st)
		cov96bExec(t, st.db, `UPDATE cluster_secret_delete_outbox SET recipient_provenance_json = 'not json'`)
	}
	inTx := func(st *Store, fn func(tx *sql.Tx) error) error {
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return fn(tx)
	}
	updateRecipients := func(recipients []string) func(st *Store) error {
		return func(st *Store) error {
			return st.UpdateSecretDeleteOutboxRecipients(ctx, "sb", "inc", recipients, 1)
		}
	}
	peerDelete := func(st *Store) error { return st.ApplyPeerSecretDelete(ctx, "sb", "inc", 1) }
	originatorDelete := func(st *Store) error {
		_, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb", "inc", []string{"n1"})
		return err
	}

	runCov96bCases(t, []cov96bCase{
		{
			name: "put same generation commit fails",
			setup: func(t *testing.T, st *Store) {
				withSecret(t, st)
				cov96bFailCommitOn(t, st, "AFTER INSERT", "cluster_secret_put_outbox")
			},
			call: func(st *Store) error {
				rec := cov96bSecretRecord(1)
				peers := []string{"n2"}
				rec.PutOutboxRecipients = &peers
				rec.PutOutboxIncarnationID = "inc"
				_, err := st.PutClusterSecret(ctx, rec)
				return err
			},
		},
		{
			name:  "put new generation commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "cluster_secrets") },
			call:  func(st *Store) error { _, err := st.PutClusterSecret(ctx, cov96bSecretRecord(1)); return err },
		},
		{
			name: "put stale outbox clear fails",
			setup: func(t *testing.T, st *Store) {
				withPutOutbox(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secret_put_outbox")
			},
			call: func(st *Store) error {
				rec := cov96bSecretRecord(2)
				peers := []string{"n2"}
				rec.PutOutboxRecipients = &peers
				rec.PutOutboxIncarnationID = "inc"
				_, err := st.PutClusterSecret(ctx, rec)
				return err
			},
		},
		{
			name: "originator delete copy provenance fails",
			setup: func(t *testing.T, st *Store) {
				withSecret(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secrets SET updated_at = X'00'`)
			},
			call: originatorDelete,
		},
		{name: "originator delete outbox merge fails", setup: withBadProvenance, call: originatorDelete},
		{
			name:  "originator delete commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "cluster_secret_tombs") },
			call:  originatorDelete,
		},
		{
			name: "delete outbox upsert commit fails",
			setup: func(t *testing.T, st *Store) {
				cov96bFailCommitOn(t, st, "AFTER INSERT", "cluster_secret_delete_outbox")
			},
			call: func(st *Store) error {
				return st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb", "inc", []string{"n1"}, 1, now)
			},
		},
		{
			name: "delete outbox merge read fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secret_delete_outbox SET created_at = X'00'`)
			},
			call: func(st *Store) error { return st.UpsertSecretDeleteOutbox(ctx, "sb", "inc", []string{"n1"}, 1) },
		},
		{
			name: "delete outbox copy provenance fails",
			setup: func(t *testing.T, st *Store) {
				withSecret(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secrets SET updated_at = X'00'`)
			},
			call: func(st *Store) error { return st.UpsertSecretDeleteOutbox(ctx, "sb", "inc", []string{"n1"}, 1) },
		},
		{
			name:  "delete outbox provenance merge fails",
			setup: withBadProvenance,
			call: func(st *Store) error {
				return st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb", "inc", []string{"n2"}, 1, now)
			},
		},
		{
			name: "delete outbox obsolete clear fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secret_delete_outbox")
			},
			call: func(st *Store) error {
				return inTx(st, func(tx *sql.Tx) error {
					return upsertSecretDeleteOutboxTx(ctx, tx, "sb", "inc", []string{"n1"}, []string{"n1"}, 2, true, now)
				})
			},
		},
		{
			name: "delete outbox generation must be positive",
			call: func(st *Store) error {
				return inTx(st, func(tx *sql.Tx) error {
					return upsertSecretDeleteOutboxTx(ctx, tx, "sb", "inc", []string{"n1"}, nil, 0, false, now)
				})
			},
		},
		{
			name:  "delete outbox read decodes bad provenance",
			setup: withBadProvenance,
			call: func(st *Store) error {
				_, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb", "inc")
				return err
			},
		},
		{
			name: "update recipients clear fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secret_delete_outbox")
			},
			call: updateRecipients(nil),
		},
		{
			name: "update recipients of missing job is a no-op",
			call: func(st *Store) error {
				return st.UpdateSecretDeleteOutboxRecipients(ctx, "ghost", "inc", []string{"n1"}, 1)
			},
			wantOK: true,
		},
		{
			name: "update recipients provenance read fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bReplaceWithView(t, st, "cluster_secret_delete_outbox", `
					SELECT sandbox_id, incarnation_id, generation, NULL AS recipient_provenance_json
					FROM cluster_secret_delete_outbox_cov96b_real`)
			},
			call: updateRecipients([]string{"n1"}),
		},
		{name: "update recipients provenance decode fails", setup: withBadProvenance, call: updateRecipients([]string{"n1"})},
		{
			name: "update recipients write fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bFailOn(t, st, "BEFORE UPDATE", "cluster_secret_delete_outbox")
			},
			call: updateRecipients([]string{"n1"}),
		},
		{
			name: "update recipients commit fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bFailCommitOn(t, st, "AFTER UPDATE", "cluster_secret_delete_outbox")
			},
			call: updateRecipients([]string{"n1"}),
		},
		{
			name:  "peer delete tomb fails",
			setup: func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "cluster_secret_tombs") },
			call:  peerDelete,
		},
		{
			name: "peer delete sealed row fails",
			setup: func(t *testing.T, st *Store) {
				withSecret(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secrets")
			},
			call: peerDelete,
		},
		{
			name: "peer delete put outbox fails",
			setup: func(t *testing.T, st *Store) {
				withPutOutbox(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secret_put_outbox")
			},
			call: peerDelete,
		},
		{
			name:  "peer delete commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "cluster_secret_tombs") },
			call:  peerDelete,
		},
		{
			name: "seal summaries scan fails",
			setup: func(t *testing.T, st *Store) {
				withSecret(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secrets SET seal_generation = 'x'`)
			},
			call: func(st *Store) error { _, err := st.ClusterSecretSealSummaries(ctx, []string{ref}); return err },
		},
		{
			name:  "seal summaries iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "cluster_secrets") },
			call:  func(st *Store) error { _, err := st.ClusterSecretSealSummaries(ctx, []string{ref}); return err },
		},
		{
			name: "owed recipients scan fails",
			setup: func(t *testing.T, st *Store) {
				cov96bReplaceWithView(t, st, "cluster_secret_delete_outbox", `SELECT NULL AS recipients_json`)
			},
			call: func(st *Store) error { _, err := st.SecretDeleteOwedByRecipient(ctx); return err },
		},
		{
			name: "owed recipients skips blanks and duplicates",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secret_delete_outbox SET recipients_json = '["", " n1 ", "n1"]'`)
			},
			call: func(st *Store) error {
				owed, err := st.SecretDeleteOwedByRecipient(ctx)
				if err != nil {
					return err
				}
				if len(owed) != 1 || owed["n1"] != 1 {
					return fmt.Errorf("owed = %v, want map[n1:1]", owed)
				}
				return nil
			},
			wantOK: true,
		},
		{
			name:  "owed recipients iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "cluster_secret_delete_outbox") },
			call:  func(st *Store) error { _, err := st.SecretDeleteOwedByRecipient(ctx); return err },
		},
		{
			name: "list delete outbox scan fails",
			setup: func(t *testing.T, st *Store) {
				withDeleteOutbox(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secret_delete_outbox SET created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.ListSecretDeleteOutboxBatch(ctx, 10); return err },
		},
		{
			name:  "list delete outbox provenance fails",
			setup: withBadProvenance,
			call:  func(st *Store) error { _, err := st.ListSecretDeleteOutboxBatch(ctx, 10); return err },
		},
		{
			name: "retry delete outbox generation must be positive",
			call: func(st *Store) error { return st.retrySecretDeleteOutbox(ctx, "sb", "inc", 0, false) },
		},
		{
			name: "delete delete outbox generation must be positive",
			call: func(st *Store) error { return st.DeleteSecretDeleteOutbox(ctx, "sb", "inc", 0) },
		},
		{
			name: "put outbox existing read fails",
			setup: func(t *testing.T, st *Store) {
				withPutOutbox(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secret_put_outbox SET seal_generation = 'x'`)
			},
			call: func(st *Store) error { return st.UpsertSecretPutOutbox(ctx, "sb", "inc", 2, []string{"n1"}) },
		},
		{
			name: "put outbox stale clear fails",
			setup: func(t *testing.T, st *Store) {
				withPutOutbox(t, st)
				cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secret_put_outbox")
			},
			call: func(st *Store) error { return st.UpsertSecretPutOutbox(ctx, "sb", "inc", 2, []string{"n1"}) },
		},
		{
			name:  "put outbox insert fails",
			setup: func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "cluster_secret_put_outbox") },
			call:  func(st *Store) error { return st.UpsertSecretPutOutbox(ctx, "sb", "inc", 1, []string{"n1"}) },
		},
		{
			name:  "put outbox commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "cluster_secret_put_outbox") },
			call:  func(st *Store) error { return st.UpsertSecretPutOutbox(ctx, "sb", "inc", 1, []string{"n1"}) },
		},
		{
			name: "list put outbox scan fails",
			setup: func(t *testing.T, st *Store) {
				withPutOutbox(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secret_put_outbox SET created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.ListSecretPutOutboxBatch(ctx, 10); return err },
		},
		{
			name: "lifecycle stats reject unparsable put outbox time",
			setup: func(t *testing.T, st *Store) {
				withPutOutbox(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secret_put_outbox SET created_at = 'not a time'`)
			},
			call: func(st *Store) error { _, err := st.SecretLifecycleStats(ctx); return err },
		},
		{
			name: "cluster secret batch scan fails",
			setup: func(t *testing.T, st *Store) {
				withSecret(t, st)
				cov96bExec(t, st.db, `UPDATE cluster_secrets SET created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.ListClusterSecretsBatch(ctx, "", 10); return err },
		},
		{
			name:  "cluster secret batch iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "cluster_secrets") },
			call:  func(st *Store) error { _, err := st.ListClusterSecretsBatch(ctx, "", 10); return err },
		},
	})
}

func TestCov96bPoolAndWasmFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	seedTap := func(t *testing.T, st *Store, name string, cid uint32) {
		t.Helper()
		if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
			TapName: name, CIDR: "10.9.0.0/30", HostIP: "10.9.0.1", GuestIP: "10.9.0.2", VsockCID: cid,
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	loadedVMM := func(t *testing.T, st *Store) {
		t.Helper()
		if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "vmm-1", TemplateID: "tpl"}, now); err != nil {
			t.Fatal(err)
		}
		if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "vmm-1", "/run/api.sock", "/run/vmm-1", 9, now); err != nil {
			t.Fatal(err)
		}
	}
	allocateVMM := func(st *Store) error { _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl", "sb", now); return err }

	runCov96bCases(t, []cov96bCase{
		{
			name: "netns reserve candidate scan fails",
			setup: func(t *testing.T, st *Store) {
				if err := st.SeedContainerNetnsSlot(ctx, "slot-1", now); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `UPDATE container_netns_slots SET created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.ReserveContainerNetnsSlot(ctx, "sb", now); return err },
		},
		{
			name: "netns claim pooled candidate scan fails",
			setup: func(t *testing.T, st *Store) {
				if err := st.SeedContainerNetnsSlot(ctx, "slot-1", now); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `UPDATE container_netns_slots SET state = 'pooled', created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb", now); return err },
		},
		{
			name: "tap allocate candidate scan fails",
			setup: func(t *testing.T, st *Store) {
				seedTap(t, st, "tap-a", 8)
				cov96bExec(t, st.db, `UPDATE firecracker_tap_pool SET created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.AllocateFirecrackerTapSlot(ctx, "sb", now); return err },
		},
		{
			name: "tap transfer source read fails",
			setup: func(t *testing.T, st *Store) {
				seedTap(t, st, "tap-a", 8)
				if _, err := st.AllocateFirecrackerTapSlot(ctx, "from", now); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `UPDATE firecracker_tap_pool SET created_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.TransferFirecrackerTapSlot(ctx, "from", "to", now); return err },
		},
		{
			name: "tap transfer re-read after lost update fails",
			setup: func(t *testing.T, st *Store) {
				seedTap(t, st, "tap-a", 8)
				seedTap(t, st, "tap-b", 9)
				if _, err := st.AllocateFirecrackerTapSlot(ctx, "from", now); err != nil {
					t.Fatal(err)
				}
				// Between the reads and the UPDATE, the source moves away and
				// an unreadable row appears under the target id.
				afterTransferTapReads = func() {
					_, _ = st.db.Exec(`UPDATE firecracker_tap_pool SET sandbox_id = 'elsewhere' WHERE sandbox_id = 'from'`)
					_, _ = st.db.Exec(`UPDATE firecracker_tap_pool SET sandbox_id = 'to', created_at = X'00' WHERE sandbox_id IS NULL`)
				}
				t.Cleanup(func() { afterTransferTapReads = nil })
			},
			call: func(st *Store) error { _, err := st.TransferFirecrackerTapSlot(ctx, "from", "to", now); return err },
		},
		{
			name: "vmm allocate candidate scan fails",
			setup: func(t *testing.T, st *Store) {
				loadedVMM(t, st)
				cov96bExec(t, st.db, `UPDATE firecracker_vmm_pool SET created_at = X'00'`)
			},
			call: allocateVMM,
		},
		{
			name: "vmm allocate claim fails",
			setup: func(t *testing.T, st *Store) {
				loadedVMM(t, st)
				cov96bFailOn(t, st, "BEFORE UPDATE", "firecracker_vmm_pool")
			},
			call: allocateVMM,
		},
		{
			name: "vmm released_at is scanned",
			setup: func(t *testing.T, st *Store) {
				loadedVMM(t, st)
				if err := allocateVMM(st); err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.Exec(`UPDATE firecracker_vmm_pool SET released_at = ?`, now); err != nil {
					t.Fatal(err)
				}
			},
			call: func(st *Store) error {
				slot, err := st.GetFirecrackerVMMSlotBySandbox(ctx, "sb")
				if err != nil {
					return err
				}
				if slot == nil || slot.ReleasedAt.IsZero() {
					return fmt.Errorf("slot = %+v, want non-zero ReleasedAt", slot)
				}
				return nil
			},
			wantOK: true,
		},
		{
			name: "vmm pool stats scan fails",
			setup: func(t *testing.T, st *Store) {
				cov96bReplaceWithView(t, st, "firecracker_vmm_pool", `SELECT 'tpl' AS template_id, NULL AS status`)
			},
			call: func(st *Store) error { _, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl"); return err },
		},
		{
			name:  "vmm pool stats iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_vmm_pool") },
			call:  func(st *Store) error { _, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl"); return err },
		},
		{
			name:  "vmm refill list iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "firecracker_vmm_pool") },
			call:  func(st *Store) error { _, err := st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl"); return err },
		},
		{
			name: "wasm kv key scan fails",
			setup: func(t *testing.T, st *Store) {
				cov96bReplaceWithView(t, st, "wasm_state_kv", `SELECT 'sb' AS sandbox_id, NULL AS key`)
			},
			call: func(st *Store) error { _, err := st.ListWasmStateKVKeys(ctx, "sb"); return err },
		},
		{
			name: "wasm cleanup ref lookup fails",
			setup: func(t *testing.T, st *Store) {
				// The INSERT is swallowed by an INSTEAD OF trigger, so the
				// follow-up lookup of the "existing" row finds nothing.
				cov96bReplaceWithView(t, st, "wasm_checkpoint_pushes", `SELECT * FROM wasm_checkpoint_pushes_cov96b_real`)
				cov96bExec(t, st.db, `CREATE TRIGGER cov96b_swallow INSTEAD OF INSERT ON wasm_checkpoint_pushes BEGIN SELECT 1; END`)
			},
			call: func(st *Store) error {
				_, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb", "registry.example/sb:tag")
				return err
			},
		},
		{
			name: "wasm checkpoint push scan fails",
			setup: func(t *testing.T, st *Store) {
				if _, err := st.InsertWasmCheckpointPush(ctx, "sb", "inc", "registry.example/sb:t1", "sha256:a"); err != nil {
					t.Fatal(err)
				}
				cov96bExec(t, st.db, `UPDATE wasm_checkpoint_pushes SET pushed_at = X'00'`)
			},
			call: func(st *Store) error { _, err := st.ListWasmCheckpointPushes(ctx, "sb"); return err },
		},
		{
			name: "wasm ref in use count fails",
			setup: func(t *testing.T, st *Store) {
				cov96bCreate(t, st, testSandbox("sb", nil))
				cov96bExec(t, st.db, `DROP TABLE wasm_checkpoint_pushes`)
			},
			call: func(st *Store) error {
				_, err := st.WasmCheckpointRefInUse(ctx, "sb", 0, "", "registry.example/sb:t1", "sha256:a")
				return err
			},
		},
		{
			name:  "wasm digests iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "wasm_modules") },
			call:  func(st *Store) error { _, err := st.WasmDigestsInUse(ctx, []string{"sha256:a"}); return err },
		},
	})
}

func TestCov96bNodeStorageRetirements(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.PutNodeStorageRetirement(ctx, "  ", "op", "why", time.Time{}); err == nil {
		t.Fatal("PutNodeStorageRetirement accepted an empty node id")
	}
	if err := st.PutNodeStorageRetirement(ctx, " n1 ", " op ", " disk destroyed ", time.Time{}); err != nil {
		t.Fatalf("PutNodeStorageRetirement: %v", err)
	}
	got, err := st.ListNodeStorageRetirements(ctx)
	if err != nil {
		t.Fatalf("ListNodeStorageRetirements: %v", err)
	}
	if len(got) != 1 || got[0].NodeID != "n1" || got[0].Actor != "op" || got[0].Reason != "disk destroyed" || got[0].AttestedAt.IsZero() {
		t.Fatalf("ListNodeStorageRetirements = %+v", got)
	}

	for _, tc := range []struct {
		name   string
		nodeID string
		want   bool
	}{
		{"blank id is a no-op", " ", false},
		{"existing attestation is revoked", "n1", true},
		{"second revoke finds nothing", "n1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			removed, err := st.DeleteNodeStorageRetirement(ctx, tc.nodeID)
			if err != nil || removed != tc.want {
				t.Fatalf("DeleteNodeStorageRetirement(%q) = %v, %v; want %v", tc.nodeID, removed, err, tc.want)
			}
		})
	}

	if err := st.PutNodeStorageRetirement(ctx, "n2", "op", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	cov96bExec(t, st.db, `UPDATE node_storage_retirements SET attested_at = X'00'`)
	if _, err := st.ListNodeStorageRetirements(ctx); err == nil {
		t.Fatal("ListNodeStorageRetirements scanned an unreadable attested_at")
	}
}

func TestCov96bVolumeFailures(t *testing.T) {
	ctx := context.Background()
	newVolume := func() *models.Volume {
		return &models.Volume{ID: "vol-1", Tenant: "t", Name: "shared", Backend: "s3", Source: "s3://b/k"}
	}

	runCov96bCases(t, []cov96bCase{
		{
			name: "raced volume commit fails",
			setup: func(t *testing.T, st *Store) {
				cov96bFailCommitOn(t, st, "AFTER INSERT", "volumes")
				afterVolumeMissSelect = func(tx *sql.Tx) {
					_, _ = tx.ExecContext(ctx, `
						INSERT INTO volumes (id, tenant, name, backend, source, created_at)
						VALUES ('vol-race', 't', 'shared', 's3', 's3://b/k', CURRENT_TIMESTAMP)`)
				}
				t.Cleanup(func() { afterVolumeMissSelect = nil })
			},
			call: func(st *Store) error { _, _, err := st.GetOrCreateVolume(ctx, newVolume(), 0); return err },
		},
		{
			name:  "new volume commit fails",
			setup: func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER INSERT", "volumes") },
			call:  func(st *Store) error { _, _, err := st.GetOrCreateVolume(ctx, newVolume(), 0); return err },
		},
		{
			name:  "list volumes iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "volumes") },
			call:  func(st *Store) error { _, err := st.ListVolumes(ctx, "t"); return err },
		},
		{
			name: "attachments commit fails",
			setup: func(t *testing.T, st *Store) {
				sb := testSandbox("sb", nil)
				sb.AuditIncarnationID = "inc"
				cov96bCreate(t, st, sb)
				if err := st.CreateVolume(ctx, newVolume()); err != nil {
					t.Fatal(err)
				}
				cov96bFailCommitOn(t, st, "AFTER INSERT", "volume_attachments")
			},
			call: func(st *Store) error {
				return st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
					Tenant: "t", VolumeID: "vol-1", SandboxID: "sb", IncarnationID: "inc", Target: "/data", Source: "s3://b/k",
				}})
			},
		},
		{
			name: "delete unattached commit fails",
			setup: func(t *testing.T, st *Store) {
				if err := st.CreateVolume(ctx, newVolume()); err != nil {
					t.Fatal(err)
				}
				cov96bFailCommitOn(t, st, "AFTER DELETE", "volumes")
			},
			call: func(st *Store) error { return st.DeleteVolumeIfUnattached(ctx, "t", "vol-1", "") },
		},
		{
			name:  "pending deletions iteration fails",
			setup: func(t *testing.T, st *Store) { cov96bBreakRows(t, st, "pending_volume_deletions") },
			call:  func(st *Store) error { _, err := st.ListPendingVolumeDeletions(ctx); return err },
		},
	})
}
