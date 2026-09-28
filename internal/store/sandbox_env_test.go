package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func testSandbox(id string, env map[string]string) *models.Sandbox {
	now := time.Now().UTC()
	return &models.Sandbox{
		ID:           id,
		Image:        "alpine:3.19",
		Status:       models.SandboxStatusStarted,
		PublicURL:    "http://localhost/" + id,
		ContainerID:  "c-" + id,
		ContainerIP:  "10.0.0.2",
		CPU:          1,
		MemoryMB:     512,
		DiskGB:       5,
		OSUser:       "root",
		Env:          env,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
}

func TestPutGetDeleteEnv(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "env.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	sb := testSandbox("sb-env", map[string]string{"A": "1"})
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sealed := []byte("sealed-env-blob")
	if err := st.PutEnv(ctx, sb.ID, sealed); err != nil {
		t.Fatalf("PutEnv: %v", err)
	}
	got, err := st.GetEnv(ctx, sb.ID)
	if err != nil {
		t.Fatalf("GetEnv: %v", err)
	}
	if string(got) != string(sealed) {
		t.Fatalf("GetEnv = %q, want %q", got, sealed)
	}
	if err := st.DeleteEnv(ctx, sb.ID); err != nil {
		t.Fatalf("DeleteEnv: %v", err)
	}
	if _, err := st.GetEnv(ctx, sb.ID); err != ErrNotFound {
		t.Fatalf("GetEnv after delete = %v, want ErrNotFound", err)
	}
}

func TestCreateWithSealedEnvAtomicCommit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "env-atom.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	sb := testSandbox("sb-atom", map[string]string{"K": "v"})
	sealed := []byte("atom-sealed")
	if err := st.CreateWithSealedEnv(ctx, sb, sealed); err != nil {
		t.Fatalf("CreateWithSealedEnv: %v", err)
	}
	if _, err := st.Get(ctx, sb.ID); err != nil {
		t.Fatalf("Get after commit: %v", err)
	}
	got, err := st.GetEnv(ctx, sb.ID)
	if err != nil {
		t.Fatalf("GetEnv after commit: %v", err)
	}
	if string(got) != string(sealed) {
		t.Fatalf("sealed = %q", got)
	}
}

func TestCreateWithSealedEnvCrashBetweenWritesRollsBack(t *testing.T) {
	// Simulate crash-before-commit: insert sandbox + env in a tx, then
	// Rollback. Neither row must be visible (outside-voice #3).
	st, err := Open(filepath.Join(t.TempDir(), "env-crash.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	sb := testSandbox("sb-crash", map[string]string{"X": "y"})
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := st.insertSandbox(ctx, tx, sb); err != nil {
		t.Fatalf("insertSandbox: %v", err)
	}
	if err := putEnvExec(ctx, tx, sb.ID, []byte("never-committed")); err != nil {
		t.Fatalf("putEnvExec: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := st.Get(ctx, sb.ID); err != ErrNotFound {
		t.Fatalf("Get after rollback = %v, want ErrNotFound", err)
	}
	if _, err := st.GetEnv(ctx, sb.ID); err != ErrNotFound {
		t.Fatalf("GetEnv after rollback = %v, want ErrNotFound", err)
	}
}

func TestSandboxRowDoesNotStoreEnvironment(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "env-omit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	sb := testSandbox("sb-omit", map[string]string{"SECRET": "value"})
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Env) != 0 {
		t.Fatalf("sandbox row projected Env = %+v, want empty", got.Env)
	}
	rows, err := st.db.QueryContext(ctx, `PRAGMA table_info(sandboxes)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "env_json" || name == "toolbox_token" {
			t.Fatalf("plaintext compatibility column %q remains in current schema", name)
		}
	}
}

func TestOpenRequiresCipherForPlaintextSecretMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-secrets.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open fresh store: %v", err)
	}
	if _, err := st.db.Exec(`ALTER TABLE sandboxes ADD COLUMN env_json TEXT NOT NULL DEFAULT '{}'`); err != nil {
		_ = st.Close()
		t.Fatalf("seed plaintext schema: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "secret cipher is required") {
		t.Fatalf("Open plaintext schema error = %v", err)
	}

	raw, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open raw database: %v", err)
	}
	defer raw.Close()
	columns, err := inspectLegacySecretColumns(raw)
	if err != nil {
		t.Fatalf("inspect legacy columns after rejected migration: %v", err)
	}
	if !columns.envJSON {
		t.Fatal("cipher-less migration removed env_json")
	}
}

func TestOpenWithSecretCipherMigratesPlaintextSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-secrets.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open fresh store: %v", err)
	}
	ctx := context.Background()
	// Cross the migration batch boundary so a large database cannot silently
	// leave later rows behind.
	for i := 0; i <= legacySecretMigrationBatchSize; i++ {
		id := fmt.Sprintf("legacy-%03d", i)
		if err := st.Create(ctx, testSandbox(id, nil)); err != nil {
			_ = st.Close()
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	fullID := fmt.Sprintf("legacy-%03d", legacySecretMigrationBatchSize)
	emptyID := "legacy-000"
	if _, err := st.db.Exec(`ALTER TABLE sandboxes ADD COLUMN env_json TEXT NOT NULL DEFAULT '{}'`); err != nil {
		_ = st.Close()
		t.Fatalf("add legacy env column: %v", err)
	}
	// A real pre-hardening database has the plaintext token column and lacks
	// the sealed replacement. OpenWithSecretCipher must add the destination
	// column before it can migrate the old value.
	if _, err := st.db.Exec(`ALTER TABLE sandboxes DROP COLUMN toolbox_token_sealed`); err != nil {
		_ = st.Close()
		t.Fatalf("remove sealed toolbox column: %v", err)
	}
	if _, err := st.db.Exec(`ALTER TABLE sandboxes ADD COLUMN toolbox_token TEXT NOT NULL DEFAULT ''`); err != nil {
		_ = st.Close()
		t.Fatalf("add legacy toolbox column: %v", err)
	}
	wantEnv := map[string]string{"API_KEY": "legacy-secret", "MODE": "test"}
	wantEnvJSON, err := json.Marshal(wantEnv)
	if err != nil {
		_ = st.Close()
		t.Fatalf("marshal legacy env: %v", err)
	}
	const wantToken = "legacy-toolbox-token"
	if _, err := st.db.Exec(`UPDATE sandboxes SET env_json = ?, toolbox_token = ? WHERE id = ?`, string(wantEnvJSON), wantToken, fullID); err != nil {
		_ = st.Close()
		t.Fatalf("seed legacy secrets: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}

	cipher, err := secrets.NewCipher("", filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	migrated, err := OpenWithSecretCipher(path, cipher)
	if err != nil {
		t.Fatalf("OpenWithSecretCipher: %v", err)
	}
	columns, err := inspectLegacySecretColumns(migrated.db)
	if err != nil {
		_ = migrated.Close()
		t.Fatalf("inspect migrated columns: %v", err)
	}
	if columns.envJSON || columns.toolboxToken {
		_ = migrated.Close()
		t.Fatalf("legacy columns remain after migration: %+v", columns)
	}

	sealedEnv, err := migrated.GetEnv(ctx, fullID)
	if err != nil {
		_ = migrated.Close()
		t.Fatalf("GetEnv: %v", err)
	}
	inc, _, err := migrated.CurrentSandboxAuditIdentity(ctx, fullID)
	if err != nil || inc == "" {
		t.Fatalf("migrated lifecycle: %q %v", inc, err)
	}
	plainEnv, err := cipher.DecryptWithAAD(sealedEnv, secrets.EnvAAD(fullID, inc))
	if err != nil {
		_ = migrated.Close()
		t.Fatalf("decrypt migrated env: %v", err)
	}
	var gotEnv map[string]string
	if err := json.Unmarshal(plainEnv, &gotEnv); err != nil {
		_ = migrated.Close()
		t.Fatalf("decode migrated env: %v", err)
	}
	if len(gotEnv) != len(wantEnv) || gotEnv["API_KEY"] != wantEnv["API_KEY"] || gotEnv["MODE"] != wantEnv["MODE"] {
		_ = migrated.Close()
		t.Fatalf("migrated env = %+v, want %+v", gotEnv, wantEnv)
	}
	gotSandbox, err := migrated.Get(ctx, fullID)
	if err != nil {
		_ = migrated.Close()
		t.Fatalf("Get migrated sandbox: %v", err)
	}
	if gotSandbox.ToolboxToken != wantToken {
		_ = migrated.Close()
		t.Fatalf("migrated toolbox token = %q, want %q", gotSandbox.ToolboxToken, wantToken)
	}
	// Every sandbox carries an env row now, empty seal included: that is what
	// lets a later read tell "no environment" from "sealed env lost" and fail
	// loud on the second. A legacy row with no env keeps an empty seal.
	emptyBlob, err := migrated.GetEnv(ctx, emptyID)
	if err != nil {
		_ = migrated.Close()
		t.Fatalf("empty legacy env has no side row: %v", err)
	}
	if len(emptyBlob) != 0 {
		_ = migrated.Close()
		t.Fatalf("empty legacy env sealed %d bytes, want 0", len(emptyBlob))
	}
	if err := migrated.Close(); err != nil {
		t.Fatalf("close migrated store: %v", err)
	}

	// A second startup is a no-op and retains access to the migrated values.
	reopened, err := OpenWithSecretCipher(path, cipher)
	if err != nil {
		t.Fatalf("reopen migrated store: %v", err)
	}
	defer reopened.Close()
	gotSandbox, err = reopened.Get(ctx, fullID)
	if err != nil {
		t.Fatalf("Get after migration reopen: %v", err)
	}
	if gotSandbox.ToolboxToken != wantToken {
		t.Fatalf("toolbox token after reopen = %q, want %q", gotSandbox.ToolboxToken, wantToken)
	}
}

func TestPlaintextSecretMigrationRollsBackOnInvalidEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-rollback.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open fresh store: %v", err)
	}
	ctx := context.Background()
	for _, id := range []string{"a-valid", "z-invalid"} {
		if err := st.Create(ctx, testSandbox(id, nil)); err != nil {
			_ = st.Close()
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	if _, err := st.db.Exec(`ALTER TABLE sandboxes ADD COLUMN env_json TEXT NOT NULL DEFAULT '{}'`); err != nil {
		_ = st.Close()
		t.Fatalf("add legacy env column: %v", err)
	}
	if _, err := st.db.Exec(`ALTER TABLE sandboxes ADD COLUMN toolbox_token TEXT NOT NULL DEFAULT ''`); err != nil {
		_ = st.Close()
		t.Fatalf("add legacy toolbox column: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE sandboxes SET env_json = '{"GOOD":"value"}', toolbox_token = 'token-a' WHERE id = 'a-valid'`); err != nil {
		_ = st.Close()
		t.Fatalf("seed valid legacy row: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE sandboxes SET env_json = 'not-json', toolbox_token = 'token-z' WHERE id = 'z-invalid'`); err != nil {
		_ = st.Close()
		t.Fatalf("seed invalid legacy row: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}

	cipher, err := secrets.NewCipher("", filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if _, err := OpenWithSecretCipher(path, cipher); err == nil || !strings.Contains(err.Error(), `decode legacy sandbox env for "z-invalid"`) {
		t.Fatalf("migration error = %v", err)
	}

	raw, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open raw database: %v", err)
	}
	defer raw.Close()
	columns, err := inspectLegacySecretColumns(raw)
	if err != nil {
		t.Fatalf("inspect legacy columns after rollback: %v", err)
	}
	if !columns.envJSON || !columns.toolboxToken {
		t.Fatalf("migration failure dropped legacy columns: %+v", columns)
	}
	var envJSON, token string
	var sealed []byte
	if err := raw.QueryRow(`SELECT env_json, toolbox_token, toolbox_token_sealed FROM sandboxes WHERE id = 'a-valid'`).Scan(&envJSON, &token, &sealed); err != nil {
		t.Fatalf("read rolled-back legacy row: %v", err)
	}
	if envJSON != `{"GOOD":"value"}` || token != "token-a" || len(sealed) != 0 {
		t.Fatalf("legacy row changed after rollback: env=%q token=%q sealed=%d bytes", envJSON, token, len(sealed))
	}
	// The schema backfill (outside this transaction) gives every sandbox an
	// empty env row; the rollback must undo the migration's SEALED writes, so
	// the rows survive with zero-length blobs.
	var sealedEnvRows int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sandbox_env WHERE length(sealed_blob) > 0`).Scan(&sealedEnvRows); err != nil {
		t.Fatalf("count rolled-back env rows: %v", err)
	}
	if sealedEnvRows != 0 {
		t.Fatalf("sealed sandbox_env rows after rollback = %d, want 0", sealedEnvRows)
	}
}

func TestOpenAddsMissingSecretGenerationColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obsolete-secret-generation.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open fresh store: %v", err)
	}
	if _, err := st.db.Exec(`ALTER TABLE cluster_secrets DROP COLUMN seal_generation`); err != nil {
		_ = st.Close()
		t.Fatalf("seed obsolete schema: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open obsolete schema: %v", err)
	}
	defer reopened.Close()
	if err := validateCurrentSecretSchema(reopened.db); err != nil {
		t.Fatalf("schema after additive migration: %v", err)
	}
}

func TestOpenRejectsUnfencedSecretPutOutboxPrimaryKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obsolete-put-outbox.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open fresh store: %v", err)
	}
	if _, err := st.db.Exec(`
		DROP TABLE cluster_secret_put_outbox;
		CREATE TABLE cluster_secret_put_outbox (
			sandbox_id TEXT PRIMARY KEY,
			incarnation_id TEXT NOT NULL DEFAULT '',
			seal_generation INTEGER NOT NULL DEFAULT 0,
			recipients_json TEXT NOT NULL DEFAULT '[]',
			attempts INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
	`); err != nil {
		_ = st.Close()
		t.Fatalf("seed unfenced outbox schema: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "primary-key position") {
		t.Fatalf("Open unfenced outbox schema error = %v", err)
	}
}

func TestDestroyCascadesSandboxEnv(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "env-cascade.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	sb := testSandbox("sb-cascade", map[string]string{"A": "1"})
	if err := st.CreateWithSealedEnv(ctx, sb, []byte("blob")); err != nil {
		t.Fatalf("CreateWithSealedEnv: %v", err)
	}
	if err := st.Delete(ctx, sb.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.GetEnv(ctx, sb.ID); err != ErrNotFound {
		t.Fatalf("GetEnv after cascade = %v, want ErrNotFound", err)
	}
}
