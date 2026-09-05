package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
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

func TestOpenRejectsPlaintextSecretSchema(t *testing.T) {
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
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "unsupported plaintext secret schema") {
		t.Fatalf("Open plaintext schema error = %v", err)
	}
}

func TestOpenRejectsObsoleteSecretGenerationSchema(t *testing.T) {
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
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "cluster_secrets.seal_generation is required") {
		t.Fatalf("Open obsolete schema error = %v", err)
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
