package store

import (
	"context"
	"path/filepath"
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
	plain, err := st.GetEnvJSON(ctx, sb.ID)
	if err != nil {
		t.Fatalf("GetEnvJSON: %v", err)
	}
	if len(plain) != 0 {
		t.Fatalf("sealed create left plaintext env_json = %+v, want empty", plain)
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

func TestOmitEnvFromScanner(t *testing.T) {
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
	if got.Env["SECRET"] != "value" {
		t.Fatalf("flag-off Get Env = %+v", got.Env)
	}

	st.SetOmitEnvFromScanner(true)
	got, err = st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get omit: %v", err)
	}
	if len(got.Env) != 0 {
		t.Fatalf("flag-on Get Env = %+v, want empty", got.Env)
	}
	plain, err := st.GetEnvJSON(ctx, sb.ID)
	if err != nil {
		t.Fatalf("GetEnvJSON: %v", err)
	}
	if plain["SECRET"] != "value" {
		t.Fatalf("GetEnvJSON = %+v", plain)
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
