package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func exitPtr(v int) *int { return &v }

func assertReason(t *testing.T, sb *models.Sandbox, reason string, exit *int) {
	t.Helper()
	if sb.StatusReason != reason {
		t.Fatalf("status_reason = %q, want %q", sb.StatusReason, reason)
	}
	switch {
	case exit == nil && sb.ExitCode != nil:
		t.Fatalf("exit_code = %d, want NULL", *sb.ExitCode)
	case exit != nil && (sb.ExitCode == nil || *sb.ExitCode != *exit):
		t.Fatalf("exit_code = %v, want %d", sb.ExitCode, *exit)
	}
}

// TestStatusReasonColumnsRoundTrip: status_reason and exit_code come back on
// every read path, and exit code 0 is not confused with "no exit".
func TestStatusReasonColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	exited := sampleSandbox("sb-exited")
	exited.Status = models.SandboxStatusStopped
	exited.StatusReason = models.StatusReasonProgramExited
	exited.ExitCode = exitPtr(0)
	if err := st.Create(ctx, exited); err != nil {
		t.Fatalf("Create: %v", err)
	}
	plain := sampleSandbox("sb-plain")
	if err := st.Create(ctx, plain); err != nil {
		t.Fatalf("Create plain: %v", err)
	}

	got, err := st.Get(ctx, exited.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertReason(t, got, models.StatusReasonProgramExited, exitPtr(0))
	got, err = st.Get(ctx, plain.ID)
	if err != nil {
		t.Fatalf("Get plain: %v", err)
	}
	assertReason(t, got, "", nil)

	all, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	byRuntime, err := st.ListByRuntime(ctx, exited.Runtime)
	if err != nil {
		t.Fatalf("ListByRuntime: %v", err)
	}
	byOwner, err := st.ListByOwner(ctx, "")
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	for name, rows := range map[string][]*models.Sandbox{"List": all, "ListByRuntime": byRuntime, "ListByOwner": byOwner} {
		found := false
		for _, row := range rows {
			if row.ID == exited.ID {
				found = true
				assertReason(t, row, models.StatusReasonProgramExited, exitPtr(0))
			}
		}
		if !found {
			t.Fatalf("%s did not return %s", name, exited.ID)
		}
	}
}

// TestUpsertWritesTheReasonOnlyWithAStatusChange is the rule every status
// writer relies on: the write that changes the status says why, and a
// whole-row write that keeps the status (a duplicate event, a reconcile pass
// that read the row a moment earlier) keeps the reason it finds.
func TestUpsertWritesTheReasonOnlyWithAStatusChange(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-transition")
	sb.Status = models.SandboxStatusStarted
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	steps := []struct {
		name       string
		status     models.SandboxStatus
		reason     string
		exit       *int
		wantReason string
		wantExit   *int
	}{
		{"stop names its reason", models.SandboxStatusStopped, models.StatusReasonCrashed, exitPtr(3), models.StatusReasonCrashed, exitPtr(3)},
		{"same-status write keeps it", models.SandboxStatusStopped, models.StatusReasonReconcile, nil, models.StatusReasonCrashed, exitPtr(3)},
		{"start clears it", models.SandboxStatusStarted, "", nil, "", nil},
		{"started write keeps the empty reason", models.SandboxStatusStarted, models.StatusReasonUserStop, nil, "", nil},
		{"next stop names its own", models.SandboxStatusStopped, models.StatusReasonUserStop, nil, models.StatusReasonUserStop, nil},
	}
	for _, step := range steps {
		row := *sb
		row.Status = step.status
		row.StatusReason = step.reason
		row.ExitCode = step.exit
		if err := st.Upsert(ctx, &row); err != nil {
			t.Fatalf("%s: Upsert: %v", step.name, err)
		}
		got, err := st.Get(ctx, sb.ID)
		if err != nil {
			t.Fatalf("%s: Get: %v", step.name, err)
		}
		if got.Status != step.status {
			t.Fatalf("%s: status %q, want %q", step.name, got.Status, step.status)
		}
		assertReason(t, got, step.wantReason, step.wantExit)
	}

	// An Upsert that inserts a row writes the reason it carries.
	fresh := sampleSandbox("sb-upsert-insert")
	fresh.StatusReason = models.StatusReasonFailover
	if err := st.Upsert(ctx, fresh); err != nil {
		t.Fatalf("Upsert insert: %v", err)
	}
	got, err := st.Get(ctx, fresh.ID)
	if err != nil {
		t.Fatalf("Get insert: %v", err)
	}
	assertReason(t, got, models.StatusReasonFailover, nil)
}

// TestTargetedStatusReasonWrites covers the two writes that set a reason
// outside Upsert, and their not-found answer.
func TestTargetedStatusReasonWrites(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-targeted")
	sb.Status = models.SandboxStatusStarted
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := st.SetStatusReason(ctx, sb.ID, models.StatusReasonRestarted, exitPtr(1)); err != nil {
		t.Fatalf("SetStatusReason: %v", err)
	}
	got, _ := st.Get(ctx, sb.ID)
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("SetStatusReason changed the status to %q", got.Status)
	}
	assertReason(t, got, models.StatusReasonRestarted, exitPtr(1))

	if err := st.UpdateStatusWithReason(ctx, sb.ID, models.SandboxStatusStopped, "lost", models.StatusReasonReconcile, nil); err != nil {
		t.Fatalf("UpdateStatusWithReason: %v", err)
	}
	got, _ = st.Get(ctx, sb.ID)
	if got.Status != models.SandboxStatusStopped || got.LastError != "lost" {
		t.Fatalf("status %q last_error %q", got.Status, got.LastError)
	}
	assertReason(t, got, models.StatusReasonReconcile, nil)

	if err := st.SetStatusReason(ctx, "missing", models.StatusReasonIdle, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetStatusReason(missing) = %v, want ErrNotFound", err)
	}
	if err := st.UpdateStatusWithReason(ctx, "missing", models.SandboxStatusStopped, "", models.StatusReasonIdle, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateStatusWithReason(missing) = %v, want ErrNotFound", err)
	}
}

// TestStatusReasonColumnsMigrateOntoAnOldDatabase: a database from before
// the columns opens, gains them, and its rows read as "nothing recorded".
func TestStatusReasonColumnsMigrateOntoAnOldDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-old")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"status_reason", "exit_code"} {
		if _, err := raw.Exec(`ALTER TABLE sandboxes DROP COLUMN ` + col); err != nil {
			t.Fatalf("drop %s: %v", col, err)
		}
	}
	_ = raw.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	got, err := st.Get(ctx, "sb-old")
	if err != nil {
		t.Fatalf("Get after migration: %v", err)
	}
	assertReason(t, got, "", nil)
}
