package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRollbackPendingIsSetOnceAndSurvivesWholeRowWrites pins the contract
// the C5 fix depends on: the flag reads back through Get and List, only
// MarkSandboxRollbackPending sets it, a whole-row Upsert from a read taken
// before the mark never clears it, and the row's delete is what ends it.
func TestRollbackPendingIsSetOnceAndSurvivesWholeRowWrites(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-rollback-pending")
	other := sampleSandbox("sb-rollback-clean")
	for _, row := range []string{sb.ID, other.ID} {
		s := sampleSandbox(row)
		if err := st.Create(ctx, s); err != nil {
			t.Fatalf("create %s: %v", row, err)
		}
	}
	stale, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stale.RollbackPending {
		t.Fatal("a new row reads rollback-pending")
	}
	if ids, err := st.ListRollbackPendingIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("pending ids before any mark = %v, %v; want none", ids, err)
	}

	if err := st.MarkSandboxRollbackPending(ctx, sb.ID); err != nil {
		t.Fatalf("mark: %v", err)
	}
	// Marking twice is harmless: a retried rollback marks again.
	if err := st.MarkSandboxRollbackPending(ctx, sb.ID); err != nil {
		t.Fatalf("second mark: %v", err)
	}
	if got, err := st.Get(ctx, sb.ID); err != nil || !got.RollbackPending {
		t.Fatalf("Get after mark: pending=%v err=%v, want true", got != nil && got.RollbackPending, err)
	}

	// A status write from the read taken before the mark.
	stale.LastError = "written from a stale read"
	if err := st.Upsert(ctx, stale); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	all, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range all {
		want := row.ID == sb.ID
		if row.RollbackPending != want {
			t.Fatalf("List: %s rollback-pending = %v, want %v", row.ID, row.RollbackPending, want)
		}
	}
	if ids, err := st.ListRollbackPendingIDs(ctx); err != nil || !slices.Equal(ids, []string{sb.ID}) {
		t.Fatalf("pending ids = %v, %v; want [%s]", ids, err, sb.ID)
	}

	if err := st.Delete(ctx, sb.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ids, err := st.ListRollbackPendingIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("pending ids after delete = %v, %v; want none", ids, err)
	}
	// A new lifetime under the same id starts clean.
	if err := st.Create(ctx, sampleSandbox(sb.ID)); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if got, err := st.Get(ctx, sb.ID); err != nil || got.RollbackPending {
		t.Fatalf("reused id reads rollback-pending=%v err=%v, want false", got != nil && got.RollbackPending, err)
	}
}

func TestMarkSandboxRollbackPendingMissingRow(t *testing.T) {
	st := newTestStore(t)
	if err := st.MarkSandboxRollbackPending(context.Background(), "sb-none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark of a missing row = %v, want ErrNotFound", err)
	}
}

// TestRollbackPendingSchemaIsAdditiveAndIndexed: the column is added on an
// existing database by re-opening it (the ALTER is idempotent), a mark
// survives the re-open, and the reconcile scan seeks the partial index.
func TestRollbackPendingSchemaIsAdditiveAndIndexed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-reopen")); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkSandboxRollbackPending(ctx, "sb-reopen"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if ids, err := st.ListRollbackPendingIDs(ctx); err != nil || !slices.Equal(ids, []string{"sb-reopen"}) {
		t.Fatalf("pending ids after re-open = %v, %v", ids, err)
	}
	plan := queryPlan(t, st, `SELECT id FROM sandboxes WHERE rollback_pending = 1 ORDER BY updated_at ASC`, nil)
	if !strings.Contains(plan, "idx_sandboxes_rollback_pending") {
		t.Fatalf("rollback-pending scan does not use its partial index; plan: %s", plan)
	}
}

func TestListRollbackPendingIDsReadError(t *testing.T) {
	st := newTestStore(t)
	_ = st.Close()
	if _, err := st.ListRollbackPendingIDs(context.Background()); err == nil {
		t.Fatal("list on a closed store succeeded")
	}
	if err := st.MarkSandboxRollbackPending(context.Background(), "sb-x"); err == nil {
		t.Fatal("mark on a closed store succeeded")
	}
}
