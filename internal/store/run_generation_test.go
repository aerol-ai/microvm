package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestRunGenerationCountsStarts: run_generation goes up by one only on a
// write that moves the row to started, and never takes the caller's value,
// so every start path counts each run once.
func TestRunGenerationCountsStarts(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-gen")
	sb.Status = models.SandboxStatusCreating
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	want := func(step string, gen int64) *models.Sandbox {
		t.Helper()
		got, err := st.Get(ctx, sb.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.RunGeneration != gen {
			t.Fatalf("%s: run_generation = %d, want %d", step, got.RunGeneration, gen)
		}
		return got
	}
	row := want("created", 0)

	steps := []struct {
		name   string
		status models.SandboxStatus
		gen    int64
	}{
		{"first start", models.SandboxStatusStarted, 1},
		{"a write that keeps it started", models.SandboxStatusStarted, 1},
		{"stop", models.SandboxStatusStopped, 1},
		{"a write that keeps it stopped", models.SandboxStatusStopped, 1},
		{"start again", models.SandboxStatusStarted, 2},
		{"error", models.SandboxStatusError, 2},
		{"start from error", models.SandboxStatusStarted, 3},
	}
	for _, step := range steps {
		next := *row
		next.Status = step.status
		next.RunGeneration = 99 // a caller's value is never written
		if err := st.Upsert(ctx, &next); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		row = want(step.name, step.gen)
	}

	// The same through List, which the lifecycle sweep reads.
	all, err := st.List(ctx)
	if err != nil || len(all) != 1 || all[0].RunGeneration != 3 {
		t.Fatalf("List: %v %+v", err, all)
	}

	// An Upsert that inserts a row starts at 0.
	fresh := sampleSandbox("sb-gen-insert")
	fresh.RunGeneration = 7
	if err := st.Upsert(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, fresh.ID); got.RunGeneration != 0 {
		t.Fatalf("inserted row: run_generation = %d", got.RunGeneration)
	}
}

// TestRecordProgramExitOnlyForItsRun is review 2 finding 10 at the store: an
// exit read in run A does not land on run B after a stop and a start, while
// run B's own exit does.
func TestRecordProgramExitOnlyForItsRun(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-run")
	sb.Lifecycle.DestroyAfterExitFor = time.Minute
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	runA, _ := st.Get(ctx, sb.ID)

	stopped := *runA
	stopped.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, &stopped); err != nil {
		t.Fatal(err)
	}
	started := stopped
	started.Status = models.SandboxStatusStarted
	if err := st.Upsert(ctx, &started); err != nil {
		t.Fatal(err)
	}
	runB, _ := st.Get(ctx, sb.ID)
	if runB.RunGeneration == runA.RunGeneration {
		t.Fatalf("stop and start kept run_generation %d", runB.RunGeneration)
	}

	at := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	if ok, err := st.RecordProgramExit(ctx, sb.ID, runA.RunGeneration, at, 0); err != nil || ok {
		t.Fatalf("run A's exit on run B: recorded=%v err=%v", ok, err)
	}
	if got, _ := st.Get(ctx, sb.ID); got.ProgramExitedAt != nil || got.StatusReason == models.StatusReasonProgramExited {
		t.Fatalf("run B marked exited: at=%v reason=%q", got.ProgramExitedAt, got.StatusReason)
	}
	if ok, err := st.RecordProgramExit(ctx, sb.ID, runB.RunGeneration, at, 4); err != nil || !ok {
		t.Fatalf("run B's own exit: recorded=%v err=%v", ok, err)
	}
	got, _ := st.Get(ctx, sb.ID)
	assertReason(t, got, models.StatusReasonProgramExited, exitPtr(4))
}

// TestRunGenerationMigration: a database from before the column gets it on
// Open with 0 on every row (the add-store-column contract), Open is safe to
// run again, and the next start counts from there.
func TestRunGenerationMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sb := sampleSandbox("sb-old")
	sb.Status = models.SandboxStatusStopped
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	// Make it a pre-migration database.
	if _, err := st.db.ExecContext(ctx, `ALTER TABLE sandboxes DROP COLUMN run_generation`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		st, err = Open(path)
		if err != nil {
			t.Fatalf("Open #%d: %v", i+1, err)
		}
		got, err := st.Get(ctx, sb.ID)
		if err != nil || got.RunGeneration != 0 {
			t.Fatalf("Open #%d: run_generation=%v err=%v", i+1, got, err)
		}
		if i == 0 {
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer st.Close()
	got, _ := st.Get(ctx, sb.ID)
	got.Status = models.SandboxStatusStarted
	if err := st.Upsert(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); got.RunGeneration != 1 {
		t.Fatalf("first start after the migration: run_generation = %d", got.RunGeneration)
	}
}
