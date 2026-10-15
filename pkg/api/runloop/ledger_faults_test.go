package runloop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
)

// The execution ledger is the one thing that stops a retried command_id
// from running twice, so these tests break each of its writes on its own
// and pin what the facade does with a store that half-works. A closed store
// or a dropped table fails everything at once; a trigger fails one step.

// ledgerFaults singles out each ledger write by what it does to the row.
var ledgerFaults = map[string]string{
	"claim":    "INSERT ON request_idempotency WHEN NEW.scope = 'runloop.exec'",
	"outcome":  "UPDATE ON request_idempotency WHEN NEW.scope = 'runloop.exec' AND NEW.state = 'pending' AND NEW.target_id != ''",
	"complete": "UPDATE ON request_idempotency WHEN NEW.scope = 'runloop.exec' AND NEW.state = 'ready'",
	"release":  "DELETE ON request_idempotency WHEN OLD.scope = 'runloop.exec'",
}

// failLedger makes one kind of ledger write fail until the returned func
// runs (or the test ends).
func failLedger(t *testing.T, st *store.Store, kind string) (clear func()) {
	t.Helper()
	name := "fault_ledger_" + kind
	execSQL(t, st, fmt.Sprintf("CREATE TRIGGER %s BEFORE %s BEGIN SELECT RAISE(ABORT, 'injected %s fault'); END", name, ledgerFaults[kind], kind))
	return func() { execSQL(t, st, "DROP TRIGGER IF EXISTS "+name) }
}

func ledgerSettled(h *handlers, devboxID string, ref execRef) bool {
	_, owed, ok := h.ledgerOutcome(context.Background(), devboxID, ref)
	return ok && !owed
}

// Without a durable claim nothing runs: the claim is what a retry would
// find, so running first would make a retry run the command again.
func TestLedgerClaimFailureNeverRunsTheCommand(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	bodies := []string{
		`{"command":"echo plain","command_id":"k"}`,
		`{"command":"echo named","command_id":"k","shell_name":"dev"}`,
	}
	clear := failLedger(t, env.store, "claim")
	for _, body := range bodies {
		if rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil); rr.Code < http.StatusInternalServerError {
			t.Fatalf("execute with a failing claim = %d %s", rr.Code, rr.Body.String())
		}
	}
	if env.toolbox.execCount() != 0 || env.toolbox.sessionCount() != 0 {
		t.Fatal("a command reached the toolbox without a durable claim")
	}

	// Nothing was claimed, so the same ids start cleanly once the store
	// recovers.
	clear()
	for _, body := range bodies {
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusOK)
	}
	if got := env.toolbox.execCount(); got != 2 {
		t.Fatalf("commands run after recovery = %d, want 2", got)
	}
}

// The session is the only other copy of a finished command's exit status,
// so it stays until the outcome is stored (step 2 of finishPlain). While the
// store refuses the write, a process that restarts still finds the real
// status in the session; once the write lands the session goes, and a retry
// replays the status without running the command again.
func TestOutcomeIsStoredBeforeTheSessionGoes(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	clearOutcome := failLedger(t, env.store, "outcome")
	clearComplete := failLedger(t, env.store, "complete")

	var first executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"exit 7","command_id":"o"}`, &first), http.StatusOK)
	if first.ExitStatus == nil || *first.ExitStatus != 7 {
		t.Fatalf("execution = %+v", first)
	}
	ref := mustRef(t, first.ExecutionID)
	time.Sleep(100 * time.Millisecond)
	if env.toolbox.sessionCount() != 1 {
		t.Fatal("the session went while the store had no outcome; a restart now could only call the execution lost")
	}
	restarted := newHandlers(env.h.deps)
	if state, err := restarted.executionState(ctx, devbox.ID, ref); err != nil || !state.completed || state.exit != 7 {
		t.Fatalf("a restart in the gap = %+v, %v; want the real exit status from the session", state, err)
	}

	clearOutcome()
	waitFor(t, "session cleanup", func() bool { return env.toolbox.sessionCount() == 0 })
	if outcome, owed, ok := env.h.ledgerOutcome(ctx, devbox.ID, ref); !ok || !owed || outcome.Exit != 7 {
		t.Fatalf("after the session went the ledger holds %+v (owed %v, ok %v); want the outcome, still owed", outcome, owed, ok)
	}
	clearComplete()
	waitFor(t, "the ledger to settle", func() bool { return ledgerSettled(env.h, devbox.ID, ref) })

	if _, err := newHandlers(env.h.deps).startExecution(ctx, devbox.ID, "exit 7", "", "o"); err != nil {
		t.Fatal(err)
	}
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("command ran %d times; want 1", got)
	}
}

// A completion write that fails leaves the row pending with its outcome:
// cleanup still owed, never forgotten. The watcher keeps trying rather than
// ending with the debt open, and so does a restarted process's; once the
// store recovers the row settles with no reader's help, and the retry
// replays rather than reruns.
func TestLedgerCompletionFailureLeavesCleanupOwed(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	clear := failLedger(t, env.store, "complete")

	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"exit 5","command_id":"c"}`, &done), http.StatusOK)
	ref := mustRef(t, done.ExecutionID)
	key := resultKey(devbox.ID, ref.id())
	waitFor(t, "session cleanup", func() bool { return env.toolbox.sessionCount() == 0 })
	time.Sleep(50 * time.Millisecond)
	if outcome, owed, ok := env.h.ledgerOutcome(context.Background(), devbox.ID, ref); !ok || !owed || outcome.Exit != 5 {
		t.Fatalf("a row whose completion failed must stay owed with its outcome: %+v owed=%v ok=%v", outcome, owed, ok)
	}
	if !watcherAlive(env.h.execs, key) {
		t.Fatal("the watcher ended with its completion still owed")
	}

	restarted := newHandlers(env.h.deps)
	if err := restarted.recoverExecutions(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, owed, ok := restarted.ledgerOutcome(context.Background(), devbox.ID, ref); !ok || !owed || !watcherAlive(restarted.execs, key) {
		t.Fatal("while the store refuses, the row stays owed and a watcher stays on it")
	}

	clear()
	waitFor(t, "the ledger to settle on its own", func() bool { return ledgerSettled(env.h, devbox.ID, ref) })
	waitFor(t, "both watchers to end", func() bool { return !watcherAlive(env.h.execs, key) && !watcherAlive(restarted.execs, key) })
	if _, err := restarted.startExecution(context.Background(), devbox.ID, "exit 5", "", "c"); err != nil {
		t.Fatal(err)
	}
	state, err := restarted.executionState(context.Background(), devbox.ID, ref)
	if err != nil || !state.completed || state.exit != 5 {
		t.Fatalf("replay = %+v, %v", state, err)
	}
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("command ran %d times; want 1", got)
	}
}

// A named command whose ledger mapping could not be written still runs
// once. Its retry cannot learn which command it maps to, so it is told to
// pick a new id instead of running the command a second time.
func TestNamedLedgerWriteFailureTellsRetryToPickANewID(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &submitWait, 50*time.Millisecond)
	devbox := env.mustCreate(t, "")
	failLedger(t, env.store, "complete")

	body := `{"command":"echo hi","command_id":"n1","shell_name":"dev"}`
	var first executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, &first), http.StatusOK)
	if first.Status != execStatusCompleted {
		t.Fatalf("named execution = %+v", first)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusConflict)
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("command ran %d times; want 1", got)
	}
}

// A failed submit whose claim cannot be dropped leaves the id fenced: the
// retry cannot tell "never ran" from "ran and was cleaned up", so it is
// told to pick a new id rather than guess. A new id runs normally.
func TestLedgerReleaseFailureFencesTheID(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &submitWait, 50*time.Millisecond)
	devbox := env.mustCreate(t, "")
	failLedger(t, env.store, "release")

	env.toolbox.failAlways("POST /process/session", http.StatusServiceUnavailable)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"r"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"r"}`, nil), http.StatusConflict)
	if got := env.toolbox.execCount(); got != 0 {
		t.Fatalf("a fenced id ran %d commands", got)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"r2"}`, nil), http.StatusOK)
}

// A ledger row that no longer decodes fails the retry. It never reads as
// "no such execution, run it": the row exists, so the command already ran.
func TestCorruptLedgerRowsNeverRerun(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	plain := `{"command":"exit 2","command_id":"p"}`
	named := `{"command":"echo n","command_id":"n","shell_name":"dev"}`
	var first executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", plain, &first), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", named, nil), http.StatusOK)
	waitFor(t, "the ledger to settle", func() bool { return ledgerSettled(env.h, devbox.ID, mustRef(t, first.ExecutionID)) })

	execSQL(t, env.store, `UPDATE request_idempotency SET target_id = '{' WHERE scope = 'runloop.exec' AND fingerprint NOT LIKE '%/rln-%'`)
	execSQL(t, env.store, `UPDATE request_idempotency SET target_id = 'garbage' WHERE scope = 'runloop.exec' AND fingerprint LIKE '%/rln-%'`)
	env.h.execs.forgetDevbox(devbox.ID) // the output cache cannot answer either
	expectError(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", plain, nil))
	expectError(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", named, nil))
	if got := env.toolbox.execCount(); got != 2 {
		t.Fatalf("commands run = %d, want the original 2", got)
	}
}

// A restart pass that cannot read the ledger does not latch, and the
// background pass keeps trying until it can.
func TestRecoveryRetriesAFailedLedgerRead(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &recoveryBackoff, 50*time.Millisecond)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()

	// A process that died after submitting left this session behind.
	dead := execRef{session: plainSession(devbox.ID, "dead")}
	if _, _, err := env.h.claimLedger(ctx, ledgerKey(devbox.ID, dead)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.createSession(ctx, devbox.ID, dead.session); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.sessionExec(ctx, devbox.ID, dead.session, "echo orphan"); err != nil {
		t.Fatal(err)
	}

	execSQL(t, env.store, `ALTER TABLE request_idempotency RENAME TO request_idempotency_away`)
	restarted := newHandlers(env.h.deps)
	if err := restarted.recoverExecutions(ctx); err == nil {
		t.Fatal("a pass that cannot read the ledger must fail")
	}
	if restarted.recovery.done.Load() {
		t.Fatal("a failed pass must not latch")
	}
	restarted.recoverExecutionsInBackground()
	time.Sleep(10 * time.Millisecond)
	execSQL(t, env.store, `ALTER TABLE request_idempotency_away RENAME TO request_idempotency`)
	waitFor(t, "the background pass to succeed", restarted.recovery.done.Load)
	waitFor(t, "the orphaned session cleanup", func() bool { return env.toolbox.sessionCount() == 0 })
	waitFor(t, "the recovered row to settle", func() bool { return ledgerSettled(restarted, devbox.ID, dead) })
}

// Kill never rewrites history: a command that already finished keeps its
// real exit status, even after a restart has dropped the output cache.
func TestKillOfAFinishedExecutionKeepsItsExit(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"exit 7","command_id":"kfin"}`, &done), http.StatusOK)
	waitFor(t, "the ledger to settle", func() bool { return ledgerSettled(env.h, devbox.ID, mustRef(t, done.ExecutionID)) })

	restarted := newHandlers(env.h.deps)
	rr := httptest.NewRecorder()
	restarted.killExecution(rr, httptest.NewRequest(http.MethodPost, "/", nil), devbox.ID, done.ExecutionID)
	expectStatus(t, rr, http.StatusOK)
	var view executionView
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.ExitStatus == nil || *view.ExitStatus != 7 {
		t.Fatalf("kill of a finished execution = %+v, want its real exit 7", view)
	}
}

// Kill reports the kill even when the ledger cannot record it; the session
// is gone either way.
func TestKillSurvivesALedgerWriteFailure(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-kill"}`, &running, "X-Request-Id", "kill"), http.StatusOK)
	failLedger(t, env.store, "complete")
	var killed executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/executions/"+running.ExecutionID+"/kill", nil, &killed), http.StatusOK)
	if killed.ExitStatus == nil || *killed.ExitStatus != killedExitStatus {
		t.Fatalf("kill = %+v", killed)
	}
	if env.toolbox.sessionCount() != 0 {
		t.Fatal("kill left the session behind")
	}
	env.toolbox.unblock("block-kill")
}

// A session the toolbox no longer has (it restarted, say) is cleanup done,
// not cleanup failed: the watcher settles the row instead of retrying the
// delete for a day.
func TestCleanupOfAnAlreadyGoneSessionSettles(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	sid := plainSession(devbox.ID, "gone404")
	env.toolbox.failAlways("DELETE /process/session/"+sid, http.StatusNotFound)
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo hi","command_id":"gone404"}`, &done), http.StatusOK)
	ref := mustRef(t, done.ExecutionID)
	waitFor(t, "the ledger to settle", func() bool { return ledgerSettled(env.h, devbox.ID, ref) })
	waitFor(t, "the watcher to end", func() bool { return !watcherAlive(env.h.execs, resultKey(devbox.ID, ref.id())) })
}

// A toolbox that accepts a command without naming it did accept it: a plain
// session holds only this execution's command, so the facade finds it there
// and follows it like any other, rather than killing it and running the id
// again.
func TestSubmitWithoutACommandIDIsAdopted(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	env.toolbox.mu.Lock()
	env.toolbox.emptyCmdID = true
	env.toolbox.mu.Unlock()
	body := `{"command":"echo x","command_id":"noid"}`
	var first executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, &first), http.StatusOK)
	if first.Status != execStatusCompleted || first.Stdout == nil || *first.Stdout != "x\n" {
		t.Fatalf("adopted execution = %+v", first)
	}
	var retried executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, &retried), http.StatusOK)
	if retried.ExecutionID != first.ExecutionID || env.toolbox.execCount() != 1 {
		t.Fatalf("retry = %+v after %d runs; want the same execution, run once", retried, env.toolbox.execCount())
	}
}

// Each fault must break exactly its own write — otherwise a test above
// could pass without its fault ever firing — and only on the execution
// ledger's scope, not on other facades sharing request_idempotency.
func TestLedgerFaultsHitOnlyTheirWrite(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	steps := []string{"claim", "outcome", "complete", "release"}
	run := map[string]func(fingerprint string) error{
		"claim": func(fp string) error { _, _, err := env.h.claimLedger(ctx, fp); return err },
		"outcome": func(fp string) error {
			return env.svc.SetIdempotentRequestTarget(ctx, service.ExecLedgerScope, fp, service.ExecOutcome{}.Encode())
		},
		"complete": func(fp string) error { return env.h.completeLedger(ctx, fp, service.ExecOutcome{}.Encode()) },
		"release":  func(fp string) error { return env.svc.DeleteIdempotentRequest(ctx, service.ExecLedgerScope, fp) },
	}
	for _, fault := range steps {
		clear := failLedger(t, env.store, fault)
		fingerprint := "devbox/" + fault
		for _, step := range steps {
			err := run[step](fingerprint)
			if (err != nil) != (step == fault) {
				t.Errorf("with the %s fault, %s returned %v", fault, step, err)
			}
			if err != nil && step == "claim" {
				break // no row to walk further
			}
		}
		if _, _, err := env.svc.ClaimIdempotentRequest(ctx, "e2b.create", fingerprint, time.Now(), time.Minute); err != nil {
			t.Errorf("the %s fault leaked into another scope: %v", fault, err)
		}
		clear()
	}
}
