package runloop

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// loseExecReply makes the toolbox run the next submitted command and then
// answer 503: the command's side effects happen, only the reply is lost.
func loseExecReply(env *testEnv) {
	var once sync.Once
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec") {
			once.Do(func() {
				env.toolbox.serveSession(httptest.NewRecorder(), r, strings.TrimPrefix(r.URL.Path, "/process/session/"))
				env.toolbox.setFailNext(r.URL.Path, http.StatusServiceUnavailable)
			})
		}
	})
}

// loseSessionCreateReply makes the toolbox open the next session and then
// answer 503: the session exists in the guest, only the reply is lost.
func loseSessionCreateReply(env *testEnv) {
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/process/session" {
			env.toolbox.setBeforeServe(nil)
			env.toolbox.ServeHTTP(httptest.NewRecorder(), r)
			env.toolbox.setFailNext(r.URL.Path, http.StatusServiceUnavailable)
		}
	})
}

// A session whose create reply was lost may exist in the guest. No command
// went into it, so once it is deleted nothing ran and nothing is left: the
// claim is released and a retry of the same id runs the command once.
func TestLostSessionCreateReplyLeavesNothingBehind(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	loseSessionCreateReply(env)
	ref := execRef{session: plainSession(devbox.ID, "lost-create")}
	if _, err := env.h.startExecution(ctx, devbox.ID, "echo ok", "", "lost-create"); err == nil {
		t.Fatal("fault setup: the session create's reply was not lost")
	}
	if env.toolbox.sessionCount() != 0 {
		t.Fatal("the session the toolbox opened was left in the guest")
	}
	if _, err := env.svc.GetIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim after a confirmed delete = %v; want it released, since nothing ran", err)
	}
	if _, err := env.h.startExecution(ctx, devbox.ID, "echo ok", "", "lost-create"); err != nil {
		t.Fatal(err)
	}
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("the retry ran the command %d times; want 1", got)
	}
}

// If that session cannot be deleted either, the claim stays and a watcher
// owns the session: once the toolbox lets it, the watcher deletes the
// session and settles the execution, with no retry or restart needed.
func TestLostSessionCreateReplyWithFailedDeleteKeepsAWatcher(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &submitGrace, 20*time.Millisecond)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	ref := execRef{session: plainSession(devbox.ID, "stuck-create")}
	key := resultKey(devbox.ID, ref.id())
	loseSessionCreateReply(env)
	env.toolbox.failAlways("DELETE /process/session/"+ref.session, http.StatusServiceUnavailable)
	if _, err := env.h.startExecution(ctx, devbox.ID, "echo ok", "", "stuck-create"); err == nil {
		t.Fatal("fault setup: the session create's reply was not lost")
	}
	time.Sleep(80 * time.Millisecond)
	if !watcherAlive(env.h.execs, key) || env.toolbox.sessionCount() != 1 {
		t.Fatal("a session that could not be deleted has no owner")
	}
	if _, err := env.svc.GetIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref)); err != nil {
		t.Fatalf("the claim was dropped with the session still in the guest: %v", err)
	}
	env.toolbox.clearFaults()
	waitFor(t, "the session deleted and the execution settled", func() bool {
		outcome, _, ok := env.h.ledgerOutcome(ctx, devbox.ID, ref)
		return ok && outcome.Lost && env.toolbox.sessionCount() == 0 && !watcherAlive(env.h.execs, key)
	})
	if env.toolbox.execCount() != 0 {
		t.Fatal("a command ran though none was submitted")
	}
}

// A lost reply is not a refusal: the command may already have done its
// work, so a retry of the same command id must never run it again. A plain
// execution finds the command in its own session and follows it; a named
// one cannot tell its command apart in the shared shell, so its retry is
// told to pick a new id instead.
func TestLostSubmitReplyNeverRunsTwice(t *testing.T) {
	for _, shell := range []string{"", "persistent"} {
		t.Run("shell="+shell, func(t *testing.T) {
			env := newTestEnv(t)
			shorten(t, &submitWait, 50*time.Millisecond)
			devbox := env.mustCreate(t, "")
			loseExecReply(env)
			first, err := env.h.startExecution(context.Background(), devbox.ID, "echo side-effect", shell, "same-key")
			if env.toolbox.execCount() != 1 {
				t.Fatalf("fault setup: %d runs", env.toolbox.execCount())
			}
			if shell == "" && err != nil {
				t.Fatalf("a plain command whose reply was lost is in its session, so the submit succeeds: %v", err)
			}
			retried, err := env.h.startExecution(context.Background(), devbox.ID, "echo side-effect", shell, "same-key")
			if got := env.toolbox.execCount(); got != 1 {
				t.Fatalf("the same command id ran %d times after a lost reply", got)
			}
			if shell == "" && (err != nil || retried != first) {
				t.Fatalf("plain retry = %v, %v; want the original execution", retried, err)
			}
			if shell != "" && (err == nil || !strings.Contains(err.Error(), "new command id")) {
				t.Fatalf("named retry = %v; want to be told to pick a new id", err)
			}
		})
	}
}

// When the reply is lost and the session cannot be deleted either, the
// pending row still has an owner: a watcher holds the cleanup until the
// toolbox lets it finish, without the client retrying or sandboxd
// restarting.
func TestLostReplyWithFailedCleanupKeepsAWatcher(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	loseExecReply(env)
	ref := execRef{session: plainSession(devbox.ID, "cleanup-failure")}
	env.toolbox.failAlways("DELETE /process/session/"+ref.session, http.StatusServiceUnavailable)
	if _, err := env.h.startExecution(context.Background(), devbox.ID, "echo done", "", "cleanup-failure"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if !watcherAlive(env.h.execs, resultKey(devbox.ID, ref.id())) || env.toolbox.sessionCount() != 1 {
		t.Fatal("a session whose cleanup keeps failing has no owner")
	}
	if _, owed, ok := env.h.ledgerOutcome(context.Background(), devbox.ID, ref); !ok || !owed {
		t.Fatal("the outcome must be stored while cleanup is still owed")
	}
	env.toolbox.clearFaults()
	waitFor(t, "the watcher to finish the cleanup", func() bool {
		return env.toolbox.sessionCount() == 0 && ledgerSettled(env.h, devbox.ID, ref)
	})
}

// A pending row is cleanup owed however old it is. The sweep, which runs on
// wall-clock time, must not collect it a day later — not while its command
// runs, nor while its devbox sleeps — and a restart must still find it.
// Once settled, the row ages out like any replay record.
func TestPendingRowsSurviveTheSweep(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	ref := execRef{session: plainSession(devbox.ID, "long")}
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-long"}`, &running, "X-Request-Id", "long"), http.StatusOK)
	defer env.toolbox.unblock("block-long")
	if running.ExecutionID != ref.id() {
		t.Fatalf("execution id = %s", running.ExecutionID)
	}

	dayLater := time.Now().Add(service.ExecLedgerTTL + time.Hour)
	if _, err := env.store.DeleteExpiredIdempotentRequests(ctx, dayLater, 500); err != nil {
		t.Fatal(err)
	}
	rec, err := env.svc.GetIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref))
	if err != nil || rec.State != models.RequestStatePending {
		t.Fatalf("a day-old pending row was swept: %+v, %v", rec, err)
	}
	// Nor can a retry a day later claim it afresh and run the command again.
	if _, acquired, err := env.svc.ClaimIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref), dayLater, service.ExecObligationHold); err != nil || acquired {
		t.Fatalf("a day-old pending row was re-claimed: acquired=%v err=%v", acquired, err)
	}
	restarted := newHandlers(env.h.deps)
	if err := restarted.recoverExecutions(ctx); err != nil {
		t.Fatal(err)
	}
	if !watcherAlive(restarted.execs, resultKey(devbox.ID, ref.id())) {
		t.Fatal("a restart lost the long-running execution")
	}

	env.toolbox.unblock("block-long")
	waitFor(t, "the execution to settle", func() bool { return ledgerSettled(env.h, devbox.ID, ref) })
	if _, err := env.store.DeleteExpiredIdempotentRequests(ctx, time.Now().Add(service.ExecLedgerTTL+time.Minute), 500); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.GetIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref)); err == nil {
		t.Fatal("a settled row outlived its replay window")
	}
}

// The restart pass walks every page of pending rows. Named claims, which it
// skips, take whole pages without starving the plain executions after them,
// and the pass latches done only at the end. Rows claimed after the pass
// began belong to live requests and are left to them.
func TestRecoveryWalksEveryPage(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &recoveryPagePause, time.Millisecond)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	before := time.Now().Add(-time.Hour)
	for i := range 2*recoveryPageRows + 1 {
		if _, _, err := env.svc.ClaimIdempotentRequest(ctx, service.ExecLedgerScope, fmt.Sprintf("%s/rln-%08x", devbox.ID, i), before, service.ExecLedgerTTL); err != nil {
			t.Fatal(err)
		}
	}
	// "rlx-" sorts after "rln-", so this row is on the last page.
	ref := execRef{session: plainSession(devbox.ID, "last-pending")}
	if _, _, err := env.svc.ClaimIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref), before, service.ExecObligationHold); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.createSession(ctx, devbox.ID, ref.session); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.sessionExec(ctx, devbox.ID, ref.session, "echo finished"); err != nil {
		t.Fatal(err)
	}
	if err := env.h.recoverExecutions(ctx); err != nil {
		t.Fatal(err)
	}
	if !env.h.recovery.done.Load() {
		t.Fatal("the pass did not latch")
	}
	waitFor(t, "the last page's execution to be cleaned up", func() bool {
		return env.toolbox.sessionCount() == 0 && ledgerSettled(env.h, devbox.ID, ref)
	})

	// A pass that began before a row was claimed leaves that row alone.
	fresh := execRef{session: plainSession(devbox.ID, "fresh")}
	if _, _, err := env.h.claimLedger(ctx, ledgerKey(devbox.ID, fresh)); err != nil {
		t.Fatal(err)
	}
	restarted := newHandlers(env.h.deps)
	restarted.recovery.cutoff = time.Now().Add(-time.Minute)
	if err := restarted.recoverExecutions(ctx); err != nil {
		t.Fatal(err)
	}
	if watcherAlive(restarted.execs, resultKey(devbox.ID, fresh.id())) {
		t.Fatal("the pass took over a row claimed after it began")
	}
}
