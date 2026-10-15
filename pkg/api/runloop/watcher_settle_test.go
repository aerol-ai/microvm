package runloop

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
)

// A watcher that cannot settle its row yet keeps the obligation instead of
// ending with it open. The store may not answer, or the toolbox may refuse
// to delete the empty session. Once both work, the watcher fences the
// session and settles the row as lost.
func TestWatcherHoldsAnUnsubmittedExecutionThroughFailures(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &submitGrace, 20*time.Millisecond)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	ref := execRef{session: plainSession(devbox.ID, "stuck")}
	key := resultKey(devbox.ID, ref.id())
	if _, _, err := env.h.claimLedger(ctx, ledgerKey(devbox.ID, ref)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.createSession(ctx, devbox.ID, ref.session); err != nil {
		t.Fatal(err)
	}

	execSQL(t, env.store, `ALTER TABLE request_idempotency RENAME TO request_idempotency_away`)
	env.h.startWatcher(ctx, devbox.ID, ref, false)
	time.Sleep(80 * time.Millisecond)
	if !watcherAlive(env.h.execs, key) || env.toolbox.sessionCount() != 1 {
		t.Fatal("with the ledger unreadable the watcher must wait, not fence")
	}
	env.toolbox.failAlways("DELETE /process/session/"+ref.session, http.StatusServiceUnavailable)
	execSQL(t, env.store, `ALTER TABLE request_idempotency_away RENAME TO request_idempotency`)
	time.Sleep(80 * time.Millisecond)
	if !watcherAlive(env.h.execs, key) || env.toolbox.sessionCount() != 1 {
		t.Fatal("a session the toolbox will not delete must stay watched")
	}
	env.toolbox.clearFaults()
	waitFor(t, "the session to be fenced and the row settled", func() bool {
		outcome, _, ok := env.h.ledgerOutcome(ctx, devbox.ID, ref)
		return ok && outcome.Lost && env.toolbox.sessionCount() == 0 && !watcherAlive(env.h.execs, key)
	})
}

// A session that never appeared is settled the same way, once the store
// answers. A devbox that is gone settles its rows at once, grace or not, and
// its watcher keeps trying until the completion write lands.
func TestWatcherSettlesThroughStoreFailures(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &submitGrace, 20*time.Millisecond)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	shorten(t, &watchIdleBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()

	never := execRef{session: plainSession(devbox.ID, "never")}
	if _, _, err := env.h.claimLedger(ctx, ledgerKey(devbox.ID, never)); err != nil {
		t.Fatal(err)
	}
	execSQL(t, env.store, `ALTER TABLE request_idempotency RENAME TO request_idempotency_away`)
	env.h.startWatcher(ctx, devbox.ID, never, false)
	time.Sleep(80 * time.Millisecond)
	if !watcherAlive(env.h.execs, resultKey(devbox.ID, never.id())) {
		t.Fatal("the watcher ended without settling its row")
	}
	execSQL(t, env.store, `ALTER TABLE request_idempotency_away RENAME TO request_idempotency`)
	waitFor(t, "the missing session's row to settle", func() bool {
		outcome, _, ok := env.h.ledgerOutcome(ctx, devbox.ID, never)
		return ok && outcome.Lost
	})

	running := execRef{session: plainSession(devbox.ID, "running")}
	if _, _, err := env.h.claimLedger(ctx, ledgerKey(devbox.ID, running)); err != nil {
		t.Fatal(err)
	}
	clear := failLedger(t, env.store, "complete")
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/shutdown", nil, nil), http.StatusOK)
	env.h.startWatcher(ctx, devbox.ID, running, false)
	time.Sleep(80 * time.Millisecond)
	if !watcherAlive(env.h.execs, resultKey(devbox.ID, running.id())) {
		t.Fatal("the watcher of a deleted devbox ended with its row unsettled")
	}
	clear()
	waitFor(t, "the deleted devbox's row to settle", func() bool {
		outcome, _, ok := env.h.ledgerOutcome(ctx, devbox.ID, running)
		return ok && outcome.Lost && !watcherAlive(env.h.execs, resultKey(devbox.ID, running.id()))
	})
}

// A row that turns lost between two reads still reads as lost: from a retry
// waiting for the command, and from a reader whose live read lost the race.
func TestLostBetweenReads(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	ref := execRef{session: plainSession(devbox.ID, "raced")}
	if _, _, err := env.h.claimLedger(ctx, ledgerKey(devbox.ID, ref)); err != nil {
		t.Fatal(err)
	}
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/"+ref.session) {
			_ = env.h.completeLedger(ctx, ledgerKey(devbox.ID, ref), service.ExecOutcome{Lost: true}.Encode())
		}
	})
	if _, err := env.h.executionState(ctx, devbox.ID, ref); !errors.Is(err, errExecutionLost) {
		t.Fatalf("reader = %v, want the execution lost", err)
	}
	if err := env.h.awaitSubmitted(ctx, devbox.ID, ref); err == nil || !strings.Contains(err.Error(), "new command id") {
		t.Fatalf("waiting retry = %v, want to be told to pick a new id", err)
	}
}
