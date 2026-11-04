package runloop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A ledger row whose outcome is stored but whose session is already gone is
// settled by the next watcher, not left owing cleanup forever.
func TestWatcherSettlesLedgerWhenSessionIsGone(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	ref := execRef{session: plainSession(devbox.ID, "settle")}
	key := ledgerKey(devbox.ID, ref)
	if _, _, err := env.h.claimLedger(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.SetIdempotentRequestTarget(ctx, service.ExecLedgerScope, key, service.ExecOutcome{Exit: 4}.Encode()); err != nil {
		t.Fatal(err)
	}

	// A reader sees the outcome, and since cleanup is owed it starts the
	// watcher that settles the row.
	state, err := env.h.executionState(ctx, devbox.ID, ref)
	if err != nil || !state.completed || state.exit != 4 {
		t.Fatalf("state = %+v, %v", state, err)
	}
	waitFor(t, "the ledger to settle", func() bool {
		_, owed, ok := env.h.ledgerOutcome(ctx, devbox.ID, ref)
		return ok && !owed
	})

	// A row nobody claimed has nothing to settle.
	if !env.h.settleLedger(ctx, devbox.ID, execRef{session: plainSession(devbox.ID, "nothing")}, false, watchPace{grace: time.Minute}) {
		t.Fatal("an unclaimed execution left its watcher something to do")
	}
	if _, _, ok := env.h.ledgerOutcome(ctx, devbox.ID, execRef{session: "rls-00", command: "01"}); ok {
		t.Fatal("a named execution has no ledger outcome")
	}
}

// Readers fall back to the ledger, and a retry joining a claimed execution
// accepts a finished one, whatever order the watcher's steps land in.
func TestReadersFallBackToTheLedger(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()

	// The live read fails, but the ledger already holds the outcome.
	ref := execRef{session: plainSession(devbox.ID, "fallback")}
	exit := int32(0)
	env.toolbox.mu.Lock()
	env.toolbox.sessions[ref.session] = &fakeSession{commands: []*fakeCommand{{id: "00000000000000bb", command: "echo", exitCode: &exit}}}
	env.toolbox.mu.Unlock()
	logsPath := "/process/session/" + ref.session + "/command/00000000000000bb/logs"
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if r.URL.Path == logsPath {
			key := ledgerKey(devbox.ID, ref)
			_, _, _ = env.h.claimLedger(ctx, key)
			_ = env.h.completeLedger(ctx, key, service.ExecOutcome{Exit: 9, StdoutLen: 3}.Encode())
		}
	})
	env.toolbox.setFailNext(logsPath, http.StatusNotFound)
	state, err := env.h.executionState(ctx, devbox.ID, ref)
	if err != nil || state.exit != 9 || !state.stdoutCut() {
		t.Fatalf("ledger fallback = %+v, %v", state, err)
	}
	env.toolbox.setBeforeServe(nil)

	// awaitSubmitted: the session is gone because the execution finished.
	shorten(t, &submitWait, 20*time.Millisecond)
	if err := env.h.awaitSubmitted(ctx, devbox.ID, execRef{session: plainSession(devbox.ID, "fallback")}); err != nil {
		t.Fatalf("finished execution (ledger) = %v", err)
	}
	cached := execRef{session: plainSession(devbox.ID, "cached")}
	env.h.execs.record(&execResult{key: resultKey(devbox.ID, cached.id())})
	if err := env.h.awaitSubmitted(ctx, devbox.ID, cached); err != nil {
		t.Fatalf("finished execution (cache) = %v", err)
	}
	var reqErr requestError
	if err := env.h.awaitSubmitted(ctx, devbox.ID, execRef{session: plainSession(devbox.ID, "never")}); err == nil {
		t.Fatal("a claim with no session and no outcome must conflict")
	} else if !asRequestError(err, &reqErr) || reqErr.status != http.StatusConflict {
		t.Fatalf("never-submitted = %v", err)
	}
}

func asRequestError(err error, target *requestError) bool {
	re, ok := err.(requestError)
	if ok {
		*target = re
	}
	return ok
}

// A devbox that stops while its finished execution still owes cleanup:
// the watcher waits on the sandbox row (never waking it through the
// toolbox) and finishes once the devbox runs again.
func TestCleanupWaitsForAStoppedDevbox(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &watchMaxBackoff, 10*time.Millisecond)
	shorten(t, &watchIdleBackoff, 10*time.Millisecond)
	devbox := env.mustCreate(t, "")
	sid := plainSession(devbox.ID, "stopped")
	env.toolbox.failAlways("DELETE /process/session/"+sid, http.StatusServiceUnavailable)
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo hi","command_id":"stopped"}`, &done), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/suspend", nil, nil), http.StatusOK)
	// Let a delete already in flight during the suspend settle (as a
	// failure) before the toolbox would accept one.
	time.Sleep(30 * time.Millisecond)
	env.toolbox.clearFaults()
	time.Sleep(50 * time.Millisecond)
	if env.toolbox.sessionCount() != 1 {
		t.Fatal("cleanup reached the toolbox of a stopped devbox")
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/resume", nil, nil), http.StatusOK)
	waitFor(t, "cleanup after resume", func() bool { return env.toolbox.sessionCount() == 0 })

	// The same wait while the command still runs: a stopped devbox's
	// watcher idles instead of polling the toolbox.
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-idle"}`, &running, "X-Request-Id", "idle"), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/suspend", nil, nil), http.StatusOK)
	time.Sleep(30 * time.Millisecond)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/resume", nil, nil), http.StatusOK)
	env.toolbox.unblock("block-idle")
	waitFor(t, "the resumed execution to finish", func() bool { return env.toolbox.sessionCount() == 0 })

	// A devbox destroyed while its cleanup is failing ends the watcher.
	gone := plainSession(devbox.ID, "gone")
	env.toolbox.failAlways("DELETE /process/session/"+gone, http.StatusServiceUnavailable)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo bye","command_id":"gone"}`, nil), http.StatusOK)
	if err := env.svc.DestroySandbox(context.Background(), devbox.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the watcher to stop", func() bool { return !watcherAlive(env.h.execs, resultKey(devbox.ID, gone)) })
}

// watcherAlive reports whether a watcher goroutine still holds key.
func watcherAlive(tr *execTracker, key string) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	_, ok := tr.watchers[key]
	return ok
}

// forwardToNode answers locally for this node, transiently for a member
// that is down, and permanently for one that left.
func TestForwardToNodeCases(t *testing.T) {
	env := newTestEnv(t)
	c := newNodeCluster("self")
	c.peers["down"] = http.NotFoundHandler()
	env.svc.AttachCluster(&downCluster{nodeCluster: c})
	local := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }

	for _, tc := range []struct {
		node      string
		want      int
		retryable bool
	}{
		{"self", http.StatusTeapot, true},
		{"down", http.StatusServiceUnavailable, true},
		{"departed", http.StatusServiceUnavailable, false},
	} {
		rr := httptest.NewRecorder()
		env.h.forwardToNode(rr, httptest.NewRequest(http.MethodGet, "/", nil), tc.node, local)
		if rr.Code != tc.want || (rr.Header().Get("x-should-retry") == "false") == tc.retryable {
			t.Errorf("%s: status %d retry header %q", tc.node, rr.Code, rr.Header().Get("x-should-retry"))
		}
	}
}

// downCluster reports its peer as a member that is not alive.
type downCluster struct{ *nodeCluster }

func (c *downCluster) Members() []cluster.Member {
	return []cluster.Member{
		{NodeID: "self", Alive: true},
		{NodeID: "down", Alive: false, InternalURL: "https://down"},
	}
}

func TestSnapshotNodeSegmentNeedsAValidNodeID(t *testing.T) {
	env := newTestEnv(t)
	if env.h.snapshotNodeSegment() != "" {
		t.Fatal("a single node mints unbound ids")
	}
	env.svc.AttachCluster(newNodeCluster("bad id with spaces"))
	if env.h.snapshotNodeSegment() != "" {
		t.Fatal("an unencodable node id must leave ids unbound")
	}
	env.svc.AttachCluster(newNodeCluster("worker-7"))
	encoded, _ := models.EncodeNodeAffinity("worker-7")
	if env.h.snapshotNodeSegment() != encoded+"." {
		t.Fatal("cluster ids carry the node")
	}
}

// A named shell's watcher only serves readers: it starts when one asks and
// stops once they stop asking, even while the command keeps running.
func TestNamedWatcherStopsWhenNobodyAsks(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &namedWatchIdle, 30*time.Millisecond)
	shorten(t, &watchMaxBackoff, 10*time.Millisecond)
	devbox := env.mustCreate(t, "")
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-named","shell_name":"dev"}`, &running, "X-Request-Id", "named"), http.StatusOK)
	key := resultKey(devbox.ID, running.ExecutionID)
	waitFor(t, "the idle named watcher to stop", func() bool { return !watcherAlive(env.h.execs, key) })

	// A reader brings it back, and it signals that reader on completion.
	go func() {
		time.Sleep(20 * time.Millisecond)
		env.toolbox.unblock("block-named")
	}()
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/executions/"+running.ExecutionID+"/wait_for_status", `{"statuses":["completed"]}`, &done), http.StatusOK)
	if done.Status != execStatusCompleted {
		t.Fatalf("named execution = %+v", done)
	}
}
