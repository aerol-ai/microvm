package runloop

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// outputChunks is the only place a truncated stream's offsets are worked
// out, and the SDK resumes from whatever offset it last saw, so every edge
// of the arithmetic is pinned here rather than through 1 MiB fixtures.
func TestOutputChunksOffsets(t *testing.T) {
	type chunk struct {
		output string
		offset int64
	}
	for _, tc := range []struct {
		name          string
		output        string
		total, offset int64
		want          []chunk
	}{
		{"whole stream", "abc", 3, 0, []chunk{{"abc", 3}}},
		{"resume inside", "abc", 3, 1, []chunk{{"bc", 3}}},
		{"resume at the end", "abc", 3, 3, nil},
		{"resume past the end", "abc", 3, 9, nil},
		{"empty stream", "", 0, 0, nil},
		{"tail only", "xyz", 10, 0, []chunk{{"[AerolVM: 7 earlier bytes of stdout were not kept", 7}, {"xyz", 10}}},
		{"resume inside the dropped part", "xyz", 10, 5, []chunk{{"[AerolVM: 2 earlier bytes of stdout were not kept", 7}, {"xyz", 10}}},
		{"resume where the tail starts", "xyz", 10, 7, []chunk{{"xyz", 10}}},
		{"resume inside the tail", "xyz", 10, 8, []chunk{{"yz", 10}}},
		{"length unknown", "", -1, 0, []chunk{{"[AerolVM: this command's stdout was too large to keep", 0}}},
		{"length unknown, resumed", "", -1, 1, nil},
	} {
		got := outputChunks(tc.output, tc.total, tc.offset, "stdout")
		if len(got) != len(tc.want) {
			t.Errorf("%s: %d chunks %+v, want %d", tc.name, len(got), got, len(tc.want))
			continue
		}
		for i, want := range tc.want {
			// Notices are prose; match their opening words, and the data
			// chunks exactly.
			if !strings.HasPrefix(got[i].Output, want.output) || got[i].Offset != want.offset {
				t.Errorf("%s: chunk %d = %q @ %d, want %q @ %d", tc.name, i, got[i].Output, got[i].Offset, want.output, want.offset)
			}
		}
	}
}

func TestKeepTailBoundary(t *testing.T) {
	exact := strings.Repeat("a", maxCapturedStream)
	if kept, n := keepTail(exact); kept != exact || n != int64(maxCapturedStream) {
		t.Fatalf("a stream of exactly the cap must be kept whole (kept %d of %d)", len(kept), n)
	}
	over := "b" + exact
	kept, n := keepTail(over)
	if kept != exact || n != int64(maxCapturedStream+1) {
		t.Fatalf("one byte over the cap must drop exactly that byte (kept %d, length %d)", len(kept), n)
	}
	state := execState{stdout: kept, stdoutLen: n}
	if !state.stdoutCut() || (execState{stdout: exact, stdoutLen: int64(len(exact))}).stdoutCut() {
		t.Fatal("stdoutCut must report exactly the truncated stream")
	}
}

// Whoever records an execution's result first decides how it ended: a kill
// racing the watcher must not have its 137 overwritten by a later exit 0,
// or the reverse.
func TestExecTrackerFirstRecordWins(t *testing.T) {
	tr := newExecTracker()
	first := tr.record(&execResult{key: "d/x", exit: killedExitStatus})
	if got := tr.record(&execResult{key: "d/x", exit: 0, stdout: "late"}); got != first || got.exit != killedExitStatus || got.stdout != "" {
		t.Fatalf("second record = %+v, want the first", got)
	}
	if tr.bytes != 0 {
		t.Fatalf("a rejected record was counted: %d bytes", tr.bytes)
	}
}

// A claimed execution whose command is not in its session yet reads as
// running, and its watcher waits instead of treating the empty session as
// finished.
func TestExecutionWithNoCommandYetReadsRunning(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	sid := plainSession(devbox.ID, "unsubmitted")
	if _, err := env.h.createSession(context.Background(), devbox.ID, sid); err != nil {
		t.Fatal(err)
	}
	var view executionView
	expectStatus(t, env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+sid, nil, &view), http.StatusOK)
	if view.Status != execStatusRunning || view.ExitStatus != nil {
		t.Fatalf("unsubmitted execution = %+v", view)
	}
	time.Sleep(50 * time.Millisecond)
	if !watcherAlive(env.h.execs, resultKey(devbox.ID, sid)) || env.toolbox.sessionCount() != 1 {
		t.Fatal("the watcher must keep waiting on an empty session, not clean it up")
	}
	if err := env.h.deleteSession(context.Background(), devbox.ID, sid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the watcher to stop", func() bool { return !watcherAlive(env.h.execs, resultKey(devbox.ID, sid)) })
}

func TestMalformedExecutionIDsAreNotFound(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	for _, id := range []string{"bogus", "rlx-", "rlx-zz", "rls-00", "rls-00.", "rls-.00", "rls-00.zz", "rlx-" + strings.Repeat("0", 66)} {
		expectStatus(t, env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+id, nil, nil), http.StatusNotFound)
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/executions/"+id+"/wait_for_status", `{"statuses":["completed"]}`, nil), http.StatusNotFound)
	}
	if env.toolbox.sessionCount() != 0 {
		t.Fatal("a malformed id reached the toolbox")
	}
}

// brokenStream is a client that has gone away: every write fails.
type brokenStream struct{ header http.Header }

func (b *brokenStream) Header() http.Header {
	if b.header == nil {
		b.header = http.Header{}
	}
	return b.header
}
func (b *brokenStream) WriteHeader(int)           {}
func (b *brokenStream) Write([]byte) (int, error) { return 0, errors.New("client went away") }
func (b *brokenStream) Flush()                    {}

// An output stream ends as soon as its client is gone, whether the server
// notices on a heartbeat write or through the request context, instead of
// holding a goroutine until the command finishes.
func TestStreamStopsWhenTheClientLeaves(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-sse"}`, &running), http.StatusOK)
	defer env.toolbox.unblock("block-sse")

	returned := func(serve func()) bool {
		done := make(chan struct{})
		go func() { serve(); close(done) }()
		select {
		case <-done:
			return true
		case <-time.After(5 * time.Second):
			return false
		}
	}

	// The heartbeat write is what fails.
	shorten(t, &sseHeartbeat, 5*time.Millisecond)
	if !returned(func() {
		env.h.streamOutput(&brokenStream{}, httptest.NewRequest(http.MethodGet, "/", nil), devbox.ID, running.ExecutionID, false)
	}) {
		t.Fatal("the stream kept running after a heartbeat write failed")
	}

	// The request context ends between heartbeats.
	sseHeartbeat = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	rr := httptest.NewRecorder()
	if !returned(func() {
		env.h.streamOutput(rr, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx), devbox.ID, running.ExecutionID, true)
	}) {
		t.Fatal("the stream kept running after its client left")
	}
	if strings.Contains(rr.Body.String(), "data:") {
		t.Fatalf("an abandoned stream sent output: %q", rr.Body.String())
	}
}
