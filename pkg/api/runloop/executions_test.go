package runloop

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestExecuteCompletesAndCleansUpSession(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var view executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo hello","command_id":"cmd-1"}`, &view), http.StatusOK)
	if view.Status != execStatusCompleted || view.ExitStatus == nil || *view.ExitStatus != 0 {
		t.Fatalf("execute = %+v", view)
	}
	if view.Stdout == nil || *view.Stdout != "hello\n" || view.StdoutTruncated == nil || *view.StdoutTruncated {
		t.Fatalf("stdout = %v truncated=%v", view.Stdout, view.StdoutTruncated)
	}
	if !strings.HasPrefix(view.ExecutionID, ephemeralPrefix) || view.DevboxID != devbox.ID {
		t.Fatalf("ids = %s / %s", view.ExecutionID, view.DevboxID)
	}
	// The captured result outlives the session, which is not left idle.
	waitFor(t, "session cleanup", func() bool { return env.toolbox.sessionCount() == 0 })
	var got executionView
	expectStatus(t, env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+view.ExecutionID, nil, &got), http.StatusOK)
	if got.Status != execStatusCompleted || got.Stdout == nil || *got.Stdout != "hello\n" {
		t.Fatalf("retrieve after cleanup = %+v", got)
	}

	// A retry with the same command_id returns the same execution and
	// does not run the command again.
	var retry executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo hello","command_id":"cmd-1"}`, &retry), http.StatusOK)
	if retry.ExecutionID != view.ExecutionID || env.toolbox.execCount() != 1 {
		t.Fatalf("retry ran again: %s vs %s, execs=%d", retry.ExecutionID, view.ExecutionID, env.toolbox.execCount())
	}
}

func TestExecuteNonZeroExit(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var view executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"exit 3","command_id":"x"}`, &view), http.StatusOK)
	if view.ExitStatus == nil || *view.ExitStatus != 3 || view.Stderr == nil || *view.Stderr != "exiting\n" {
		t.Fatalf("exit = %+v", view)
	}
}

func TestExecuteAsyncWaitAndLastN(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var started executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-1"}`, &started, "X-Request-Id", "async-1"), http.StatusOK)
	if started.Status != execStatusRunning || started.ExitStatus != nil {
		t.Fatalf("async start = %+v", started)
	}
	path := "/" + devbox.ID + "/executions/" + started.ExecutionID
	// Not done yet: the long-poll expires with 408.
	expectStatus(t, env.do(t, http.MethodPost, path+"/wait_for_status", `{"statuses":["completed"],"timeout_seconds":0.05}`, nil), http.StatusRequestTimeout)
	// A wait for running (or queued) is satisfied right away.
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, path+"/wait_for_status", `{"statuses":["queued"]}`, &running), http.StatusOK)
	if running.Status != execStatusRunning {
		t.Fatalf("queued wait = %+v", running)
	}

	env.toolbox.unblock("block-1")
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, path+"/wait_for_status", `{"statuses":["completed"],"timeout_seconds":5}`, &done), http.StatusOK)
	if done.Status != execStatusCompleted {
		t.Fatalf("after unblock = %+v", done)
	}
	// A completed execution answers a wait for running at once.
	expectStatus(t, env.do(t, http.MethodPost, path+"/wait_for_status", `{"statuses":["running"]}`, &done), http.StatusOK)

	var lines executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute?last_n=2", `{"command":"lines 5","command_id":"l5"}`, &lines), http.StatusOK)
	if lines.Stdout == nil || *lines.Stdout != "line 4\nline 5\n" || lines.StdoutTruncated == nil || !*lines.StdoutTruncated {
		t.Fatalf("last_n = %q truncated=%v", deref(lines.Stdout), lines.StdoutTruncated)
	}
	expectStatus(t, env.do(t, http.MethodPost, path+"/wait_for_status", `{}`, nil), http.StatusBadRequest)
}

func TestExecuteOptimisticTimeoutReturnsRunning(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var view executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"block-opt","command_id":"o1","optimistic_timeout":0.05}`, &view), http.StatusOK)
	if view.Status != execStatusRunning {
		t.Fatalf("optimistic = %+v", view)
	}
	env.toolbox.unblock("block-opt")
}

func TestExecuteSyncBlocksUntilDone(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var detail executionDetailView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_sync", `{"command":"echo sync"}`, &detail), http.StatusOK)
	if detail.ExitStatus != 0 || detail.Stdout != "sync\n" || detail.DevboxID != devbox.ID {
		t.Fatalf("execute_sync = %+v", detail)
	}
}

func TestNamedShellExecutions(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var first, second, retry executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo one","command_id":"n1","shell_name":"main"}`, &first), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo two","command_id":"n2","shell_name":"main"}`, &second), http.StatusOK)
	if !strings.HasPrefix(first.ExecutionID, shellPrefix) || first.ExecutionID == second.ExecutionID {
		t.Fatalf("named ids = %s %s", first.ExecutionID, second.ExecutionID)
	}
	sessFirst, _, _ := strings.Cut(first.ExecutionID, ".")
	sessSecond, _, _ := strings.Cut(second.ExecutionID, ".")
	if sessFirst != sessSecond {
		t.Fatal("one shell name mapped to two sessions")
	}
	if first.ShellName == nil || *first.ShellName != "main" || second.Stdout == nil || *second.Stdout != "two\n" {
		t.Fatalf("named view = %+v / %+v", first, second)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo one","command_id":"n1","shell_name":"main"}`, &retry), http.StatusOK)
	if retry.ExecutionID != first.ExecutionID || env.toolbox.execCount() != 2 {
		t.Fatalf("named retry ran again: %s, execs=%d", retry.ExecutionID, env.toolbox.execCount())
	}
	// The named shell persists: it is not cleaned up like a plain one.
	if env.toolbox.sessionCount() != 1 {
		t.Fatalf("sessions = %d, want the named shell", env.toolbox.sessionCount())
	}
	var got executionView
	expectStatus(t, env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+second.ExecutionID, nil, &got), http.StatusOK)
	if got.Status != execStatusCompleted {
		t.Fatalf("named retrieve = %+v", got)
	}

	// Killing a named-shell execution ends the shell.
	var async executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-named","shell_name":"main"}`, &async), http.StatusOK)
	var killed executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/executions/"+async.ExecutionID+"/kill", `{}`, &killed), http.StatusOK)
	if killed.ExitStatus == nil || *killed.ExitStatus != killedExitStatus {
		t.Fatalf("named kill = %+v", killed)
	}
	env.toolbox.unblock("block-named")
}

func TestKillExecution(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var started executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-kill"}`, &started), http.StatusOK)
	path := "/" + devbox.ID + "/executions/" + started.ExecutionID
	var killed executionView
	expectStatus(t, env.do(t, http.MethodPost, path+"/kill", `{"kill_process_group":true}`, &killed), http.StatusOK)
	if killed.Status != execStatusCompleted || killed.ExitStatus == nil || *killed.ExitStatus != killedExitStatus {
		t.Fatalf("kill = %+v", killed)
	}
	// A second kill reports the same outcome.
	expectStatus(t, env.do(t, http.MethodPost, path+"/kill", nil, &killed), http.StatusOK)
	env.toolbox.unblock("block-kill")

	// Killing a finished command keeps its real exit status.
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"exit 4","command_id":"k2"}`, &done), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/executions/"+done.ExecutionID+"/kill", nil, &killed), http.StatusOK)
	if killed.ExitStatus == nil || *killed.ExitStatus != 4 {
		t.Fatalf("kill after exit = %+v", killed)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/executions/rlx-0123456789abcdef/kill", nil, nil), http.StatusNotFound)
}

func TestSendStdin(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var started executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-stdin","attach_stdin":true}`, &started), http.StatusOK)
	path := "/" + devbox.ID + "/executions/" + started.ExecutionID + "/send_std_in"
	var resp sendStdinResponse
	expectStatus(t, env.do(t, http.MethodPost, path, `{"text":"yes\n"}`, &resp), http.StatusOK)
	if !resp.Success || resp.ExecutionID != started.ExecutionID {
		t.Fatalf("stdin = %+v", resp)
	}
	if len(env.toolbox.inputs) != 1 || env.toolbox.inputs[0] != "yes\n" {
		t.Fatalf("toolbox got %q", env.toolbox.inputs)
	}
	expectStatus(t, env.do(t, http.MethodPost, path, `{"signal":"EOF"}`, nil), http.StatusNotImplemented)
	expectStatus(t, env.do(t, http.MethodPost, path, `{}`, nil), http.StatusBadRequest)
	env.toolbox.unblock("block-stdin")
}

func TestExecutionErrors(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	base := "/" + devbox.ID
	expectStatus(t, env.do(t, http.MethodPost, base+"/execute", `{"command":""}`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, base+"/execute", `{`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/execute", `{"command":"echo"}`, nil), http.StatusNotFound)
	for _, id := range []string{"nope", "rlx-zz", "rls-00", "rls-zz.00", "rls-00.zz"} {
		expectStatus(t, env.do(t, http.MethodGet, base+"/executions/"+id, nil, nil), http.StatusNotFound)
	}
	expectStatus(t, env.do(t, http.MethodGet, base+"/executions/rlx-0123456789abcdef", nil, nil), http.StatusNotFound)
	// A toolbox failure is a retryable 502.
	env.toolbox.setFailNext("/process/session", http.StatusInternalServerError)
	rr := env.do(t, http.MethodPost, base+"/execute_async", `{"command":"echo"}`, nil)
	expectStatus(t, rr, http.StatusBadGateway)
	if rr.Header().Get("x-should-retry") == "false" {
		t.Fatal("502 must stay retryable")
	}
}

func TestStreamOutput(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo streamed","command_id":"s1"}`, &done), http.StatusOK)
	path := "/" + devbox.ID + "/executions/" + done.ExecutionID

	rr := env.do(t, http.MethodGet, path+"/stream_stdout_updates?offset=0", nil, nil)
	expectStatus(t, rr, http.StatusOK)
	if ct := rr.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type = %q", ct)
	}
	chunks := readSSE(t, rr.Body.String())
	if len(chunks) != 1 || chunks[0].Output != "streamed\n" || chunks[0].Offset != len("streamed\n") {
		t.Fatalf("chunks = %+v", chunks)
	}
	// Reconnecting at the end offset yields nothing more.
	rr = env.do(t, http.MethodGet, path+"/stream_stdout_updates?offset=9", nil, nil)
	if got := readSSE(t, rr.Body.String()); len(got) != 0 {
		t.Fatalf("resume past end = %+v", got)
	}
	rr = env.do(t, http.MethodGet, path+"/stream_stderr_updates", nil, nil)
	if got := readSSE(t, rr.Body.String()); len(got) != 0 {
		t.Fatalf("empty stderr = %+v", got)
	}
	expectStatus(t, env.do(t, http.MethodGet, path+"/stream_stdout_updates?offset=-1", nil, nil), http.StatusBadRequest)

	// A running command's stream ends once it completes.
	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-sse"}`, &running), http.StatusOK)
	go func() {
		time.Sleep(50 * time.Millisecond)
		env.toolbox.unblock("block-sse")
	}()
	rr = env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+running.ExecutionID+"/stream_stdout_updates", nil, nil)
	if got := readSSE(t, rr.Body.String()); len(got) != 1 || got[0].Output != "ran: block-sse\n" {
		t.Fatalf("streamed after completion = %+v", got)
	}
}

func readSSE(t *testing.T, body string) []executionUpdateChunk {
	t.Helper()
	var chunks []executionUpdateChunk
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var chunk executionUpdateChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			t.Fatalf("bad SSE data %q: %v", data, err)
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestLiveStateFallsBackWhenWatcherCleansUp pins the race the go-race CI job
// hit: a reader sees the session and the finished command, then the
// watcher captures the result and deletes the session before the reader's
// logs read, which 404s. The reader must answer from the capture.
func TestLiveStateFallsBackWhenWatcherCleansUp(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ref := execRef{session: ephemeralPrefix + "0123456789abcdef"}
	exit := int32(0)
	env.toolbox.mu.Lock()
	env.toolbox.sessions[ref.session] = &fakeSession{commands: []*fakeCommand{{id: "00000000000000aa", command: "echo raced", exitCode: &exit, stdout: "raced\n"}}}
	env.toolbox.mu.Unlock()
	env.h.execs.record(&execResult{key: resultKey(devbox.ID, ref.id()), stdout: "raced\n"})
	env.toolbox.setFailNext("/process/session/"+ref.session+"/command/00000000000000aa/logs", http.StatusNotFound)

	state, err := env.h.liveState(context.Background(), devbox.ID, ref)
	if err != nil {
		t.Fatalf("liveState after cleanup race: %v", err)
	}
	if !state.completed || state.stdout != "raced\n" {
		t.Fatalf("state = %+v", state)
	}
}

func TestTailLines(t *testing.T) {
	cases := []struct {
		in    string
		n     int
		want  string
		trunc bool
	}{
		{"a\nb\nc\n", 2, "b\nc\n", true},
		{"a\nb\nc", 2, "b\nc", true},
		{"a\nb\n", 2, "a\nb\n", false},
		{"a\nb\n", 0, "a\nb\n", false},
		{"", 3, "", false},
		{"one", 1, "one", false},
	}
	for _, tc := range cases {
		got, trunc := tailLines(tc.in, tc.n)
		if got != tc.want || trunc != tc.trunc {
			t.Fatalf("tailLines(%q,%d) = %q,%v want %q,%v", tc.in, tc.n, got, trunc, tc.want, tc.trunc)
		}
	}
}

func TestParseExecID(t *testing.T) {
	cases := map[string]bool{
		"rlx-0123abcd":                   true,
		"rls-0123abcd.89ef":              true,
		"rlx-":                           false,
		"rlx-../etc":                     false,
		"rls-0123":                       false,
		"rls-0123.":                      false,
		"rls-0123.../x":                  false,
		"sb-0123":                        false,
		"rlx-" + strings.Repeat("a", 66): false,
	}
	for id, want := range cases {
		if _, ok := parseExecID(id); ok != want {
			t.Fatalf("parseExecID(%q) ok=%v want %v", id, ok, want)
		}
	}
}

func TestExecTrackerEvictsByBytes(t *testing.T) {
	tr := newExecTracker()
	big := strings.Repeat("x", maxCapturedStream)
	for i := 0; i < resultCacheBytes/maxCapturedStream+4; i++ {
		tr.record(&execResult{key: "d/" + string(rune('a'+i%26)) + strings.Repeat("k", i), stdout: big})
	}
	if tr.bytes > resultCacheBytes {
		t.Fatalf("cache holds %d bytes, cap %d", tr.bytes, resultCacheBytes)
	}
	tr.forgetDevbox("d")
	if tr.bytes != 0 || len(tr.results) != 0 {
		t.Fatalf("forgetDevbox left %d bytes / %d results", tr.bytes, len(tr.results))
	}
	if out, cut := keepTail(big + "tail"); !cut || !strings.HasSuffix(out, "tail") || len(out) != maxCapturedStream {
		t.Fatal("keepTail must keep the tail")
	}
}

func TestNamedClaimsAreBounded(t *testing.T) {
	tr := newExecTracker()
	for i := 0; i < maxNamedClaims+10; i++ {
		c, owner := tr.claimNamed("d/s\x00" + strings.Repeat("k", i%50) + string(rune(i)))
		if !owner {
			t.Fatal("fresh key was not owned")
		}
		tr.finishNamed("k", c, "rls-00.00", nil)
	}
	if len(tr.named) > maxNamedClaims {
		t.Fatalf("named claims grew to %d", len(tr.named))
	}
}
