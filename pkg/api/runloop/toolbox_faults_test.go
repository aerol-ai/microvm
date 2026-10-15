package runloop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// plainSession is the session a plain execution keyed by key runs in.
func plainSession(devboxID, key string) string {
	return ephemeralPrefix + shortHash(devboxID, key)
}

// Only a refusal proves a command did not run. A toolbox 4xx drops the
// claim and the session, so the same id runs cleanly next time. A 5xx may
// have come after the command started, so the claim stays and a watcher
// takes the session over: past the grace it removes the session and
// settles the row as lost, and the id is never run a second time.
func TestSubmitFailureKeepsTheClaimUnlessRefused(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		env := newTestEnv(t)
		devbox := env.mustCreate(t, "")
		env.toolbox.failAlways("/exec", http.StatusBadRequest)
		body := `{"command":"echo x","command_id":"s1"}`
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusBadRequest)
		if env.toolbox.sessionCount() != 0 {
			t.Fatal("a refused submit left its session behind")
		}
		env.toolbox.clearFaults()
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusOK)
		if got := env.toolbox.execCount(); got != 1 {
			t.Fatalf("ran %d times; want 1", got)
		}
	})
	t.Run("session refused", func(t *testing.T) {
		env := newTestEnv(t)
		devbox := env.mustCreate(t, "")
		env.toolbox.failAlways("POST /process/session", http.StatusBadRequest)
		body := `{"command":"echo x","command_id":"s0"}`
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusBadRequest)
		ref := execRef{session: plainSession(devbox.ID, "s0")}
		if _, err := env.svc.GetIdempotentRequest(context.Background(), service.ExecLedgerScope, ledgerKey(devbox.ID, ref)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("claim after a refused session = %v; want it released", err)
		}
		env.toolbox.clearFaults()
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusOK)
		if got := env.toolbox.execCount(); got != 1 {
			t.Fatalf("ran %d times; want 1", got)
		}
	})
	t.Run("failed", func(t *testing.T) {
		env := newTestEnv(t)
		shorten(t, &submitGrace, 50*time.Millisecond)
		devbox := env.mustCreate(t, "")
		env.toolbox.failAlways("/exec", http.StatusInternalServerError)
		body := `{"command":"echo x","command_id":"s2"}`
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusBadGateway)
		ref := execRef{session: plainSession(devbox.ID, "s2")}
		if !watcherAlive(env.h.execs, resultKey(devbox.ID, ref.id())) {
			t.Fatal("an ambiguous submit left its session with no owner")
		}
		waitFor(t, "the session to be fenced and the row settled", func() bool {
			outcome, _, ok := env.h.ledgerOutcome(context.Background(), devbox.ID, ref)
			return ok && outcome.Lost && env.toolbox.sessionCount() == 0
		})
		env.toolbox.clearFaults()
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", body, nil), http.StatusConflict)
		if got := env.toolbox.execCount(); got != 0 {
			t.Fatalf("ran %d times; want none", got)
		}
	})
}

func TestNamedShellFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	path := "/" + devbox.ID + "/execute"

	env.toolbox.failAlways("POST /process/session", http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo x","command_id":"n","shell_name":"s"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	// The failed claim was dropped, so the retry runs.
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo x","command_id":"n","shell_name":"s"}`, nil), http.StatusOK)

	env.toolbox.failAlways("/exec", http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo y","command_id":"m","shell_name":"s"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()

	env.toolbox.mu.Lock()
	env.toolbox.badCmdID = true
	env.toolbox.mu.Unlock()
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo z","command_id":"z","shell_name":"s"}`, nil), http.StatusBadGateway)
	env.toolbox.mu.Lock()
	env.toolbox.badCmdID = false
	env.toolbox.mu.Unlock()

	// A named command whose output cannot be read fails the request; the
	// named shell has no capture to fall back on.
	env.toolbox.failAlways("/logs", http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo w","command_id":"w","shell_name":"s"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	// Its command id is the next one the fake hands out.
	env.toolbox.failAlways("GET /command/"+nextCmdID(env), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo v","command_id":"v","shell_name":"s"}`, nil), http.StatusBadRequest)
	env.toolbox.clearFaults()
	env.toolbox.badJSON["/exec"] = true
	expectStatus(t, env.do(t, http.MethodPost, path, `{"command":"echo u","command_id":"u","shell_name":"s"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
}

func nextCmdID(env *testEnv) string {
	env.toolbox.mu.Lock()
	defer env.toolbox.mu.Unlock()
	return fmt.Sprintf("%016x", env.toolbox.cmdSeq+1)
}

// multipartBody builds an upload_file form; an empty path omits the field.
func multipartBody(t *testing.T, path string) (io.Reader, string) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "f.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("data"))
	if path != "" {
		_ = form.WriteField("path", path)
	}
	_ = form.Close()
	return &body, form.FormDataContentType()
}

func TestNamedClaimJoiners(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()

	// A retry arriving while the original holds the claim gets the
	// original's execution once it is recorded.
	key := namedLedgerKey(devbox.ID, "s", "k")
	if _, acquired, err := env.h.claimLedger(ctx, key); err != nil || !acquired {
		t.Fatalf("claim = %v %v", acquired, err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = env.h.completeLedger(ctx, key, "rls-00.01")
	}()
	ref, err := env.h.startNamedExecution(ctx, devbox.ID, "echo", "s", "k")
	if err != nil || ref.id() != "rls-00.01" {
		t.Fatalf("joiner = %v, %v", ref, err)
	}

	// The original failing and letting go: the retry takes over and runs.
	failKey := namedLedgerKey(devbox.ID, "s", "f")
	if _, _, err := env.h.claimLedger(ctx, failKey); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		env.h.releaseLedger(ctx, failKey)
	}()
	before := env.toolbox.execCount()
	if _, err := env.h.startNamedExecution(ctx, devbox.ID, "echo", "s", "f"); err != nil {
		t.Fatalf("retry after a released claim: %v", err)
	}
	if env.toolbox.execCount() != before+1 {
		t.Fatal("the retry did not run the command")
	}

	// A claim that is never recorded: the retry gives up with a conflict.
	shorten(t, &submitWait, 30*time.Millisecond)
	if _, _, err := env.h.claimLedger(ctx, namedLedgerKey(devbox.ID, "s", "stuck")); err != nil {
		t.Fatal(err)
	}
	var reqErr requestError
	if _, err := env.h.startNamedExecution(ctx, devbox.ID, "echo", "s", "stuck"); !errors.As(err, &reqErr) || reqErr.status != http.StatusConflict {
		t.Fatalf("stuck claim err = %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := env.h.startNamedExecution(cancelled, devbox.ID, "echo", "s", "c"); err == nil {
		t.Fatal("cancelled named execution succeeded")
	}
}

func TestAwaitSubmittedFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	sid := plainSession(devbox.ID, "k")
	if _, err := env.h.createSession(context.Background(), devbox.ID, sid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := env.h.awaitSubmitted(ctx, devbox.ID, execRef{session: sid}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled await = %v", err)
	}
	env.toolbox.failAlways("GET /process/session/"+sid, http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"k"}`, nil), http.StatusBadGateway)
}

func TestWatcherExits(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	watching := func(id string) bool { return env.h.execs.signal(resultKey(devbox.ID, id)) != nil }

	// Toolbox failures do not end a watcher: it owns the session's cleanup.
	// Once the toolbox answers again it finishes the job.
	var flaky executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-w1"}`, &flaky, "X-Request-Id", "w1"), http.StatusOK)
	env.toolbox.failAlways("GET /process/session/"+flaky.ExecutionID, http.StatusInternalServerError)
	waitFor(t, "the watcher to see the failure", func() bool { return !env.h.execs.running(resultKey(devbox.ID, flaky.ExecutionID)) })
	if !watching(flaky.ExecutionID) {
		t.Fatal("watcher gave up on toolbox failures")
	}
	env.toolbox.clearFaults()
	env.toolbox.unblock("block-w1")
	waitFor(t, "the watcher to finish and clean up", func() bool {
		_, cached := env.h.execs.result(resultKey(devbox.ID, flaky.ExecutionID))
		return cached && env.toolbox.sessionCount() == 0
	})

	// The session vanishing under it: the watcher stops.
	var gone executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-w2"}`, &gone, "X-Request-Id", "w2"), http.StatusOK)
	if err := env.h.deleteSession(context.Background(), devbox.ID, gone.ExecutionID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "watcher to stop", func() bool { return !watching(gone.ExecutionID) })
	env.toolbox.unblock("block-w2")

	// The devbox going away: the watcher stops.
	var orphan executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-w4"}`, &orphan, "X-Request-Id", "w4"), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/shutdown", nil, nil), http.StatusOK)
	waitFor(t, "watcher of a shut-down devbox to stop", func() bool { return !watching(orphan.ExecutionID) })
	env.toolbox.unblock("block-w4")

	// A second watcher for the same execution is not started.
	ref := execRef{session: plainSession(devbox.ID, "w3")}
	if !env.h.execs.watch(resultKey(devbox.ID, ref.id())) || env.h.execs.watch(resultKey(devbox.ID, ref.id())) {
		t.Fatal("watch must claim once")
	}
	env.h.startWatcher(context.Background(), devbox.ID, ref, false)
}

func TestExecutionHandlerFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	base := "/" + devbox.ID

	for _, action := range []string{"execute_async", "execute_sync", "execute"} {
		expectStatus(t, env.do(t, http.MethodPost, base+"/"+action, `{`, nil), http.StatusBadRequest)
		expectStatus(t, env.do(t, http.MethodPost, base+"/"+action, `{"command":" "}`, nil), http.StatusBadRequest)
	}
	// The live read fails right after submit. The blocking forms report it;
	// execute_async answers from the watcher it just started ("running"),
	// and the failure shows on the next read once the watcher has seen it.
	for i, action := range []string{"execute_sync", "execute"} {
		key := "f" + string(rune('0'+i))
		env.toolbox.failAlways("GET /process/session/"+plainSession(devbox.ID, key), http.StatusInternalServerError)
		expectStatus(t, env.do(t, http.MethodPost, base+"/"+action, `{"command":"echo x","command_id":"`+key+`"}`, nil, "X-Request-Id", key), http.StatusBadGateway)
		env.toolbox.clearFaults()
	}
	asyncSession := plainSession(devbox.ID, "f9")
	env.toolbox.failAlways("GET /process/session/"+asyncSession, http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, base+"/execute_async", `{"command":"echo x"}`, nil, "X-Request-Id", "f9"), http.StatusOK)
	waitFor(t, "the watcher to see the failure", func() bool { return !env.h.execs.running(resultKey(devbox.ID, asyncSession)) })
	expectStatus(t, env.do(t, http.MethodGet, base+"/executions/"+asyncSession, nil, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()

	var running executionView
	expectStatus(t, env.do(t, http.MethodPost, base+"/execute_async", `{"command":"block-h"}`, &running, "X-Request-Id", "h"), http.StatusOK)
	exec := base + "/executions/" + running.ExecutionID
	expectStatus(t, env.do(t, http.MethodPost, exec+"/wait_for_status", `{`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, exec+"/kill", `{`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, exec+"/send_std_in", `{`, nil), http.StatusBadRequest)
	var got executionView
	expectStatus(t, env.do(t, http.MethodGet, exec+"?last_n=x", nil, &got), http.StatusOK)

	// The client leaves while the wait is holding.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	rr := httptest.NewRecorder()
	env.h.waitForExecutionStatus(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"statuses":["completed"]}`)).WithContext(ctx), devbox.ID, running.ExecutionID)
	if rr.Body.Len() != 0 {
		t.Fatalf("abandoned wait wrote %s", rr.Body.String())
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	if _, err := env.h.awaitExecution(ctx2, devbox.ID, mustRef(t, running.ExecutionID), "", time.Minute); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abandoned await = %v", err)
	}

	sid := running.ExecutionID
	env.toolbox.failAlways("GET /process/session/"+sid, http.StatusInternalServerError)
	waitFor(t, "the watcher to see the failure", func() bool { return !env.h.execs.running(resultKey(devbox.ID, sid)) })
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, exec, ""},
		{http.MethodPost, exec + "/wait_for_status", `{"statuses":["completed"]}`},
		{http.MethodPost, exec + "/kill", ""},
		{http.MethodPost, exec + "/send_std_in", `{"text":"x"}`},
		{http.MethodGet, exec + "/stream_stdout_updates", ""},
	} {
		expectStatus(t, env.do(t, tc.method, tc.path, tc.body, nil), http.StatusBadGateway)
	}
	env.toolbox.clearFaults()
	waitFor(t, "the watcher to recover", func() bool { return env.h.execs.running(resultKey(devbox.ID, sid)) })
	env.toolbox.failAlways("DELETE /process/session/"+sid, http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, exec+"/kill", nil, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	env.toolbox.failAlways("/input", http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, exec+"/send_std_in", `{"text":"x"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	env.toolbox.unblock("block-h")

	// An execution whose session holds no command yet.
	empty := plainSession(devbox.ID, "empty")
	if _, err := env.h.createSession(context.Background(), devbox.ID, empty); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, env.do(t, http.MethodPost, base+"/executions/"+empty+"/send_std_in", `{"text":"x"}`, nil), http.StatusConflict)
	for action, method := range map[string]string{"/kill": http.MethodPost, "/send_std_in": http.MethodPost, "/stream_stdout_updates": http.MethodGet} {
		expectStatus(t, env.do(t, method, base+"/executions/bogus"+action, `{"text":"x"}`, nil), http.StatusNotFound)
	}

	// execute_sync keeps holding past one wait window.
	shorten(t, &execWaitMax, 20*time.Millisecond)
	go func() {
		time.Sleep(80 * time.Millisecond)
		env.toolbox.unblock("block-sync")
	}()
	var detail executionDetailView
	expectStatus(t, env.do(t, http.MethodPost, base+"/execute_sync", `{"command":"block-sync"}`, &detail), http.StatusOK)
	if detail.Stdout != "ran: block-sync\n" {
		t.Fatalf("sync = %+v", detail)
	}
}

func mustRef(t *testing.T, id string) execRef {
	t.Helper()
	ref, ok := parseExecID(id)
	if !ok {
		t.Fatalf("bad execution id %q", id)
	}
	return ref
}

func TestStreamHeartbeatAndMidStreamFailure(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	shorten(t, &sseHeartbeat, 10*time.Millisecond)

	var beat executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-beat"}`, &beat), http.StatusOK)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		env.toolbox.unblock("block-beat")
	}()
	rr := env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+beat.ExecutionID+"/stream_stdout_updates", nil, nil)
	if !strings.Contains(rr.Body.String(), ": ping") || len(readSSE(t, rr.Body.String())) != 1 {
		t.Fatalf("stream = %q", rr.Body.String())
	}

	var broken executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-broken"}`, &broken), http.StatusOK)
	go func() {
		time.Sleep(100 * time.Millisecond)
		env.toolbox.failAlways("GET /process/session/"+broken.ExecutionID, http.StatusInternalServerError)
	}()
	rr = env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+broken.ExecutionID+"/stream_stderr_updates", nil, nil)
	if !strings.Contains(rr.Body.String(), "event: error") {
		t.Fatalf("stream = %q", rr.Body.String())
	}
	env.toolbox.clearFaults()
	env.toolbox.unblock("block-broken")
}

func TestFileFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	base := "/" + devbox.ID
	expectStatus(t, env.do(t, http.MethodPost, base+"/read_file_contents", `{`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, base+"/write_file_contents", `{"file_path":"","contents":"x"}`, nil), http.StatusBadRequest)

	env.toolbox.failAlways("/files/upload", http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, base+"/write_file_contents", `{"file_path":"/a","contents":"x"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	env.toolbox.badJSON["/process/execute"] = true
	expectStatus(t, env.do(t, http.MethodPost, base+"/read_file_contents", `{"file_path":"rel"}`, nil), http.StatusBadGateway)
	env.toolbox.clearFaults()
	env.toolbox.mu.Lock()
	env.toolbox.home = "not-absolute"
	env.toolbox.mu.Unlock()
	expectStatus(t, env.do(t, http.MethodPost, base+"/read_file_contents", `{"file_path":"rel"}`, nil), http.StatusBadGateway)

	// No reachable toolbox at all.
	execSQL(t, env.store, `UPDATE sandboxes SET container_ip = ''`)
	expectStatus(t, env.do(t, http.MethodPost, base+"/download_file", `{"path":"/a"}`, nil), http.StatusBadGateway)
	expectStatus(t, env.do(t, http.MethodPost, base+"/write_file_contents", `{"file_path":"/a","contents":"x"}`, nil), http.StatusBadGateway)
}

func TestUploadFileFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	upload := func(path string) *httptest.ResponseRecorder {
		body, contentType := multipartBody(t, path)
		req := httptest.NewRequest(http.MethodPost, devboxesPath+"/"+devbox.ID+"/upload_file", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		return rr
	}
	expectStatus(t, upload(""), http.StatusBadRequest)
	env.toolbox.failAlways("/files/upload", http.StatusInternalServerError)
	expectStatus(t, upload("/x"), http.StatusBadGateway)
}

func TestDevboxEdgeFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	base := "/" + devbox.ID

	var page listDevboxesResponse
	expectStatus(t, env.do(t, http.MethodGet, "?limit=999999", nil, &page), http.StatusOK)
	ids := make([]string, 0, 2001)
	for i := 0; i < 2001; i++ {
		ids = append(ids, "sb-"+strings.Repeat("a", i%5)+time.Duration(i).String())
	}
	expectStatus(t, env.do(t, http.MethodGet, "?ids="+strings.Join(ids, ","), nil, nil, "X-Cluster-Forwarded", "1"), http.StatusBadRequest)

	env.runtime.errDestroy = errors.New("destroy failed")
	expectError(t, env.do(t, http.MethodPost, base+"/shutdown", nil, nil))
	env.runtime.errDestroy = nil

	// A wait whose client leaves while the devbox is still provisioning.
	shorten(t, &createHold, 10*time.Millisecond)
	env.runtime.blockCreate = make(chan struct{})
	defer close(env.runtime.blockCreate)
	var prov devboxView
	expectStatus(t, env.do(t, http.MethodPost, "", `{}`, &prov), http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	rr := httptest.NewRecorder()
	env.h.waitForDevboxStatus(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"statuses":["running"]}`)).WithContext(ctx), prov.ID)
	if rr.Body.Len() != 0 {
		t.Fatalf("abandoned wait wrote %s", rr.Body.String())
	}

	execSQL(t, env.store, `DROP TABLE sandbox_compat_state`)
	expectError(t, env.do(t, http.MethodGet, base, nil, nil))
}

func TestSnapshotFacadeAliasesFromOtherFacades(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	native, _, err := env.svc.CreateSnapshotWithOwnership(context.Background(), devbox.ID, models.CreateSandboxSnapshotRequest{Name: "e2b/base:default"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.svc.UpsertSnapshotAlias(context.Background(), models.SnapshotAlias{Alias: "snapshot_e2b", SnapshotName: native.Name, Facade: models.FacadeE2B}); err != nil {
		t.Fatal(err)
	}
	// Another facade's alias resolves, but is not treated as Runloop state.
	var status snapshotStatusView
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/snapshot_e2b/status", nil, &status), http.StatusOK)
	if status.Snapshot == nil || status.Snapshot.ID != env.h.snapshotIDForName(native.Name) {
		t.Fatalf("status = %+v", status)
	}
	var list listSnapshotsResponse
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?metadata[k]=v", nil, &list), http.StatusOK)
	if len(list.Snapshots) != 0 {
		t.Fatalf("metadata filter matched a snapshot without metadata: %+v", list)
	}
}

func TestExecTrackerEdges(t *testing.T) {
	tr := newExecTracker()
	tr.record(&execResult{key: "d/old"})
	tr.results["d/old"].Value.(*execResult).at = time.Now().Add(-2 * resultTTL)
	if _, ok := tr.result("d/old"); ok {
		t.Fatal("expired result answered")
	}
	// A watcher owns cleanup, so it can attach after a reader recorded the
	// result; a recorded result's signal is already closed.
	tr.record(&execResult{key: "d/done"})
	if !tr.watch("d/done") {
		t.Fatal("a recorded result blocked the cleanup watcher")
	}
	select {
	case <-tr.signal("d/done"):
	default:
		t.Fatal("signal for a recorded result must already be closed")
	}
	if !tr.watch("d/w") || tr.watch("d/w") {
		t.Fatal("watch must claim once")
	}
	if !tr.running("d/w") {
		t.Fatal("a healthy watcher reads as running")
	}
	sig := tr.signal("d/w")
	tr.observed("d/w", true)
	select {
	case <-sig:
	default:
		t.Fatal("a failing watcher must wake its waiters")
	}
	if tr.running("d/w") {
		t.Fatal("a failing watcher must not read as running")
	}
	tr.observed("d/w", false)
	tr.finishing("d/w")
	if tr.running("d/w") {
		t.Fatal("a finishing watcher must not read as running")
	}
	tr.unwatch("d/w")
	tr.unwatch("d/w")
	tr.observed("d/w", true)
	tr.finishing("d/w")
	if tr.signal("d/w") != nil {
		t.Fatal("an unwatched execution has no signal")
	}
	tr.watch("d/w2")
	waiter := tr.signal("d/w2")
	tr.forgetDevbox("d")
	select {
	case <-waiter:
	default:
		t.Fatal("forgetDevbox must wake waiters")
	}
	if len(tr.results) != 0 || tr.bytes != 0 {
		t.Fatal("forgetDevbox left results behind")
	}
}
