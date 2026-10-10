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

	"github.com/aerol-ai/microvm/pkg/models"
)

func setWatchMaxErrors(t *testing.T, n int) {
	t.Helper()
	old := watchMaxErrors
	watchMaxErrors = n
	t.Cleanup(func() { watchMaxErrors = old })
}

// plainSession is the session a plain execution keyed by key runs in.
func plainSession(devboxID, key string) string {
	return ephemeralPrefix + shortHash(devboxID, key)
}

func TestSubmitFailureReleasesTheSession(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	env.toolbox.failAlways("/exec", http.StatusInternalServerError)
	rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"s1"}`, nil)
	expectStatus(t, rr, http.StatusBadGateway)
	if env.toolbox.sessionCount() != 0 {
		t.Fatal("a failed submit left its claimed session behind")
	}
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
	key := devbox.ID + "/s\x00k"

	claim, _ := env.h.execs.claimNamed(key)
	go func() {
		time.Sleep(20 * time.Millisecond)
		env.h.execs.finishNamed(key, claim, "rls-00.01", nil)
	}()
	ref, err := env.h.startNamedExecution(context.Background(), devbox.ID, "echo", "s", "k")
	if err != nil || ref.id() != "rls-00.01" {
		t.Fatalf("joiner = %v, %v", ref, err)
	}

	failKey := devbox.ID + "/s\x00f"
	failing, _ := env.h.execs.claimNamed(failKey)
	go func() {
		time.Sleep(20 * time.Millisecond)
		env.h.execs.finishNamed(failKey, failing, "", errors.New("submit failed"))
	}()
	if _, err := env.h.startNamedExecution(context.Background(), devbox.ID, "echo", "s", "f"); err == nil {
		t.Fatal("joiner of a failed claim succeeded")
	}

	env.h.execs.claimNamed(devbox.ID + "/s\x00c")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := env.h.startNamedExecution(ctx, devbox.ID, "echo", "s", "c"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled joiner err = %v", err)
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
	if err := env.h.awaitSubmitted(ctx, devbox.ID, sid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled await = %v", err)
	}
	env.toolbox.failAlways("GET /process/session/"+sid, http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"k"}`, nil), http.StatusBadGateway)
}

func TestWatcherExits(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	setWatchMaxErrors(t, 2)

	// Persistent toolbox failures: the watcher gives up.
	var giveUp executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-w1"}`, &giveUp, "X-Request-Id", "w1"), http.StatusOK)
	env.toolbox.failAlways("GET /process/session/"+giveUp.ExecutionID, http.StatusInternalServerError)
	waitFor(t, "watcher to give up", func() bool { return env.h.execs.signal(resultKey(devbox.ID, giveUp.ExecutionID)) == nil })
	env.toolbox.clearFaults()
	env.toolbox.unblock("block-w1")

	// The session vanishing under it: the watcher stops.
	var gone executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_async", `{"command":"block-w2"}`, &gone, "X-Request-Id", "w2"), http.StatusOK)
	if err := env.h.deleteSession(context.Background(), devbox.ID, gone.ExecutionID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "watcher to stop", func() bool { return env.h.execs.signal(resultKey(devbox.ID, gone.ExecutionID)) == nil })
	env.toolbox.unblock("block-w2")

	// A second watcher for the same execution is not started.
	ref := execRef{session: plainSession(devbox.ID, "w3")}
	env.h.execs.watch(resultKey(devbox.ID, ref.id()))
	env.h.startWatcher(context.Background(), devbox.ID, ref)
}

func TestExecutionHandlerFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	setWatchMaxErrors(t, 1)
	base := "/" + devbox.ID

	for _, action := range []string{"execute_async", "execute_sync", "execute"} {
		expectStatus(t, env.do(t, http.MethodPost, base+"/"+action, `{`, nil), http.StatusBadRequest)
		expectStatus(t, env.do(t, http.MethodPost, base+"/"+action, `{"command":" "}`, nil), http.StatusBadRequest)
	}
	// The live read fails right after submit.
	for i, action := range []string{"execute_async", "execute_sync", "execute"} {
		key := "f" + string(rune('0'+i))
		env.toolbox.failAlways("GET /process/session/"+plainSession(devbox.ID, key), http.StatusInternalServerError)
		expectStatus(t, env.do(t, http.MethodPost, base+"/"+action, `{"command":"echo x","command_id":"`+key+`"}`, nil, "X-Request-Id", key), http.StatusBadGateway)
		env.toolbox.clearFaults()
	}

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
	setWatchMaxErrors(t, 1)
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
	if status.Snapshot == nil || status.Snapshot.ID != snapshotIDForName(native.Name) {
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
	tr.record(&execResult{key: "d/done"})
	if tr.watch("d/done") {
		t.Fatal("watched an execution that already has a result")
	}
	if !tr.watch("d/w") || tr.watch("d/w") {
		t.Fatal("watch must claim once")
	}
	tr.unwatch("d/w")
	tr.unwatch("d/w")
	tr.watch("d/w2")
	tr.claimNamed("d/s\x00k")
	tr.forgetDevbox("d")
	if len(tr.watches) != 0 || len(tr.named) != 0 || len(tr.results) != 0 {
		t.Fatal("forgetDevbox left state behind")
	}

	for i := 0; i < maxNamedClaims; i++ {
		c, _ := tr.claimNamed("e/" + time.Duration(i).String())
		c.at = time.Now().Add(-2 * namedClaimTTL)
	}
	tr.claimNamed("e/fresh")
	if len(tr.named) != 1 {
		t.Fatalf("expired named claims kept: %d", len(tr.named))
	}

	ts := newTombstones()
	for i := 0; i < maxTombstones; i++ {
		ts.put(time.Duration(i).String(), "", devboxView{})
	}
	for key, entry := range ts.views {
		entry.at = time.Now().Add(-2 * tombstoneTTL)
		ts.views[key] = entry
	}
	ts.put("fresh", "", devboxView{})
	if len(ts.views) != 1 {
		t.Fatalf("expired tombstones kept: %d", len(ts.views))
	}
}
