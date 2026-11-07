package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonaerrors "github.com/daytonaio/daytona/libs/sdk-go/pkg/errors"
	daytonaoptions "github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	toolbox "github.com/daytonaio/daytona/libs/toolbox-api-client-go"
)

// ptyTestEnv is toolboxd's real routes on a real listener, driven by the
// Daytona Go SDK pinned in go.mod. The SDK's toolbox client decodes every
// terminal response strictly (required fields, no unknown fields), so these
// tests also prove the wire shapes (plan E8).
type ptyTestEnv struct {
	srv  *server
	ptys *daytonaPTYs
	ts   *httptest.Server
	api  *toolbox.APIClient
	proc *daytonasdk.ProcessService
}

func newPTYTestEnv(t *testing.T, bufferBytes int) *ptyTestEnv {
	t.Helper()
	return newPTYTestEnvWith(t, sessions.Config{BufferBytes: bufferBytes})
}

func newPTYTestEnvWith(t *testing.T, cfg sessions.Config) *ptyTestEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg.SandboxID = "sb-test"
	cfg.RecordingDir = filepath.Join(t.TempDir(), "recordings")
	mgr, err := sessions.New(logger, cfg)
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	srv := &server{sessions: mgr, daytona: newDaytonaCompat(), logger: logger}
	srv.ptys = newDaytonaPTYs(mgr, logger)
	ts := httptest.NewServer(authedRoutes(srv))
	t.Cleanup(ts.Close)

	// The SDK's toolbox URL is the proxy URL plus the sandbox id; toolboxd
	// strips that prefix.
	apiCfg := toolbox.NewConfiguration()
	apiCfg.Servers = toolbox.ServerConfigurations{{URL: ts.URL + "/sb-test"}}
	apiCfg.HTTPClient = ts.Client()
	apiCfg.AddDefaultHeader("Authorization", "Bearer "+testToolboxToken)
	api := toolbox.NewAPIClient(apiCfg)
	return &ptyTestEnv{
		srv:  srv,
		ptys: srv.ptys,
		ts:   ts,
		api:  api,
		proc: daytonasdk.NewProcessService(api, nil, daytonatypes.CodeLanguagePython),
	}
}

func ptyCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// connectPTY creates (or, with create false, reattaches to) a terminal and
// waits for the SDK's "connected" control message.
func connectPTY(t *testing.T, env *ptyTestEnv, id string, create bool, opts ...func(*daytonaoptions.CreatePty)) *daytonasdk.PtyHandle {
	t.Helper()
	ctx := ptyCtx(t)
	var handle *daytonasdk.PtyHandle
	var err error
	if create {
		handle, err = env.proc.CreatePty(ctx, id, opts...)
	} else {
		handle, err = env.proc.ConnectPty(ctx, id)
	}
	if err != nil {
		t.Fatalf("terminal %s: %v", id, err)
	}
	t.Cleanup(func() { _ = handle.Disconnect() })
	if err := handle.WaitForConnection(ctx); err != nil {
		t.Fatalf("WaitForConnection(%s): %v", id, err)
	}
	return handle
}

// readUntil reads terminal output until it matches want, which is written
// so the typed command line (the terminal echoes it) cannot match it.
func readUntil(t *testing.T, handle *daytonasdk.PtyHandle, want *regexp.Regexp) string {
	t.Helper()
	var out strings.Builder
	timeout := time.After(15 * time.Second)
	for {
		if m := want.FindStringSubmatch(out.String()); m != nil {
			return m[len(m)-1]
		}
		select {
		case data, ok := <-handle.DataChan():
			if !ok {
				t.Fatalf("terminal closed before %s; output %q", want, out.String())
			}
			out.Write(data)
		case <-timeout:
			t.Fatalf("no %s in 15s; output %q", want, out.String())
		}
	}
}

func sendInput(t *testing.T, handle *daytonasdk.PtyHandle, line string) {
	t.Helper()
	if err := handle.SendInput([]byte(line + "\n")); err != nil {
		t.Fatalf("SendInput(%q): %v", line, err)
	}
}

func waitExit(t *testing.T, handle *daytonasdk.PtyHandle) *daytonatypes.PtyResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode == nil {
		t.Fatal("terminal ended with no exit code")
	}
	return result
}

func ptyRecord(env *ptyTestEnv, id string) (*daytonaPTY, bool) {
	env.ptys.mu.Lock()
	defer env.ptys.mu.Unlock()
	pty, ok := env.ptys.byID[id]
	return pty, ok
}

func waitReleased(t *testing.T, env *ptyTestEnv, pty *daytonaPTY) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		env.ptys.mu.Lock()
		released := pty.released
		env.ptys.mu.Unlock()
		if released {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("terminal %s never released its buffer", pty.id)
}

// UC-386 offline: the Daytona SDK creates a terminal, connects, runs a
// command and reads its output; every REST call decodes under the SDK's
// strict models.
func TestDaytonaPTYThroughTheDaytonaSDK(t *testing.T) {
	env := newPTYTestEnv(t, 1<<16)
	ctx := ptyCtx(t)
	cwd := t.TempDir()

	created, _, err := env.api.ProcessAPI.CreatePtySession(ctx).Request(toolbox.PtyCreateRequest{
		Id: toolbox.PtrString("term-1"), Cwd: toolbox.PtrString(cwd),
		Envs: &map[string]string{"GREETING": "hi"},
		Cols: toolbox.PtrInt32(100), Rows: toolbox.PtrInt32(30),
	}).Execute()
	if err != nil {
		t.Fatalf("CreatePtySession: %v", err)
	}
	if created.GetSessionId() != "term-1" {
		t.Fatalf("sessionId = %q, want the id the client chose", created.GetSessionId())
	}

	handle := connectPTY(t, env, "term-1", false)
	sendInput(t, handle, `echo "out=$GREETING-$((40+2))-$(pwd)-$TERM"`)
	if got := readUntil(t, handle, regexp.MustCompile(`out=(hi-42-\S+-\S+)`)); !strings.HasSuffix(got, "-"+daytonaPTYDefaultTerm) || !strings.Contains(got, filepath.Base(cwd)) {
		t.Fatalf("command output = %q, want the env, the cwd and TERM=%s", got, daytonaPTYDefaultTerm)
	}

	info, _, err := env.api.ProcessAPI.GetPtySession(ctx, "term-1").Execute()
	if err != nil {
		t.Fatalf("GetPtySession: %v", err)
	}
	if !info.Active || info.Id != "term-1" || info.Cols != 100 || info.Rows != 30 || info.Cwd != cwd ||
		info.Envs["GREETING"] != "hi" || len(info.Envs) != 1 || info.LazyStart {
		t.Fatalf("info = %+v", info)
	}
	if createdAt, err := time.Parse(time.RFC3339Nano, info.CreatedAt); err != nil || time.Since(createdAt) > time.Minute {
		t.Fatalf("createdAt = %q (%v)", info.CreatedAt, err)
	}

	list, err := env.proc.ListPtySessions(ctx)
	if err != nil || len(list) != 1 || list[0].ID != "term-1" {
		t.Fatalf("ListPtySessions = %+v, %v", list, err)
	}

	resized, err := handle.Resize(ctx, 120, 40)
	if err != nil || resized.Cols != 120 || resized.Rows != 40 || resized.ID != "term-1" {
		t.Fatalf("Resize = %+v, %v", resized, err)
	}
	sendInput(t, handle, `echo "size=$(stty size | tr ' ' x)"`)
	if got := readUntil(t, handle, regexp.MustCompile(`size=(\d+x\d+)`)); got != "40x120" {
		t.Fatalf("stty size after resize = %q, want 40x120", got)
	}

	// Kill ends the shell; a connected client sees the end.
	if err := handle.Kill(ctx); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if result := waitExit(t, handle); result.Error == nil || !strings.Contains(*result.Error, "signal") {
		t.Fatalf("killed terminal ended with %+v, want the signal named", result)
	}
	var notFound *daytonaerrors.DaytonaNotFoundError
	if _, err := env.proc.GetPtySessionInfo(ctx, "term-1"); !errors.As(err, &notFound) {
		t.Fatalf("info after kill = %v, want not found", err)
	}
	if err := env.proc.KillPtySession(ctx, "term-1"); !errors.As(err, &notFound) {
		t.Fatalf("kill twice = %v, want not found", err)
	}
	if list, err := env.proc.ListPtySessions(ctx); err != nil || len(list) != 0 {
		t.Fatalf("list after kill = %+v, %v", list, err)
	}
}

// The exit code reaches the SDK, and a finished terminal can still be
// connected to for its last output and exit.
func TestDaytonaPTYExitCodeReachesTheSDK(t *testing.T) {
	env := newPTYTestEnv(t, 1<<16)
	env.ptys.retention = time.Hour
	handle := connectPTY(t, env, "exits", true)
	sendInput(t, handle, `echo "last=$((3*3))"; exit 7`)
	readUntil(t, handle, regexp.MustCompile(`last=(9)`))
	result := waitExit(t, handle)
	if *result.ExitCode != 7 || result.Error != nil {
		t.Fatalf("exit = %d %v, want 7", *result.ExitCode, result.Error)
	}

	ctx := ptyCtx(t)
	info, _, err := env.api.ProcessAPI.GetPtySession(ctx, "exits").Execute()
	if err != nil || info.Active {
		t.Fatalf("info of a finished terminal = %+v, %v; want it kept, inactive", info, err)
	}
	var conflict *daytonaerrors.DaytonaConflictError
	if _, err := env.proc.ResizePtySession(ctx, "exits", daytonatypes.PtySize{Cols: 90, Rows: 20}); !errors.As(err, &conflict) {
		t.Fatalf("resize of a finished terminal = %v, want 409", err)
	}

	again := connectPTY(t, env, "exits", false)
	readUntil(t, again, regexp.MustCompile(`last=(9)`))
	if result := waitExit(t, again); *result.ExitCode != 7 {
		t.Fatalf("reconnect to a finished terminal: exit %d, want 7", *result.ExitCode)
	}
}

// UC-389 offline: a terminal survives a disconnect, keeps running and
// writing, and the client reconnects to the same shell and its output.
func TestDaytonaPTYReattachAfterDisconnect(t *testing.T) {
	env := newPTYTestEnv(t, 1<<16)
	handle := connectPTY(t, env, "reattach", true)
	sendInput(t, handle, `MARK=$((6*7)); echo "pid=$$"`)
	pid := readUntil(t, handle, regexp.MustCompile(`pid=(\d+)`))
	sendInput(t, handle, `(sleep 0.5; echo "away=$((MARK+1))") &`)
	if err := handle.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	ctx := ptyCtx(t)
	time.Sleep(time.Second) // the job writes while no client is connected
	info, err := env.proc.GetPtySessionInfo(ctx, "reattach")
	if err != nil || info.ID != "reattach" {
		t.Fatalf("info while disconnected = %+v, %v", info, err)
	}
	if pty, _ := ptyRecord(env, "reattach"); pty.exited() {
		t.Fatal("the shell ended when its client disconnected")
	}

	again := connectPTY(t, env, "reattach", false)
	// The replay buffer hands over what was written while away.
	readUntil(t, again, regexp.MustCompile(`away=(43)`))
	sendInput(t, again, `echo "again=$MARK-$$"`)
	if got := readUntil(t, again, regexp.MustCompile(`again=(\d+-\d+)`)); got != "42-"+pid {
		t.Fatalf("after reconnect = %q, want the same shell (42-%s)", got, pid)
	}

	// Two clients on one terminal both see its output.
	third := connectPTY(t, env, "reattach", false)
	sendInput(t, again, `echo "both=$((MARK*2))"`)
	readUntil(t, again, regexp.MustCompile(`both=(84)`))
	readUntil(t, third, regexp.MustCompile(`both=(84)`))
}

// R11: the Daytona terminal limit answers 429 on terminal N+1, counts a
// finished terminal until its buffer is freed, holds under concurrent
// creates, and leaves other sessions alone.
func TestDaytonaPTYLimit(t *testing.T) {
	env := newPTYTestEnv(t, 1<<14)
	env.ptys.limit = 3
	env.ptys.retention = time.Hour
	ctx := ptyCtx(t)

	for i := 0; i < 3; i++ {
		if _, err := env.proc.CreatePtySession(ctx, fmt.Sprintf("t%d", i)); err != nil {
			t.Fatalf("terminal %d of 3: %v", i, err)
		}
	}
	_, httpResp, err := env.api.ProcessAPI.CreatePtySession(ctx).Request(toolbox.PtyCreateRequest{Id: toolbox.PtrString("t3")}).Execute()
	if httpResp == nil || httpResp.StatusCode != http.StatusTooManyRequests || err == nil {
		t.Fatalf("terminal 4 of 3 = %v, %v; want 429", httpResp, err)
	}
	var limited *daytonaerrors.DaytonaRateLimitError
	if _, err := env.proc.CreatePtySession(ctx, "t3"); !errors.As(err, &limited) || !strings.Contains(err.Error(), "3 terminals") {
		t.Fatalf("SDK create over the limit = %v, want a rate-limit error naming the count", err)
	}
	if _, ok := ptyRecord(env, "t3"); ok {
		t.Fatal("a refused terminal was recorded")
	}

	// Re-creating a running terminal is not a new one, so it is not limited.
	if _, err := env.proc.CreatePtySession(ctx, "t0"); err != nil {
		t.Fatalf("idempotent create at the limit: %v", err)
	}

	// Other sessions are not Daytona terminals: never counted, never refused.
	h := authedRoutes(env.srv)
	for i := 0; i < 4; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"command":"sleep 30","pty":true}`)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("v1 session %d at the terminal limit = %d %s", i, rr.Code, rr.Body.String())
		}
	}

	// A finished terminal keeps its slot until its buffer is freed.
	pty, _ := ptyRecord(env, "t0")
	_ = pty.sess.Signal("KILL")
	<-pty.sess.Done()
	if _, err := env.proc.CreatePtySession(ctx, "t3"); !errors.As(err, &limited) {
		t.Fatalf("create while a finished terminal holds its buffer = %v, want 429", err)
	}
	env.ptys.release(pty)
	if _, err := env.proc.CreatePtySession(ctx, "t3"); err != nil {
		t.Fatalf("create after the finished terminal's buffer was freed: %v", err)
	}

	// Killing frees a slot at once.
	if err := env.proc.KillPtySession(ctx, "t1"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	if _, err := env.proc.CreatePtySession(ctx, "t4"); err != nil {
		t.Fatalf("create after a kill: %v", err)
	}
}

func TestDaytonaPTYLimitHoldsUnderConcurrentCreates(t *testing.T) {
	env := newPTYTestEnv(t, 1<<14)
	env.ptys.limit = 4
	ctx := ptyCtx(t)
	const callers = 10
	codes := make([]int, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, resp, _ := env.api.ProcessAPI.CreatePtySession(ctx).Request(toolbox.PtyCreateRequest{Id: toolbox.PtrString(fmt.Sprintf("c%d", i))}).Execute()
			if resp != nil {
				codes[i] = resp.StatusCode
			}
		}(i)
	}
	wg.Wait()
	created, limited := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if created != 4 || limited != callers-4 {
		t.Fatalf("concurrent creates = %v; want 4 created and %d refused", codes, callers-4)
	}
}

// Creating an id is safe to retry and to send twice at once: one shell,
// exactly one 201. The id with other settings is a conflict; an id whose
// terminal finished starts a fresh one.
func TestDaytonaPTYCreateIsIdempotent(t *testing.T) {
	env := newPTYTestEnv(t, 1<<14)
	env.ptys.retention = time.Hour
	ctx := ptyCtx(t)
	const callers = 8
	codes := make([]int, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, httpResp, err := env.api.ProcessAPI.CreatePtySession(ctx).Request(toolbox.PtyCreateRequest{Id: toolbox.PtrString("same")}).Execute()
			if err != nil || resp.GetSessionId() != "same" {
				t.Errorf("create %d: %v %+v", i, err, resp)
				return
			}
			codes[i] = httpResp.StatusCode
		}(i)
	}
	wg.Wait()
	first := 0
	for _, code := range codes {
		if code == http.StatusCreated {
			first++
		} else if code != http.StatusOK {
			t.Fatalf("duplicate create answered %d", code)
		}
	}
	if first != 1 {
		t.Fatalf("concurrent creates of one id = %v, want exactly one 201", codes)
	}
	daytonaShells := 0
	for _, s := range env.srv.sessions.List() {
		if strings.HasPrefix(s.Name, "daytona-pty-same-") {
			daytonaShells++
		}
	}
	if daytonaShells != 1 {
		t.Fatalf("%d shells for one terminal id, want 1", daytonaShells)
	}

	var conflict *daytonaerrors.DaytonaConflictError
	_, err := env.proc.CreatePtySession(ctx, "same", daytonaoptions.WithPtyEnv(map[string]string{"OTHER": "1"}))
	if !errors.As(err, &conflict) {
		t.Fatalf("same id, other envs = %v, want 409", err)
	}

	pty, _ := ptyRecord(env, "same")
	_ = pty.sess.Signal("KILL")
	<-pty.sess.Done()
	_, httpResp, err := env.api.ProcessAPI.CreatePtySession(ctx).Request(toolbox.PtyCreateRequest{Id: toolbox.PtrString("same")}).Execute()
	if err != nil || httpResp.StatusCode != http.StatusCreated {
		t.Fatalf("create of a finished id = %v %v, want a fresh terminal (201)", httpResp, err)
	}
	if fresh, _ := ptyRecord(env, "same"); fresh == pty || fresh.exited() {
		t.Fatal("the finished terminal was handed back instead of a fresh one")
	}
	if _, err := env.srv.sessions.Get(pty.sess.ID()); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("the replaced terminal's session is still tracked: %v", err)
	}

	resp, httpResp, err := env.api.ProcessAPI.CreatePtySession(ctx).Request(toolbox.PtyCreateRequest{}).Execute()
	if err != nil || httpResp.StatusCode != http.StatusCreated || !strings.HasPrefix(resp.GetSessionId(), "pty-") {
		t.Fatalf("create without an id = %+v %v %v", resp, httpResp, err)
	}
}

// R11 memory check: a finished terminal's replay buffer is freed after the
// retention (the heap really shrinks), its exit status stays, and only a
// bounded number of finished terminals are remembered at all.
func TestDaytonaPTYFinishedTerminalFreesItsBuffer(t *testing.T) {
	const buffer = 64 << 20
	env := newPTYTestEnv(t, buffer)
	env.ptys.retention = 50 * time.Millisecond
	env.ptys.limit = 1
	ctx := ptyCtx(t)

	heap := func() int64 {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return int64(stats.HeapAlloc)
	}
	base := heap()
	handle := connectPTY(t, env, "done", true)
	pty, _ := ptyRecord(env, "done")
	if grew := heap() - base; grew < buffer/2 {
		t.Fatalf("heap grew %d bytes for a %d-byte buffer; the check cannot see it", grew, buffer)
	}

	sendInput(t, handle, `echo "bye=$((2+3))"; exit 5`)
	readUntil(t, handle, regexp.MustCompile(`bye=(5)`))
	if result := waitExit(t, handle); *result.ExitCode != 5 {
		t.Fatalf("exit = %d, want 5", *result.ExitCode)
	}
	_ = handle.Disconnect()
	waitReleased(t, env, pty)
	if left := heap() - base; left > buffer/4 {
		t.Fatalf("heap is still %d bytes above the start after the buffer was freed", left)
	}
	if got := pty.sess.Replay(); len(got) != 0 {
		t.Fatalf("replay after release = %q", got)
	}

	// The exit status outlives the buffer.
	info, err := env.proc.GetPtySessionInfo(ctx, "done")
	if err != nil || info.ID != "done" {
		t.Fatalf("info after release = %+v, %v", info, err)
	}
	again := connectPTY(t, env, "done", false)
	if result := waitExit(t, again); *result.ExitCode != 5 {
		t.Fatalf("exit after release = %d, want 5", *result.ExitCode)
	}

	// Its slot is free again (the limit is 1).
	if _, err := env.proc.CreatePtySession(ctx, "next"); err != nil {
		t.Fatalf("create after the finished terminal was released: %v", err)
	}
}

func TestDaytonaPTYForgetsTheOldestFinishedTerminals(t *testing.T) {
	env := newPTYTestEnv(t, 1<<14)
	env.ptys.retention = time.Millisecond
	env.ptys.keepFinished = 1
	ctx := ptyCtx(t)

	var finished []*daytonaPTY
	for _, id := range []string{"old", "new"} {
		if _, err := env.proc.CreatePtySession(ctx, id); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		pty, _ := ptyRecord(env, id)
		_ = pty.sess.Signal("KILL")
		waitReleased(t, env, pty)
		finished = append(finished, pty)
	}
	var notFound *daytonaerrors.DaytonaNotFoundError
	if _, err := env.proc.GetPtySessionInfo(ctx, "old"); !errors.As(err, &notFound) {
		t.Fatalf("oldest finished terminal = %v, want forgotten", err)
	}
	if _, err := env.srv.sessions.Get(finished[0].sess.ID()); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("the forgotten terminal's session is still tracked: %v", err)
	}
	if info, err := env.proc.GetPtySessionInfo(ctx, "new"); err != nil || info.ID != "new" {
		t.Fatalf("newest finished terminal = %+v, %v; want it kept", info, err)
	}
}

// Kill hangs the terminal up first, so a job the shell started in a process
// group of its own ends with it.
func TestDaytonaPTYKillEndsTheShellsJobs(t *testing.T) {
	env := newPTYTestEnv(t, 1<<16)
	handle := connectPTY(t, env, "jobs", true)
	sendInput(t, handle, `sleep 300 & echo "job=$!"`)
	var pid int
	if _, err := fmt.Sscan(readUntil(t, handle, regexp.MustCompile(`job=(\d+)`)), &pid); err != nil || pid <= 0 {
		t.Fatalf("job pid: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	if err := env.proc.KillPtySession(ptyCtx(t), "jobs"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	waitExit(t, handle)
	deadline := time.Now().Add(10 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("background job %d outlived the killed terminal", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A terminal deleted through the v1 sessions API is gone from the Daytona
// view too, and frees its slot.
func TestDaytonaPTYDeletedAsASession(t *testing.T) {
	env := newPTYTestEnv(t, 1<<14)
	env.ptys.limit = 1
	ctx := ptyCtx(t)
	if _, err := env.proc.CreatePtySession(ctx, "v1-deleted"); err != nil {
		t.Fatalf("create: %v", err)
	}
	pty, _ := ptyRecord(env, "v1-deleted")
	rr := httptest.NewRecorder()
	authedRoutes(env.srv).ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/sessions/"+pty.sess.ID(), nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("v1 delete = %d %s", rr.Code, rr.Body.String())
	}
	var notFound *daytonaerrors.DaytonaNotFoundError
	if _, err := env.proc.GetPtySessionInfo(ctx, "v1-deleted"); !errors.As(err, &notFound) {
		t.Fatalf("info after v1 delete = %v, want not found", err)
	}
	if _, err := env.proc.CreatePtySession(ctx, "next"); err != nil {
		t.Fatalf("create after v1 delete: %v", err)
	}
}

// A quiet terminal stays connected: toolboxd pings, the SDK answers, and
// the read deadline moves on.
func TestDaytonaPTYQuietConnectionStaysOpen(t *testing.T) {
	env := newPTYTestEnv(t, 1<<16)
	env.srv.execLiveness = execStreamLiveness{pingInterval: 20 * time.Millisecond, pongWait: 150 * time.Millisecond}
	handle := connectPTY(t, env, "quiet", true)
	time.Sleep(600 * time.Millisecond)
	if !handle.IsConnected() {
		t.Fatalf("a quiet terminal was disconnected: %v", handle.Error())
	}
	sendInput(t, handle, `echo "still=$((1+1))"`)
	readUntil(t, handle, regexp.MustCompile(`still=(2)`))
}

func TestDaytonaPTYRouteErrors(t *testing.T) {
	env := newPTYTestEnv(t, 1<<14)
	h := authedRoutes(env.srv)
	ctx := ptyCtx(t)
	if _, err := env.proc.CreatePtySession(ctx, "live"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := env.proc.CreatePtySession(ctx, "ended"); err != nil {
		t.Fatalf("create: %v", err)
	}
	ended, _ := ptyRecord(env, "ended")
	_ = ended.sess.Signal("KILL")
	<-ended.sess.Done()

	for _, tc := range []struct {
		name, method, path, body string
		want                     int
		missingRoute             bool
	}{
		{"invalid create JSON", http.MethodPost, "/process/pty", `{`, http.StatusBadRequest, false},
		{"id with a slash", http.MethodPost, "/process/pty", `{"id":"a/b"}`, http.StatusBadRequest, false},
		{"id with a space", http.MethodPost, "/process/pty", `{"id":"a b"}`, http.StatusBadRequest, false},
		{"id too long", http.MethodPost, "/process/pty", `{"id":"` + strings.Repeat("x", daytonaPTYIDMaxLen+1) + `"}`, http.StatusBadRequest, false},
		{"size too big", http.MethodPost, "/process/pty", `{"id":"big","cols":70000}`, http.StatusBadRequest, false},
		{"negative size", http.MethodPost, "/process/pty", `{"id":"neg","rows":-1}`, http.StatusBadRequest, false},
		{"missing cwd", http.MethodPost, "/process/pty", `{"id":"nocwd","cwd":"/no/such/folder"}`, http.StatusBadRequest, false},
		{"empty body", http.MethodPost, "/process/pty", ``, http.StatusCreated, false},
		{"bad method", http.MethodPut, "/process/pty", `{}`, http.StatusMethodNotAllowed, false},
		{"empty id", http.MethodGet, "/process/pty/", ``, http.StatusBadRequest, false},
		{"info of a missing terminal", http.MethodGet, "/process/pty/nope", ``, http.StatusNotFound, false},
		{"kill of a missing terminal", http.MethodDelete, "/process/pty/nope", ``, http.StatusNotFound, false},
		{"resize of a missing terminal", http.MethodPost, "/process/pty/nope/resize", `{"cols":80,"rows":24}`, http.StatusNotFound, false},
		{"connect to a missing terminal", http.MethodGet, "/process/pty/nope/connect", ``, http.StatusNotFound, false},
		{"invalid resize JSON", http.MethodPost, "/process/pty/live/resize", `{`, http.StatusBadRequest, false},
		{"zero resize", http.MethodPost, "/process/pty/live/resize", `{"cols":0,"rows":24}`, http.StatusBadRequest, false},
		{"huge resize", http.MethodPost, "/process/pty/live/resize", `{"cols":80,"rows":70000}`, http.StatusBadRequest, false},
		{"resize of a finished terminal", http.MethodPost, "/process/pty/ended/resize", `{"cols":80,"rows":24}`, http.StatusConflict, false},
		{"connect without an upgrade", http.MethodGet, "/process/pty/live/connect", ``, http.StatusBadRequest, false},
		{"info bad method", http.MethodPut, "/process/pty/live", ``, http.StatusMethodNotAllowed, false},
		{"resize bad method", http.MethodGet, "/process/pty/live/resize", ``, http.StatusMethodNotAllowed, false},
		{"connect bad method", http.MethodPost, "/process/pty/live/connect", ``, http.StatusMethodNotAllowed, false},
		{"unknown action", http.MethodGet, "/process/pty/live/bogus", ``, http.StatusNotFound, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rr.Code != tc.want {
				t.Fatalf("%s %s = %d %s, want %d", tc.method, tc.path, rr.Code, rr.Body.String(), tc.want)
			}
			if got := rr.Header().Get(routeMissingHeader) != ""; got != tc.missingRoute {
				t.Fatalf("route-missing header = %v, want %v", got, tc.missingRoute)
			}
			if rr.Code >= 400 {
				var body models.ErrorResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Error == "" {
					t.Fatalf("error body = %q, want a message", rr.Body.String())
				}
			}
		})
	}

	t.Run("sessions disabled", func(t *testing.T) {
		rr := httptest.NewRecorder()
		authedRoutes(&server{logger: env.srv.logger}).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/process/pty", nil))
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rr.Code)
		}
	})
	t.Run("unauthenticated", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/process/pty", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

// A shell that will not start answers an error and gives its id and its
// slot back, so the next create can use them.
func TestDaytonaPTYStartFailureFreesTheID(t *testing.T) {
	fail := true
	var mu sync.Mutex
	env := newPTYTestEnvWith(t, sessions.Config{
		BufferBytes: 1 << 14,
		StartProcess: func(cmd *exec.Cmd, start func() error) (func() (int, string), error) {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return nil, errors.New("fork failed")
			}
			if err := start(); err != nil {
				return nil, err
			}
			return func() (int, string) { return interpretWaitResult(cmd.Wait()) }, nil
		},
	})
	env.ptys.limit = 1
	rr := httptest.NewRecorder()
	h := authedRoutes(env.srv)
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/process/pty", strings.NewReader(`{"id":"flaky"}`)))
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "fork failed") {
		t.Fatalf("create with a failing start = %d %s, want 500 naming the cause", rr.Code, rr.Body.String())
	}
	if _, ok := ptyRecord(env, "flaky"); ok {
		t.Fatal("a failed create left its id claimed")
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/process/pty", strings.NewReader(`{"id":"flaky"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create after the failure = %d %s, want 201", rr.Code, rr.Body.String())
	}
}

func TestDaytonaPTYStartError(t *testing.T) {
	var ptyErr *errDaytonaPTY
	if err := daytonaPTYStartError(fmt.Errorf("wrapped: %w", sessions.ErrNoShell)); !errors.As(err, &ptyErr) || ptyErr.status != http.StatusBadRequest || !strings.Contains(err.Error(), "no shell") {
		t.Fatalf("no shell = %v, want 400 naming it", err)
	}
	if err := daytonaPTYStartError(errors.New("boom")); errors.As(err, &ptyErr) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("other failure = %v, want a plain 500 error", err)
	}
	rr := httptest.NewRecorder()
	writeDaytonaPTYError(rr, errors.New("boom"))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("plain error = %d, want 500", rr.Code)
	}
}

func TestNewDaytonaPTYsWithoutALogger(t *testing.T) {
	if p := newDaytonaPTYs(nil, nil); p.logger == nil {
		t.Fatal("no logger")
	}
}

func TestDaytonaPTYExitReason(t *testing.T) {
	for _, tc := range []struct {
		code   int
		signal string
		want   string
	}{
		{0, "", `{"exitCode":0}`},
		{7, "", `{"exitCode":7}`},
		{-1, "hangup", `{"exitCode":-1,"exitReason":"terminated by signal: hangup"}`},
		{-1, strings.Repeat("x", 200), `{"exitCode":-1}`},
	} {
		if got := daytonaPTYExitReason(tc.code, tc.signal); got != tc.want {
			t.Errorf("daytonaPTYExitReason(%d, %q) = %s, want %s", tc.code, tc.signal, got, tc.want)
		}
	}
}
