package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func runExecRequest(t *testing.T, s *server, command string, timeoutSeconds int) (models.ExecResult, time.Duration) {
	t.Helper()
	body, _ := json.Marshal(models.ExecRequest{Command: command, TimeoutSeconds: timeoutSeconds})
	rr := httptest.NewRecorder()
	start := time.Now()
	s.handleExec(rr, httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(string(body))))
	took := time.Since(start)
	if rr.Code != http.StatusOK {
		t.Fatalf("exec %q = %d %s", command, rr.Code, rr.Body.String())
	}
	var res models.ExecResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return res, took
}

func newExecTestServer() *server {
	return &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), allowedPorts: map[int]struct{}{}}
}

func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func killPID(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) }

// waitGone polls because a killed orphan is reaped by init asynchronously.
func waitGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !pidAlive(pid)
}

func setExecGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := execOutputGrace
	execOutputGrace = d
	t.Cleanup(func() { execOutputGrace = old })
}

// B2: a command that starts a background job returns when the command
// itself ends, and the job keeps running. Before B2 this call waited for
// the job (30 s here).
func TestExecReturnsWhileBackgroundJobKeepsRunning(t *testing.T) {
	setExecGrace(t, 300*time.Millisecond)
	res, took := runExecRequest(t, newExecTestServer(), "sleep 30 & echo $!", 20)
	pid, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		t.Fatalf("stdout %q has no pid", res.Stdout)
	}
	t.Cleanup(func() { killPID(pid) })
	if took > 5*time.Second {
		t.Fatalf("exec took %v; it waited for the background job", took)
	}
	if res.ExitCode != 0 || res.TimedOut {
		t.Fatalf("result = %+v", res)
	}
	if !pidAlive(pid) {
		t.Fatalf("background job %d was killed; it must keep running", pid)
	}
}

// B2: on a timeout the whole process group dies, including background
// jobs, and the reply says timed_out. Before B2 only the shell was killed
// and the call never returned while the job held the output.
func TestExecTimeoutKillsTheWholeProcessGroup(t *testing.T) {
	setExecGrace(t, 300*time.Millisecond)
	res, took := runExecRequest(t, newExecTestServer(), "sleep 30 & echo $!; sleep 30", 1)
	pid, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		t.Fatalf("stdout %q has no pid", res.Stdout)
	}
	t.Cleanup(func() { killPID(pid) })
	if !res.TimedOut {
		t.Fatalf("timed_out not set: %+v", res)
	}
	if took > 6*time.Second {
		t.Fatalf("timed-out exec took %v", took)
	}
	if !waitGone(pid, 3*time.Second) {
		t.Fatalf("background job %d survived the timeout", pid)
	}
}

// Output a background job writes before it exits, inside the grace, is in
// the reply; output written after the reply is dropped and never mixes in.
func TestExecGraceKeepsEarlyOutputAndDropsLateOutput(t *testing.T) {
	setExecGrace(t, 600*time.Millisecond)
	res, _ := runExecRequest(t, newExecTestServer(), "(sleep 0.1; echo inside) & echo first", 10)
	if !strings.Contains(res.Stdout, "first") || !strings.Contains(res.Stdout, "inside") {
		t.Fatalf("stdout %q, want both lines (late line arrived inside the grace)", res.Stdout)
	}

	setExecGrace(t, 100*time.Millisecond)
	res, took := runExecRequest(t, newExecTestServer(), "(sleep 1; echo after) & echo first", 10)
	if res.Stdout != "first\n" {
		t.Fatalf("stdout %q, want only the line written before the reply", res.Stdout)
	}
	if took > 900*time.Millisecond {
		t.Fatalf("exec took %v; it waited past the grace", took)
	}
}

// Normal commands keep their full output and exit status (ER2 preserve
// list); the grace never applies when nothing holds the output.
func TestExecWithoutBackgroundJobsIsUnchanged(t *testing.T) {
	setExecGrace(t, 5*time.Second)
	res, took := runExecRequest(t, newExecTestServer(), "printf 'out'; printf 'err' 1>&2; exit 7", 10)
	if res.Stdout != "out" || res.Stderr != "err" || res.ExitCode != 7 || res.TimedOut {
		t.Fatalf("result = %+v", res)
	}
	if took > 2*time.Second {
		t.Fatalf("exec took %v; the grace applied with no background job", took)
	}
}

// ER3: past the drainer limit a background job's output is closed instead
// of keeping a reader, so toolboxd cannot run out of file descriptors.
// /health reports the count and the cap.
func TestExecDrainerLimit(t *testing.T) {
	setExecGrace(t, 100*time.Millisecond)
	oldMax := maxExecDrainers
	maxExecDrainers = 1
	t.Cleanup(func() { maxExecDrainers = oldMax })
	s := newExecTestServer()
	// Earlier tests' background jobs release their drainers asynchronously.
	waitDrainers(t, 0)
	before := execDrainers.Load()

	first, _ := runExecRequest(t, s, "sleep 20 & echo $!", 10)
	firstPID, _ := strconv.Atoi(strings.TrimSpace(first.Stdout))
	t.Cleanup(func() { killPID(firstPID) })
	if got := execDrainers.Load(); got != before+1 {
		t.Fatalf("drainers = %d, want %d", got, before+1)
	}

	// The second job writes after the reply; with its output closed it is
	// stopped by SIGPIPE on that write, and no second drainer is kept.
	second, _ := runExecRequest(t, s, "(sleep 0.3; while true; do echo tick; sleep 0.1; done) & echo $!", 10)
	secondPID, _ := strconv.Atoi(strings.TrimSpace(second.Stdout))
	t.Cleanup(func() { killPID(secondPID) })
	if got := execDrainers.Load(); got != before+1 {
		t.Fatalf("drainers = %d after the cap, want %d", got, before+1)
	}
	if !waitGone(secondPID, 5*time.Second) {
		t.Fatalf("job %d kept running with its output closed", secondPID)
	}

	h := authedRoutes(s)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	var health map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["exec_drainers_at_cap"] != true {
		t.Fatalf("/health = %v, want exec_drainers_at_cap true", health)
	}

	killPID(firstPID)
	waitDrainers(t, before)
}

func waitDrainers(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for execDrainers.Load() != want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := execDrainers.Load(); got != want {
		t.Fatalf("drainers = %d, want %d", got, want)
	}
}

func TestPrepareProcessGroupCancel(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "true")
	prepareProcessGroup(cmd)
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid not set")
	}
	if err := cmd.Cancel(); err != nil {
		t.Fatalf("Cancel before start = %v, want nil", err)
	}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("Cancel after exit = %v, want os.ErrProcessDone", err)
	}
}

func TestRunBufferedExecStartFailure(t *testing.T) {
	cmd := exec.Command("/definitely/not/a/binary")
	if _, err := runBufferedExec(nil, cmd); err == nil {
		t.Fatal("start of a missing binary succeeded")
	}
}
