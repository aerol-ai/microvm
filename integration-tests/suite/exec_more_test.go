//go:build integration

package suite

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-68 — The streaming exec transport carries stdin to the process and its
// stdout back, and Wait reports the real exit code. This is a different code
// path from the blocking Exec (UC-39): a long-lived bidirectional stream over
// the toolbox proxy, not a single request/response.
func TestExecStreamInteractive(t *testing.T) {
	harness.Require(t, sc, "UC-68")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// OnStdout fires on the SDK's read-loop goroutine, so the buffer it writes
	// into is shared across goroutines — guard it with a mutex.
	var mu sync.Mutex
	var out strings.Builder
	// Command runs under `/bin/sh -c`, so `read` consumes the line we write to
	// stdin; the process then exits 0 on its own (no need to half-close stdin).
	handle, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command: `read line; echo "echoed:$line"`,
		OnStdout: func(b []byte) {
			mu.Lock()
			out.Write(b)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("exec stream: %v", err)
	}
	if err := handle.WriteString("marker-68\n"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	info, err := handle.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if info.Code != 0 {
		t.Fatalf("stream exit code = %d, want 0", info.Code)
	}
	mu.Lock()
	got := out.String()
	mu.Unlock()
	if !strings.Contains(got, "echoed:marker-68") {
		t.Fatalf("stream stdout = %q, want it to contain echoed:marker-68", got)
	}
}

// UC-69 — Exec honours the full request shape: a working directory and
// per-exec environment, not just a bare command string (UC-39 covers the
// string sugar).
func TestExecWithWorkdirAndEnv(t *testing.T) {
	harness.Require(t, sc, "UC-69")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{
		Command: `pwd; echo "var=$UC69"`,
		WorkDir: "/tmp",
		Env:     map[string]string{"UC69": "value-69"},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(res.Stdout, "/tmp") {
		t.Fatalf("workdir not honoured: stdout = %q, want it to contain /tmp", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "var=value-69") {
		t.Fatalf("env not honoured: stdout = %q, want it to contain var=value-69", res.Stdout)
	}
}

// UC-70 — The full session lifecycle beyond create+log (UC-42): a live PTY
// session is listed, fetched by id, resized, and terminated via a signal.
func TestSessionLifecycle(t *testing.T) {
	harness.Require(t, sc, "UC-70")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// A long-lived PTY shell so the session stays "running" while we exercise
	// list/get/resize before we signal it dead.
	sess, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{
		Name:    "uc70",
		Command: "sleep 300",
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = sb.DeleteSession(cctx, sess.ID)
	})

	// List includes it.
	list, err := sb.ListSessions(ctx)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	found := false
	for _, s := range list {
		if s.ID == sess.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("session %s not in list (%d sessions)", sess.ID, len(list))
	}

	// Get by id returns the same row.
	got, err := sb.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.ID != sess.ID {
		t.Fatalf("get returned session %q, want %q", got.ID, sess.ID)
	}

	// Resize the PTY (no-op assertion: the contract is that it's accepted).
	if err := sb.ResizeSession(ctx, sess.ID, 120, 40); err != nil {
		t.Fatalf("resize session: %v", err)
	}

	// Signal it dead and confirm it leaves the running state.
	if err := sb.SignalSession(ctx, sess.ID, "TERM"); err != nil {
		t.Fatalf("signal session: %v", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		s, err := sb.GetSession(ctx, sess.ID)
		if err == nil && s.Status != sdktypes.SessionStatusRunning {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("session never left the running state after TERM")
}

// UC-71 — A session's recording (asciinema cast) is downloadable. Recording is
// always-on in the toolbox agent, so after a PTY session has produced output
// the cast file exists and SessionRecording returns its bytes.
func TestSessionRecordingDownloadable(t *testing.T) {
	harness.Require(t, sc, "UC-71")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sess, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{
		Name:    "uc71",
		Command: `echo recorded-71; sleep 1`,
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = sb.DeleteSession(cctx, sess.ID)
	})

	// The cast is flushed as the session produces output; poll until non-empty.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := sb.SessionRecording(ctx, sess.ID)
		if err == nil && len(rec) > 0 {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("session recording never became available")
}
