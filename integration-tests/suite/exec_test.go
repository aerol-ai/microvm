//go:build integration

package suite

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-39 — Toolbox exec returns command output.
func TestExecReturnsOutput(t *testing.T) {
	harness.Require(t, sc, "UC-39")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, "echo hello-aerol")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(res.Stdout, "hello-aerol") {
		t.Fatalf("exec stdout = %q, want it to contain hello-aerol", res.Stdout)
	}
}

// UC-40 — Upload a file into the sandbox; the write succeeds.
func TestUploadFile(t *testing.T) {
	harness.Require(t, sc, "UC-40")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := sb.UploadFile(ctx, "/tmp/aerol-upload.txt", []byte("payload-42")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	// Confirm via exec that the bytes landed.
	res, err := sb.ExecCommand(ctx, "cat /tmp/aerol-upload.txt")
	if err != nil {
		t.Fatalf("exec cat: %v", err)
	}
	if !strings.Contains(res.Stdout, "payload-42") {
		t.Fatalf("uploaded file content = %q, want payload-42", res.Stdout)
	}
}

// UC-41 — Download a file; bytes round-trip exactly.
func TestDownloadFileRoundTrip(t *testing.T) {
	harness.Require(t, sc, "UC-41")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want := []byte("round-trip-bytes-\x00\x01\x02")
	if err := sb.UploadFile(ctx, "/tmp/aerol-rt.bin", want); err != nil {
		t.Fatalf("upload: %v", err)
	}
	got, err := sb.DownloadFile(ctx, "/tmp/aerol-rt.bin")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// UC-42 — Create a session that runs a command; its log captures the output.
func TestSessionRunCommand(t *testing.T) {
	harness.Require(t, sc, "UC-42")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sess, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{
		Name:    "uc42",
		Command: "echo session-output",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = sb.DeleteSession(cctx, sess.ID)
	})

	// The command is short-lived; poll the log until the output shows up.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		log, err := sb.SessionLog(ctx, sess.ID)
		if err == nil && strings.Contains(string(log), "session-output") {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("session log never contained the command output")
}

// UC-44 — Exec works on every runtime this scenario advertises. Docker is
// always present; gVisor/WASM/Firecracker are added only when the scenario's
// caps include them, so this scales with the deployment.
func TestExecOnEveryRuntime(t *testing.T) {
	harness.Require(t, sc, "UC-44")
	c := client(t)

	runtimes := []string{"docker"}
	if sc.Has(harness.CapGvisor) {
		runtimes = append(runtimes, "gvisor")
	}
	if sc.Has(harness.CapFirecracker) {
		runtimes = append(runtimes, "firecracker")
	}

	for _, rt := range runtimes {
		rt := rt
		t.Run(rt, func(t *testing.T) {
			sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
				Name:    harness.UniqueName(sc, t),
				Runtime: rt,
			})
			waitRunning(t, sb)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			res, err := sb.ExecCommand(ctx, "echo "+rt)
			if err != nil {
				t.Fatalf("exec on %s: %v", rt, err)
			}
			if !strings.Contains(res.Stdout, rt) {
				t.Fatalf("exec on %s stdout = %q", rt, res.Stdout)
			}
		})
	}
}

// UC-45 — The sessions proxy streams: attach to a PTY session, write input,
// and close cleanly. Exercises the bidirectional attach path end to end.
func TestSessionProxyStreams(t *testing.T) {
	harness.Require(t, sc, "UC-45")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sess, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{
		Name:    "uc45",
		Command: "sh",
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("create pty session: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = sb.DeleteSession(cctx, sess.ID)
	})

	handle, err := c.SDK().AttachSession(ctx, sb.ID, sess.ID, microvm.SessionAttachOptions{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("attach session: %v", err)
	}
	if err := handle.WriteString("echo streamed && exit\n"); err != nil {
		t.Fatalf("write to session: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close session stream: %v", err)
	}
}
