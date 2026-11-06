//go:build integration

package suite

// Live checks for the lifecycle and observability items of
// plans/agent-sandbox-feature-parity.md (L1-L6, O1, O2). Use cases
// UC-395 to UC-409.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// waitReason polls a sandbox until it reaches the status with the reason,
// and returns the last read.
func waitReason(t *testing.T, c *harness.Client, id, status, reason string, timeout time.Duration) *microvm.Sandbox {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last *microvm.Sandbox
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		sb, err := c.SDK().Get(ctx, id)
		cancel()
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		last = sb
		if string(sb.Status) == status && sb.StatusReason == reason {
			return sb
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("sandbox %s never reached %s/%s (last %s/%q, exit %v)", id, status, reason, last.Status, last.StatusReason, last.ExitCode)
	return nil
}

// UC-395 — status_reason (plan L2): a stop call records user_stop and a
// start clears it; the idle timer records idle. Neither carries an exit code.
func TestParityStatusReasonLive(t *testing.T) {
	harness.Require(t, sc, "UC-395")
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if _, err := c.SDK().Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	got := waitReason(t, c, sb.ID, "stopped", sdktypes.StatusReasonUserStop, time.Minute)
	if got.ExitCode != nil {
		t.Fatalf("user stop carries exit code %d", *got.ExitCode)
	}
	if _, err := c.SDK().Start(ctx, sb.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitReason(t, c, sb.ID, "started", "", 90*time.Second)

	// The lifecycle sweep runs once a minute: a one-minute idle timer stops
	// the sandbox within about two.
	idle := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:      harness.UniqueName(sc, t) + "-idle",
		Lifecycle: &sdktypes.Lifecycle{StopIfIdleFor: time.Minute},
	})
	waitRunning(t, idle)
	got = waitReason(t, c, idle.ID, "stopped", sdktypes.StatusReasonIdle, 4*time.Minute)
	if got.ExitCode != nil {
		t.Fatalf("idle stop carries exit code %d", *got.ExitCode)
	}
}

// crashSandbox makes the sandbox's init (toolboxd, PID 1) exit with a
// non-zero code: SIGQUIT is one of the signals the Go runtime handles, so it
// reaches PID 1 inside the container and ends it with a stack dump and exit
// status 2. The exec that sends it dies with it, so its error is expected.
func crashSandbox(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _ = sb.ExecCommand(ctx, "kill -QUIT 1")
}

// UC-396 — restartOnFailure (plan L1) restarts a crashed Docker sandbox:
// after 5 s the first time and 10 s the second, with status_reason
// restarted and the crash's exit code; a stop afterwards stays stopped.
func TestParityRestartOnFailureLive(t *testing.T) {
	harness.Require(t, sc, "UC-396")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:      harness.UniqueName(sc, t),
		Runtime:   sdktypes.RuntimeDocker,
		Lifecycle: &sdktypes.Lifecycle{RestartOnFailure: true},
	})
	waitRunning(t, sb)

	var waits []time.Duration
	for _, minWait := range []time.Duration{4 * time.Second, 9 * time.Second} {
		crashed := time.Now()
		crashSandbox(t, sb)
		got := waitReason(t, c, sb.ID, "started", sdktypes.StatusReasonRestarted, 2*time.Minute)
		took := time.Since(crashed)
		if took < minWait {
			t.Fatalf("restart %d came %v after the crash, before its %v wait", len(waits)+1, took, minWait)
		}
		if got.ExitCode == nil || *got.ExitCode == 0 {
			t.Fatalf("restarted sandbox's exit code = %v, want the crash's non-zero code", got.ExitCode)
		}
		waits = append(waits, took)
		waitRunning(t, sb)
		// The next crash must not race the reason of this restart.
		time.Sleep(2 * time.Second)
	}
	t.Logf("restart waits: %v", waits)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.SDK().Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitReason(t, c, sb.ID, "stopped", sdktypes.StatusReasonUserStop, time.Minute)
	time.Sleep(15 * time.Second)
	if got, err := c.SDK().Get(ctx, sb.ID); err != nil || string(got.Status) != "stopped" {
		t.Fatalf("after a stop the sandbox came back: %v %v", got, err)
	}
}

// wantBadRequest asserts err is the API's 400 and that its message names
// the option.
func wantBadRequest(t *testing.T, err error, option string) {
	t.Helper()
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("err = %v, want HTTP 400", err)
	}
	if !strings.Contains(apiErr.Message, option) {
		t.Fatalf("400 message %q does not name %s", apiErr.Message, option)
	}
}

// UC-397 — restartOnFailure is refused on Firecracker with a clear 400 (plan
// L1, P4): its VMM exits are not a die event this can act on.
func TestParityRestartOnFailureRefusedOnFirecrackerLive(t *testing.T) {
	harness.Require(t, sc, "UC-397")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	createRefused(t, ctx, sdktypes.CreateSandboxOptions{
		Name:      harness.UniqueName(sc, t),
		Image:     harness.DefaultImage,
		Runtime:   sdktypes.RuntimeFirecracker,
		Lifecycle: &sdktypes.Lifecycle{RestartOnFailure: true},
	}, "restart_on_failure")
}

// createRefused asserts a create is refused with a 400 naming option, and
// cleans up a sandbox a wrong answer created.
func createRefused(t *testing.T, ctx context.Context, opts sdktypes.CreateSandboxOptions, option string) {
	t.Helper()
	c := client(t)
	sb, err := c.SDK().Create(ctx, opts)
	if err == nil && sb != nil {
		_ = c.SDK().Destroy(context.Background(), sb.ID)
	}
	wantBadRequest(t, err, option)
}
