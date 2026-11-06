//go:build integration

package suite

// Live checks for the lifecycle and observability items of
// plans/agent-sandbox-feature-parity.md (L1-L6, O1, O2). Use cases
// UC-395 to UC-409.

import (
	"context"
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
