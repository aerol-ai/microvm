//go:build integration

package suite

// Live checks for the exec lane of plans/agent-sandbox-feature-parity.md
// (E1-E3). They reuse parity_test.go's helpers.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-380 — exec output caps (plan E1): each stream keeps its first N bytes
// and says it was cut, the command still exits 0 and is not slowed by the
// output it drops, and the agent lists the caps on /version (ER4).
func TestParityExecOutputCaps(t *testing.T) {
	harness.Require(t, sc, "UC-380")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := sb.ToolboxRequest(ctx, http.MethodGet, "/version", nil, nil, "")
	if err != nil {
		t.Fatalf("toolbox /version: %v", err)
	}
	version, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(version), `"exec.max_output_bytes"`) {
		t.Fatalf("toolbox /version = %s, want exec.max_output_bytes", version)
	}

	// 4 MiB on each stream: far more than a pipe holds, so an agent that
	// stopped reading at the cap would hang the command until the timeout.
	const loud = "head -c 4194304 /dev/zero | tr '\\0' o; head -c 4194304 /dev/zero | tr '\\0' e >&2; exit 0"
	start := time.Now()
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: loud, TimeoutSeconds: 60, MaxStdoutBytes: 100, MaxStderrBytes: 10})
	if err != nil {
		t.Fatalf("capped exec: %v", err)
	}
	if res.Stdout != strings.Repeat("o", 100) || res.Stderr != strings.Repeat("e", 10) {
		t.Fatalf("kept %d bytes of stdout and %d of stderr, want 100 and 10", len(res.Stdout), len(res.Stderr))
	}
	if !res.StdoutTruncated || !res.StderrTruncated || res.ExitCode != 0 || res.TimedOut {
		t.Fatalf("result = truncated %v/%v exit %d timed_out %v", res.StdoutTruncated, res.StderrTruncated, res.ExitCode, res.TimedOut)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("capped exec took %v; dropping the rest held the command up", took)
	}

	// A cap above the output keeps it whole and unflagged (ER2: full output).
	res, err = sb.Exec(ctx, sdktypes.ExecRequest{Command: "printf hello; printf oops >&2", MaxStdoutBytes: 1 << 20, MaxStderrBytes: 1 << 20})
	if err != nil {
		t.Fatalf("exec under its caps: %v", err)
	}
	if res.Stdout != "hello" || res.Stderr != "oops" || res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("result = %+v", res)
	}
}

// UC-381 — the caps are clamped on the way: a cap above the agent's 64 MiB
// ceiling (or above the operator's SB_EXEC_OUTPUT_MAX_BYTES, if the scenario
// sets one) is lowered, and a caller's cap below it is kept. No scenario
// sets the operator's default or maximum today; their fill-in and clamp on
// the v1, Daytona and Runloop paths are covered offline in
// internal/service, pkg/api/v1, pkg/api/daytona and pkg/api/runloop
// (exec_output_policy_test.go).
func TestParityExecOutputCapClamp(t *testing.T) {
	harness.Require(t, sc, "UC-381")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	const ceiling = 64 << 20
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{
		Command:        "head -c 68157440 /dev/zero | tr '\\0' a", // 65 MiB
		TimeoutSeconds: 120,
		MaxStdoutBytes: 128 << 20,
	})
	if err != nil {
		t.Fatalf("exec past the ceiling: %v", err)
	}
	if !res.StdoutTruncated || len(res.Stdout) == 0 || len(res.Stdout) > ceiling || res.ExitCode != 0 {
		t.Fatalf("kept %d bytes (truncated %v, exit %d), want at most %d and cut", len(res.Stdout), res.StdoutTruncated, res.ExitCode, ceiling)
	}
	if strings.Trim(res.Stdout, "a") != "" {
		t.Fatal("kept output is not the start of the stream")
	}
	t.Logf("a 128 MiB cap on 65 MiB of output kept %d bytes", len(res.Stdout))

	res, err = sb.Exec(ctx, sdktypes.ExecRequest{Command: "head -c 2048 /dev/zero | tr '\\0' b", MaxStdoutBytes: 1024})
	if err != nil {
		t.Fatalf("exec with a small cap: %v", err)
	}
	if len(res.Stdout) != 1024 || !res.StdoutTruncated {
		t.Fatalf("kept %d bytes (truncated %v), want the caller's 1024", len(res.Stdout), res.StdoutTruncated)
	}
}
