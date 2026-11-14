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
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
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

// parityArgv is a program and arguments a shell would mangle: spaces,
// quotes, $, ; and backticks reach printf whole, or the output shows it.
var parityArgv = []string{"printf", "%s|", "a b", "'single'", `"double"`, "$HOME", "; echo pwned", "`id`", "*"}

const parityArgvWant = `a b|'single'|"double"|$HOME|; echo pwned|` + "`id`" + `|*|`

// UC-382 — exec with argv (plan E2): hostile-looking arguments reach the
// program with no shell parsing, on exec and on the exec stream, and argv
// finds a program the login profile puts on PATH, as a command does.
func TestParityExecArgv(t *testing.T) {
	harness.Require(t, sc, "UC-382")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Argv: parityArgv})
	if err != nil {
		t.Fatalf("argv exec: %v", err)
	}
	if res.Stdout != parityArgvWant || res.ExitCode != 0 {
		t.Fatalf("argv exec = %q exit %d, want %q", res.Stdout, res.ExitCode, parityArgvWant)
	}

	var out strings.Builder
	handle, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{Argv: parityArgv, OnStdout: func(b []byte) { out.Write(b) }})
	if err != nil {
		t.Fatalf("argv stream: %v", err)
	}
	exit, err := handle.Wait()
	if err != nil || exit.Code != 0 || out.String() != parityArgvWant {
		t.Fatalf("argv stream = %q exit %+v err %v, want %q", out.String(), exit, err, parityArgvWant)
	}

	// A tool only the login profile puts on PATH (conda, nix and sdkman do
	// it this way) is found by argv exactly as by a command string.
	setup := "mkdir -p /opt/uc382/bin && printf '#!/bin/sh\\nprintf \"tool:%%s\" \"$1\"\\n' > /opt/uc382/bin/uc382tool && " +
		"chmod +x /opt/uc382/bin/uc382tool && echo 'PATH=\"$PATH:/opt/uc382/bin\"; export PATH' > /etc/profile.d/uc382.sh"
	if res, err := sb.ExecCommand(ctx, setup); err != nil || res.ExitCode != 0 {
		t.Fatalf("profile setup: %+v %v", res, err)
	}
	for _, req := range []sdktypes.ExecRequest{{Command: "uc382tool 'a b'"}, {Argv: []string{"uc382tool", "a b"}}} {
		res, err := sb.Exec(ctx, req)
		if err != nil || res.Stdout != "tool:a b" || res.ExitCode != 0 {
			t.Fatalf("%+v = %+v %v, want the profile's tool", req, res, err)
		}
	}
	_, _ = sb.ExecCommand(ctx, "rm -rf /opt/uc382 /etc/profile.d/uc382.sh")
}

// UC-383 — argv naming a missing program answers like a shell: exit 127
// and a "not found" line on stderr, on exec and on the exec stream.
func TestParityExecArgvMissingProgram(t *testing.T) {
	harness.Require(t, sc, "UC-383")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Argv: []string{"uc383-no-such-program", "x"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 127 || !strings.Contains(res.Stderr, "not found") {
		t.Fatalf("missing program = exit %d stderr %q, want 127 and not found", res.ExitCode, res.Stderr)
	}

	var stderr strings.Builder
	handle, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{Argv: []string{"uc383-no-such-program"}, OnStderr: func(b []byte) { stderr.Write(b) }})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	exit, err := handle.Wait()
	if err != nil || exit.Code != 127 || !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("missing program stream = %+v %v stderr %q", exit, err, stderr.String())
	}
}

// assertExecReportsSignal is plan E3: the buffered exec result names the
// signal that ended the process (exit_code stays -1), for argv, for a
// timeout, and not when a shell outlives its killed child (137).
func assertExecReportsSignal(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Argv: []string{"sh", "-c", "kill -SEGV $$"}})
	if err != nil {
		t.Fatalf("crash: %v", err)
	}
	if res.Signal != "SIGSEGV" || res.ExitCode != -1 {
		t.Fatalf("crashed program = signal %q exit %d, want SIGSEGV and -1", res.Signal, res.ExitCode)
	}

	res, err = sb.Exec(ctx, sdktypes.ExecRequest{Command: "sleep 120", TimeoutSeconds: 2})
	if err != nil {
		t.Fatalf("timeout: %v", err)
	}
	if res.Signal != "SIGKILL" || !res.TimedOut || res.ExitCode != -1 {
		t.Fatalf("timed-out command = signal %q timed_out %v exit %d, want SIGKILL", res.Signal, res.TimedOut, res.ExitCode)
	}

	res, err = sb.Exec(ctx, sdktypes.ExecRequest{Command: "sh -c 'kill -KILL $$'; exit $?"})
	if err != nil {
		t.Fatalf("shell outlives child: %v", err)
	}
	if res.Signal != "" || res.ExitCode != 137 {
		t.Fatalf("shell-reported kill = signal %q exit %d, want none and 137", res.Signal, res.ExitCode)
	}
}

// UC-384 — exec reports the signal that ended a command (plan E3).
func TestParityExecSignal(t *testing.T) {
	harness.Require(t, sc, "UC-384")
	assertExecReportsSignal(t, paritySandbox(t))
}

// UC-385 — the same on gVisor, where the reaper can win the wait and toolboxd
// reads the status it collected (UC-335 history).
func TestParityExecSignalGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-385")
	sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Runtime: "gvisor"})
	waitRunning(t, sb)
	assertExecReportsSignal(t, sb)
}
