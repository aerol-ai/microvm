package agenttools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

func resolveTarget(t *testing.T, tools *Tools, ref string) *microvm.Sandbox {
	t.Helper()
	sb, err := tools.Target(context.Background(), ref)
	if err != nil {
		t.Fatalf("Target(%s): %v", ref, err)
	}
	return sb
}

func TestExecStreamPath(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box", Runtime: models.RuntimeDocker})
	sb := resolveTarget(t, tools, "box")

	var live bytes.Buffer
	res, err := tools.Exec(ctx, sb, ExecRequest{Command: "echo hello", OnStdout: func(b []byte) { live.Write(b) }})
	if err != nil || res.ExitCode != 0 || res.Stdout != "hello\n" || live.String() != "hello\n" {
		t.Fatalf("echo = (%+v, %v), live %q", res, err, live.String())
	}
	res, err = tools.Exec(ctx, sb, ExecRequest{Command: "stderr oops", OnStderr: func(b []byte) { live.Write(b) }})
	if err != nil || res.Stderr != "oops\n" {
		t.Fatalf("stderr = (%+v, %v)", res, err)
	}
	// A non-zero exit is a result, not an error.
	if res, err := tools.Exec(ctx, sb, ExecRequest{Command: "exit 3"}); err != nil || res.ExitCode != 3 {
		t.Fatalf("exit 3 = (%+v, %v)", res, err)
	}
	if res, err := tools.Exec(ctx, sb, ExecRequest{Command: "signal terminated"}); err != nil || res.ExitCode != 143 || res.Signal != "terminated" {
		t.Fatalf("signal = (%+v, %v), want 128+15", res, err)
	}
	if res, err := tools.Exec(ctx, sb, ExecRequest{Command: "cat", Stdin: strings.NewReader("piped input")}); err != nil || res.Stdout != "piped input" {
		t.Fatalf("stdin = (%+v, %v)", res, err)
	}
	// No stdin: cat sees EOF at once instead of waiting forever.
	if res, err := tools.Exec(ctx, sb, ExecRequest{Command: "cat", Timeout: 5 * time.Second}); err != nil || res.TimedOut || res.Stdout != "" {
		t.Fatalf("closed stdin = (%+v, %v)", res, err)
	}
	if _, err := tools.Exec(ctx, sb, ExecRequest{Command: "  "}); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("empty command = %v", err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if s.BufferedExecs != 0 {
			t.Fatal("docker exec must stream")
		}
	})
}

func TestExecBoundsOutput(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")
	res, err := tools.Exec(context.Background(), sb, ExecRequest{Command: "yes 1000000"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.StdoutTruncated || res.StdoutDroppedBytes != 1000000-DefaultMaxOutputBytes {
		t.Fatalf("truncation = %v dropped %d", res.StdoutTruncated, res.StdoutDroppedBytes)
	}
	if len(res.Stdout) > DefaultMaxOutputBytes+64 || !strings.Contains(res.Stdout, "omitted") {
		t.Fatalf("bounded stdout is %d bytes", len(res.Stdout))
	}
}

// TestExecTimeoutKills pins §5.5: --timeout cancels the stream, sends KILL
// and reports 124.
func TestExecTimeoutKills(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")
	res, err := tools.Exec(context.Background(), sb, ExecRequest{Command: "sleep", Timeout: 100 * time.Millisecond})
	if err != nil || !res.TimedOut || res.ExitCode != TimeoutExitCode {
		t.Fatalf("timeout = (%+v, %v)", res, err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if len(s.Signals) != 1 || s.Signals[0] != "KILL" {
			t.Fatalf("signals = %v, want [KILL]", s.Signals)
		}
	})
}

// TestExecCancelSendsKill is CEO review CT2 (client half): any cancellation
// sends KILL before the stream closes, so a sandbox with an older toolboxd
// (no kill-on-drop) still stops the command.
func TestExecCancelSendsKill(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	_, err := tools.Exec(ctx, sb, ExecRequest{Command: "sleep"})
	if !IsCode(err, CodeCanceled) {
		t.Fatalf("canceled exec = %v", err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if len(s.Signals) != 1 || s.Signals[0] != "KILL" {
			t.Fatalf("signals = %v, want KILL before close", s.Signals)
		}
	})
}

func TestExecStreamDropIsAnError(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	fake.ExecFunc = func(string, io.Reader, func(byte, []byte), <-chan struct{}) (int, string) {
		return 0, agenttoolstest.DropStream // close without an exit message
	}
	sb := resolveTarget(t, tools, "box")
	_, err := tools.Exec(context.Background(), sb, ExecRequest{Command: "echo x"})
	if !IsCode(err, CodeUnavailable) || !strings.Contains(err.Error(), "ended before the command exited") {
		t.Fatalf("dropped stream = %v", err)
	}
}

// TestExecWasmBuffered pins D10: WASM sandboxes use buffered exec with no
// WebSocket, refuse a response over 4 MiB, and refuse -i/-t clearly.
func TestExecWasmBuffered(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
	sb := resolveTarget(t, tools, "wasm")

	var live strings.Builder
	res, err := tools.Exec(ctx, sb, ExecRequest{Command: "echo hi", Cwd: "/work", Timeout: 1500 * time.Millisecond, OnStdout: func(b []byte) { live.Write(b) }, OnStderr: func(b []byte) { live.Write(b) }})
	if err != nil || res.Stdout != "hi\n" || res.ExitCode != 0 || live.String() != "hi\n" {
		t.Fatalf("wasm echo = (%+v, %v), live %q", res, err, live.String())
	}
	live.Reset()
	if _, err := tools.Exec(ctx, sb, ExecRequest{Command: "stderr warn", OnStderr: func(b []byte) { live.Write(b) }}); err != nil || live.String() != "warn\n" {
		t.Fatalf("wasm stderr live = %q, %v", live.String(), err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if s.StreamDials != 0 || s.BufferedExecs != 2 {
			t.Fatalf("stream dials %d, buffered %d", s.StreamDials, s.BufferedExecs)
		}
	})
	// Long output under the limit is bounded like streamed output.
	fake.BufferedPad = 100 * 1024
	res, err = tools.Exec(ctx, sb, ExecRequest{Command: "echo hi"})
	if err != nil || !res.StdoutTruncated {
		t.Fatalf("long buffered output = (%v, %v)", res.StdoutTruncated, err)
	}
	fake.BufferedPad = MaxBufferedExecResponseBytes + 1
	if _, err := tools.Exec(ctx, sb, ExecRequest{Command: "echo hi"}); !IsCode(err, CodeOutputTooLarge) {
		t.Fatalf("over 4 MiB = %v, want output_too_large", err)
	}
	fake.BufferedPad = 0
	for name, req := range map[string]ExecRequest{
		"tty":   {Command: "echo", TTY: true},
		"stdin": {Command: "cat", Stdin: strings.NewReader("x")},
	} {
		if _, err := tools.Exec(ctx, sb, req); !IsCode(err, CodeUnsupportedRuntime) {
			t.Fatalf("%s on wasm = %v", name, err)
		}
	}
	// A command killed at its timeout reads as a timeout.
	fake.ExecFunc = func(string, io.Reader, func(byte, []byte), <-chan struct{}) (int, string) { return -1, "killed" }
	if res, err := tools.Exec(ctx, sb, ExecRequest{Command: "x", Timeout: time.Millisecond}); err != nil || !res.TimedOut || res.ExitCode != TimeoutExitCode {
		t.Fatalf("buffered timeout = (%+v, %v)", res, err)
	}
}

func TestExecBufferedForcedAndIsolate(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceMCP)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	iso := fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	sb := resolveTarget(t, tools, "box")
	if res, err := tools.Exec(ctx, sb, ExecRequest{Command: "echo forced", Buffered: true}); err != nil || res.Stdout != "forced\n" {
		t.Fatalf("forced buffered = (%+v, %v)", res, err)
	}
	isoSB := &microvm.Sandbox{}
	isoSB.ID, isoSB.Runtime = iso.ID, models.RuntimeIsolate
	if _, err := tools.Exec(ctx, isoSB, ExecRequest{Command: "echo"}); !IsCode(err, CodeUnsupportedRuntime) {
		t.Fatalf("isolate exec = %v", err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if len(s.ExecCommands) != 1 {
			t.Fatalf("isolate must not reach the toolbox: %v", s.ExecCommands)
		}
	})
}

func TestHeadTail(t *testing.T) {
	tests := []struct {
		name    string
		max     int
		writes  []string
		want    string
		dropped int64
	}{
		{name: "under budget", max: 8, writes: []string{"abc"}, want: "abc"},
		{name: "exactly budget", max: 8, writes: []string{"abcdefgh"}, want: "abcdefgh"},
		{name: "one over", max: 8, writes: []string{"abcdefghi"}, want: "ab\n[... 1 bytes omitted ...]\ndefghi", dropped: 1},
		{name: "many writes", max: 8, writes: []string{"ab", "cd", "ef", "gh", "ij", "kl"}, want: "ab\n[... 4 bytes omitted ...]\ngh" + "ijkl", dropped: 4},
		{name: "huge single write", max: 8, writes: []string{strings.Repeat("x", 100) + "end123"}, want: "xx\n[... 98 bytes omitted ...]\nend123", dropped: 98},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHeadTail(tt.max)
			for _, w := range tt.writes {
				_, _ = h.Write([]byte(w))
			}
			if got := h.String(); got != tt.want || h.Dropped() != tt.dropped || h.Truncated() != (tt.dropped > 0) {
				t.Fatalf("String() = %q dropped %d, want %q dropped %d", got, h.Dropped(), tt.want, tt.dropped)
			}
		})
	}
	// Cut points never split a rune.
	h := newHeadTail(8)
	_, _ = h.Write([]byte(strings.Repeat("é", 20)))
	if s := h.String(); !utf8.ValidString(s) {
		t.Fatalf("split rune: %q", s)
	}
	if out, truncated, dropped := boundText("short", 0); out != "short" || truncated || dropped != 0 {
		t.Fatal("boundText default budget")
	}
}

func TestSignalExitCodeAndFormat(t *testing.T) {
	for sig, want := range map[string]int{"killed": 137, "KILL": 137, "SIGTERM": 143, "terminated": 143, "interrupt": 130, "segmentation fault": 139, "": 0, "signal 99": 0} {
		if got := signalExitCode(sig); got != want {
			t.Fatalf("signalExitCode(%q) = %d, want %d", sig, got, want)
		}
	}
	for n, want := range map[int64]string{12: "12 bytes", 2048: "2 KiB", 1536: "1.5 KiB", 3 << 20: "3 MiB"} {
		if got := formatBytes(n); got != want {
			t.Fatalf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	if Classify(nil) != nil || WithHint(nil, "x") != nil {
		t.Fatal("nil must classify to nil")
	}
	tests := []struct {
		err       error
		code      string
		retryable bool
	}{
		{&microvm.APIError{StatusCode: 400, Message: "bad"}, CodeInvalidArgument, false},
		{&microvm.APIError{StatusCode: 401}, CodeUnauthorized, false},
		{&microvm.APIError{StatusCode: 403}, CodeForbidden, false},
		{&microvm.APIError{StatusCode: 404}, CodeNotFound, false},
		{&microvm.APIError{StatusCode: 409}, CodeConflict, false},
		{&microvm.APIError{StatusCode: 410}, CodeGone, false},
		{&microvm.APIError{StatusCode: 413}, CodeTooLarge, false},
		{&microvm.APIError{StatusCode: 418}, CodeInvalidArgument, false},
		{&microvm.APIError{StatusCode: 429}, CodeUnavailable, true},
		{&microvm.APIError{StatusCode: 501}, CodeUnsupportedRuntime, false},
		{&microvm.APIError{StatusCode: 503, Code: "artifact_node_unavailable"}, "artifact_node_unavailable", true},
		{&microvm.APIError{StatusCode: 500}, CodeInternal, false},
		{fmt.Errorf("wrap: %w", microvm.ErrNameLookupUnsupported), CodeServerUnsupported, false},
		{fmt.Errorf("x: %w", microvm.ErrNotFound), CodeNotFound, false},
		{context.DeadlineExceeded, CodeTimeout, false},
		{context.Canceled, CodeCanceled, false},
		{&url.Error{Op: "Get", URL: "http://x", Err: errors.New("refused")}, CodeUnreachable, true},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, CodeUnreachable, true},
		{errors.New("other"), CodeInternal, false},
	}
	for _, tt := range tests {
		e := Classify(tt.err)
		if e.Code != tt.code || e.Retryable != tt.retryable {
			t.Fatalf("Classify(%v) = %+v, want %s retryable=%v", tt.err, e, tt.code, tt.retryable)
		}
	}
	own := &Error{Code: CodeConflict, Message: "m"}
	if Classify(own) != own || errors.Unwrap(own) != nil {
		t.Fatal("an *Error classifies to itself")
	}
	hinted := WithHint(own, "do x")
	if hinted.Hint != "do x" || own.Hint != "" || WithHint(hinted, "other").Hint != "do x" {
		t.Fatal("WithHint must copy and keep the first hint")
	}
}
