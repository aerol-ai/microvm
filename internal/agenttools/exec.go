package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// MaxBufferedExecResponseBytes caps how much of a buffered exec response is
// read (eng review D10). Buffered exec returns stdout and stderr in one JSON
// body, and toolbox /process/execute doesn't cap output, so a larger body is
// refused rather than decoded into memory. It can't be truncated instead: a
// JSON body cut short doesn't decode.
const MaxBufferedExecResponseBytes = 4 << 20

// TimeoutExitCode is what a command stopped by its timeout reports, matching
// GNU timeout.
const TimeoutExitCode = 124

// killGrace is how long a cancelled exec waits for the sandbox to report the
// killed command's exit before closing the stream anyway.
const killGrace = 2 * time.Second

// ExecRequest runs one command in a sandbox.
type ExecRequest struct {
	Command string
	Cwd     string
	Env     map[string]string
	// Timeout stops the command (KILL) and reports exit code 124. Zero means
	// no client-side timeout on the streaming path; the buffered path then
	// uses the toolbox default of 5 minutes.
	Timeout time.Duration
	// Stdin is forwarded to the command, then closed at EOF. Nil closes
	// stdin immediately. Not supported on the buffered path.
	Stdin io.Reader
	// TTY requests a pseudo-terminal of Cols x Rows. Streaming path only.
	TTY        bool
	Cols, Rows int
	// Resize delivers the local terminal's new size after a resize, so
	// full-screen programs (vim, top) redraw to fit. Used only with TTY.
	Resize <-chan TermSize
	// MaxOutputBytes bounds the captured output per stream; zero means
	// DefaultMaxOutputBytes.
	MaxOutputBytes int
	// OnStdout and OnStderr receive output live, in addition to capture.
	OnStdout func([]byte)
	OnStderr func([]byte)
	// Buffered forces the buffered path for every runtime. The remote MCP
	// endpoint sets it: its in-process transport can't carry a WebSocket.
	Buffered bool
}

// TermSize is a terminal size in character cells.
type TermSize struct{ Cols, Rows int }

// ExecResult is a finished command. ExitCode follows `docker exec`: the
// command's own code, 128+n when a signal killed it, 124 on timeout.
type ExecResult struct {
	ExitCode           int    `json:"exit_code"`
	Signal             string `json:"signal,omitempty"`
	TimedOut           bool   `json:"timed_out,omitempty"`
	Stdout             string `json:"stdout"`
	Stderr             string `json:"stderr"`
	StdoutTruncated    bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated    bool   `json:"stderr_truncated,omitempty"`
	StdoutDroppedBytes int64  `json:"stdout_dropped_bytes,omitempty"`
	StderrDroppedBytes int64  `json:"stderr_dropped_bytes,omitempty"`
	DurationMS         int64  `json:"duration_ms"`
}

// Exec runs req in sb and returns its exit status with bounded output. A
// non-zero exit is a normal result, not an error; errors are API, transport
// and argument failures.
//
// The channel depends on the runtime (eng review D10): WASM sandboxes refuse
// streaming exec, so they use buffered /process/execute under
// MaxBufferedExecResponseBytes; every other runtime streams over the exec
// WebSocket into head/tail buffers.
func (t *Tools) Exec(ctx context.Context, sb *microvm.Sandbox, req ExecRequest) (ExecResult, error) {
	if strings.TrimSpace(req.Command) == "" {
		return ExecResult{}, newError(CodeInvalidArgument, "command is required")
	}
	if err := RequireShell(sb); err != nil {
		return ExecResult{}, err
	}
	if req.Buffered || IsWasm(sb) {
		if req.TTY || req.Stdin != nil {
			return ExecResult{}, &Error{
				Code:    CodeUnsupportedRuntime,
				Message: "interactive exec (stdin or a TTY) is not available on WASM sandboxes; run the command without -i/-t, or write input to a file first",
			}
		}
		return t.execBuffered(ctx, sb, req)
	}
	return t.execStream(ctx, sb, req)
}

// IsWasm reports whether sb runs on the WASM runtime.
func IsWasm(sb *microvm.Sandbox) bool {
	return sb != nil && strings.TrimSpace(sb.Runtime) == models.RuntimeWasm
}

func (t *Tools) execStream(ctx context.Context, sb *microvm.Sandbox, req ExecRequest) (ExecResult, error) {
	start := time.Now()
	var mu sync.Mutex
	stdout, stderr := newHeadTail(req.MaxOutputBytes), newHeadTail(req.MaxOutputBytes)
	capture := func(buf *headTail, live func([]byte)) func([]byte) {
		return func(chunk []byte) {
			mu.Lock()
			_, _ = buf.Write(chunk)
			mu.Unlock()
			if live != nil {
				live(chunk)
			}
		}
	}
	// The stream gets its own context: on cancellation agenttools sends KILL
	// first and only then closes the stream (CEO review CT2). Handing the
	// SDK the caller's context would close the stream the moment it ends,
	// before the KILL could go out. toolboxd also kills on a dropped stream,
	// but a sandbox with an older toolboxd only stops on the KILL.
	streamCtx, closeStream := context.WithCancel(context.WithoutCancel(ctx))
	defer closeStream()
	handle, err := sb.ExecStream(streamCtx, sdktypes.ExecStreamOptions{
		Command:  req.Command,
		Workdir:  req.Cwd,
		Env:      req.Env,
		TTY:      req.TTY,
		Cols:     req.Cols,
		Rows:     req.Rows,
		OnStdout: capture(stdout, req.OnStdout),
		OnStderr: capture(stderr, req.OnStderr),
	})
	if err != nil {
		return ExecResult{}, Classify(err)
	}
	forwardStdin(handle, req.Stdin)
	if req.TTY && req.Resize != nil {
		go ForwardResizes(streamCtx, req.Resize, handle.Resize)
	}

	type waitResult struct {
		info sdktypes.ExecExitInfo
		err  error
	}
	done := make(chan waitResult, 1)
	go func() {
		info, err := handle.Wait()
		done <- waitResult{info, err}
	}()
	var timeout <-chan time.Time
	if req.Timeout > 0 {
		timer := time.NewTimer(req.Timeout)
		defer timer.Stop()
		timeout = timer.C
	}

	result := func() ExecResult {
		mu.Lock()
		defer mu.Unlock()
		return ExecResult{
			Stdout:             stdout.String(),
			Stderr:             stderr.String(),
			StdoutTruncated:    stdout.Truncated(),
			StderrTruncated:    stderr.Truncated(),
			StdoutDroppedBytes: stdout.Dropped(),
			StderrDroppedBytes: stderr.Dropped(),
			DurationMS:         time.Since(start).Milliseconds(),
		}
	}
	kill := func() {
		_ = handle.Signal("KILL")
		select {
		case <-done:
		case <-time.After(killGrace):
		}
		closeStream()
	}

	select {
	case w := <-done:
		res := result()
		if w.err != nil {
			// The toolbox couldn't start the command (an image with no
			// shell, say). The stream didn't drop, and repeating the call
			// won't help.
			var refused *microvm.StreamError
			if errors.As(w.err, &refused) {
				return res, &Error{Code: CodeInvalidArgument, Message: refused.Message, cause: w.err}
			}
			return res, &Error{
				Code:      CodeUnavailable,
				Message:   "the exec stream ended before the command exited (" + w.err.Error() + "); the sandbox stops a command whose stream drops",
				Retryable: true,
				cause:     w.err,
			}
		}
		res.Signal = w.info.Signal
		res.ExitCode = w.info.Code
		if code := signalExitCode(w.info.Signal); code != 0 {
			res.ExitCode = code
		}
		return res, nil
	case <-timeout:
		kill()
		res := result()
		res.TimedOut = true
		res.ExitCode = TimeoutExitCode
		return res, nil
	case <-ctx.Done():
		kill()
		return result(), Classify(ctx.Err())
	}
}

// forwardStdin copies r into the command's stdin and closes stdin at EOF.
// With no reader, stdin is closed at once so a command that reads it sees
// EOF instead of waiting forever.
func forwardStdin(handle *microvm.ExecStreamHandle, r io.Reader) {
	if r == nil {
		_ = handle.Close()
		return
	}
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if werr := handle.Write(append([]byte(nil), buf[:n]...)); werr != nil {
					return
				}
			}
			if err != nil {
				_ = handle.Close()
				return
			}
		}
	}()
}

// ForwardResizes sends each new terminal size to the remote PTY until ctx
// ends or sizes closes. A failed send is dropped: it means the stream is
// ending, and the end is reported by Wait.
func ForwardResizes(ctx context.Context, sizes <-chan TermSize, resize func(cols, rows int) error) {
	for {
		select {
		case <-ctx.Done():
			return
		case size, ok := <-sizes:
			if !ok {
				return
			}
			if size.Cols > 0 && size.Rows > 0 {
				_ = resize(size.Cols, size.Rows)
			}
		}
	}
}

func (t *Tools) execBuffered(ctx context.Context, sb *microvm.Sandbox, req ExecRequest) (ExecResult, error) {
	start := time.Now()
	body, err := json.Marshal(models.ExecRequest{
		Command:        req.Command,
		WorkDir:        req.Cwd,
		Env:            req.Env,
		TimeoutSeconds: timeoutSeconds(req.Timeout),
	})
	if err != nil {
		return ExecResult{}, Classify(err)
	}
	resp, err := sb.ToolboxRequest(ctx, http.MethodPost, "/process/execute", nil, body, "application/json")
	if err != nil {
		return ExecResult{}, Classify(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBufferedExecResponseBytes+1))
	if err != nil {
		return ExecResult{}, Classify(err)
	}
	if len(raw) > MaxBufferedExecResponseBytes {
		return ExecResult{}, &Error{
			Code:    CodeOutputTooLarge,
			Message: "the command's output is larger than 4 MiB, more than buffered exec returns",
			Hint:    "redirect output to a file and read it in parts, e.g. `cmd > /tmp/out.txt 2>&1`, then read_file /tmp/out.txt",
		}
	}
	var out models.ExecResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return ExecResult{}, &Error{Code: CodeInternal, Message: "decode exec response: " + err.Error(), cause: err}
	}
	// Live sinks get the whole output: the CLI prints it unbounded, as it
	// does for a streamed exec. Only the returned result is bounded.
	if req.OnStdout != nil && out.Stdout != "" {
		req.OnStdout([]byte(out.Stdout))
	}
	if req.OnStderr != nil && out.Stderr != "" {
		req.OnStderr([]byte(out.Stderr))
	}
	res := ExecResult{ExitCode: out.ExitCode, DurationMS: out.DurationMS}
	if res.DurationMS == 0 {
		res.DurationMS = time.Since(start).Milliseconds()
	}
	res.Stdout, res.StdoutTruncated, res.StdoutDroppedBytes = boundText(out.Stdout, req.MaxOutputBytes)
	res.Stderr, res.StderrTruncated, res.StderrDroppedBytes = boundText(out.Stderr, req.MaxOutputBytes)
	// Buffered exec reports a command killed by its timeout as -1 with no
	// signal name; one that ran the full timeout is reported as a timeout.
	if out.ExitCode == -1 && req.Timeout > 0 && time.Duration(out.DurationMS)*time.Millisecond >= req.Timeout-time.Second {
		res.TimedOut = true
		res.ExitCode = TimeoutExitCode
	}
	return res, nil
}

func timeoutSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}
