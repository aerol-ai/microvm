package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

func runExec(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("exec")
	var (
		cwd                       string
		timeout                   time.Duration
		interactive, tty, noStdin bool
		background                bool
		maxOutput                 int
	)
	env := kvList{}
	fs.StringVar(&cwd, "cwd", "", "")
	fs.Var(env, "env", "")
	fs.DurationVar(&timeout, "timeout", 0, "")
	fs.BoolVar(&interactive, "i", false, "")
	fs.BoolVar(&tty, "t", false, "")
	fs.BoolVar(&noStdin, "no-stdin", false, "")
	fs.BoolVar(&background, "background", false, "")
	fs.IntVar(&maxOutput, "max-output-bytes", agenttools.DefaultMaxOutputBytes, "")
	pos, rest, err := parseArgs(fs, args)
	if err != nil {
		a.flagError(c, "exec", err)
		return execFailure
	}
	if len(pos) == 0 {
		a.usageError(c, "exec", "expected <sandbox> -- <command>")
		return execFailure
	}
	words := append(pos[1:], rest...)
	if len(words) == 0 {
		a.usageError(c, "exec", "no command given after --")
		return execFailure
	}
	command := shellCommand(words)
	if interactive && noStdin {
		a.usageError(c, "exec", "-i and --no-stdin contradict each other")
		return execFailure
	}
	if tty && !a.stdoutIsTTY {
		a.usageError(c, "exec", "-t needs a terminal on stdout; drop -t when output is piped or captured")
		return execFailure
	}
	if timeout < 0 {
		a.usageError(c, "exec", "--timeout must be positive")
		return execFailure
	}

	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, execFailure)
	}
	sb, err := tools.Target(ctx, pos[0])
	if err != nil {
		return a.fail(c, err, execFailure)
	}

	if background {
		proc, err := tools.StartProcess(ctx, sb, command, cwd, env.orNil())
		if err != nil {
			return a.fail(c, err, execFailure)
		}
		if c.json {
			a.printJSON(proc)
		} else {
			fmt.Fprintln(a.stdout, proc.SessionID)
			a.note("started in the background; follow it with: aerolvm logs %s %s --follow", pos[0], proc.SessionID)
		}
		return exitOK
	}

	// Stdin (eng review D19): forwarded automatically when it isn't a
	// terminal, so `echo x | aerolvm exec sb -- cat` works with no flag;
	// -i forces it on a terminal. WASM has only buffered exec, so the
	// automatic forward is skipped there and an explicit -i is refused by
	// agenttools (D10).
	forward := interactive || (!a.stdinIsTTY && !noStdin && !agenttools.IsWasm(sb))
	req := agenttools.ExecRequest{
		Command:        command,
		Cwd:            cwd,
		Env:            env.orNil(),
		Timeout:        timeout,
		TTY:            tty,
		MaxOutputBytes: maxOutput,
	}
	if forward {
		req.Stdin = a.stdin
	}
	if !c.json {
		var outMu sync.Mutex
		req.OnStdout = func(b []byte) { outMu.Lock(); _, _ = a.stdout.Write(b); outMu.Unlock() }
		req.OnStderr = func(b []byte) { outMu.Lock(); _, _ = a.stderr.Write(b); outMu.Unlock() }
	}
	if tty {
		if cols, rows, ok := a.term.Size(); ok {
			req.Cols, req.Rows = cols, rows
		}
		if forward {
			restore, err := a.term.MakeRaw()
			if err != nil {
				return a.fail(c, err, execFailure)
			}
			defer restore()
		}
	}

	// SIGINT/SIGTERM cancel the exec; agenttools then sends KILL before it
	// closes the stream (§5.5). In a raw terminal Ctrl-C is a byte for the
	// remote PTY instead.
	execCtx, received, stop := a.notifySignals(ctx)
	defer stop()
	res, err := tools.Exec(execCtx, sb, req)
	if err != nil {
		if sig := received(); sig != nil {
			a.note("aerolvm: interrupted by %s; the remote command was killed", sig)
			return signalExit(sig)
		}
		return a.fail(c, err, execFailure)
	}
	if c.json {
		a.printJSON(res)
	}
	if res.TimedOut {
		a.note("aerolvm: command killed after --timeout %s", timeout)
	}
	if res.ExitCode < 0 || res.ExitCode > 255 {
		a.note("aerolvm: the remote command ended without an exit status (code %d)", res.ExitCode)
		return execFailure
	}
	return res.ExitCode
}

// shellCommand turns the words after "--" into the command line the
// toolbox runs with /bin/sh -c. A single word is used as written, so shell
// syntax works ("make 2>&1 | tail"); several words are quoted and joined,
// so `-- echo "a b"` prints "a b" like `docker exec` would.
func shellCommand(words []string) string {
	if len(words) == 1 {
		return words[0]
	}
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = shellQuote(w)
	}
	return strings.Join(quoted, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func runLogs(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("logs")
	var follow bool
	fs.BoolVar(&follow, "follow", false, "")
	fs.BoolVar(&follow, "f", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "logs", err)
	}
	if len(pos) != 2 {
		return a.usageError(c, "logs", "expected <sandbox> <session-id>")
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	sb, err := tools.Target(ctx, pos[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if !follow {
		if c.json {
			logs, err := tools.ProcessLogs(ctx, sb, pos[1], 0)
			if err != nil {
				return a.fail(c, err, exitError)
			}
			a.printJSON(logs)
			return exitOK
		}
		raw, err := sb.SessionLog(ctx, pos[1])
		if err != nil {
			return a.fail(c, agenttools.Classify(err), exitError)
		}
		_, _ = a.stdout.Write(raw)
		return exitOK
	}
	return a.followLogs(ctx, c, sb, pos[1])
}

// followLogs attaches to a session and streams it until the command exits
// or the user detaches. Detaching leaves the command running.
func (a *app) followLogs(ctx context.Context, c *commonFlags, sb *microvm.Sandbox, sessionID string) int {
	ctx, received, stop := a.notifySignals(ctx)
	defer stop()
	var outMu sync.Mutex
	write := func(w io.Writer) func([]byte) {
		return func(b []byte) { outMu.Lock(); _, _ = w.Write(b); outMu.Unlock() }
	}
	handle, err := sb.AttachSession(ctx, sessionID, microvm.SessionAttachOptions{OnStdout: write(a.stdout), OnStderr: write(a.stderr)})
	if err != nil {
		return a.fail(c, err, exitError)
	}
	done := make(chan struct{})
	var code int
	var signal string
	var waitErr error
	go func() {
		code, signal, waitErr = handle.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		_ = handle.Close()
		<-done
		if sig := received(); sig != nil {
			a.note("aerolvm: detached; the command keeps running")
			return exitOK
		}
	}
	if waitErr != nil {
		return a.fail(c, waitErr, exitError)
	}
	if signal != "" {
		a.note("aerolvm: the command exited by signal %s", signal)
	} else {
		a.note("aerolvm: the command exited with code %d", code)
	}
	return exitOK
}
