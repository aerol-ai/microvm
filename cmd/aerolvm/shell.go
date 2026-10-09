package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// detachKey (Ctrl-]) leaves a shell running and returns to the local
// prompt, as in telnet. In raw mode Ctrl-C belongs to the remote shell, so
// without it a hung connection would hold the terminal until it is closed.
const detachKey = 0x1d

// pickLimit is how many sandboxes the picker offers.
const pickLimit = 20

// runShell is the one interactive verb. Every other verb follows the agent
// contract (§5.2 rule 1: never interactive); shell exists to be typed into,
// so it refuses to run without a terminal and points scripts at exec. Like
// exec, it exits with the remote code and uses 125 for its own failures.
func runShell(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("shell")
	var session string
	var fresh bool
	fs.StringVar(&session, "session", "", "")
	fs.BoolVar(&fresh, "new", false, "")
	pos, rest, err := parseArgs(fs, args)
	if err != nil {
		a.flagError(c, "shell", err)
		return execFailure
	}
	if len(pos) > 1 || len(rest) > 0 {
		a.usageError(c, "shell", "expected at most one sandbox; to run a command, use: aerolvm exec <sandbox> -it -- <command>")
		return execFailure
	}
	if fresh && session != "" {
		a.usageError(c, "shell", "--new and --session contradict each other")
		return execFailure
	}
	if !a.stdinIsTTY || !a.stdoutIsTTY {
		a.usageError(c, "shell", "shell needs a terminal; from a script or an agent, use: aerolvm exec <sandbox> -- <command>")
		return execFailure
	}

	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, execFailure)
	}
	ref := ""
	if len(pos) == 1 {
		ref = pos[0]
	} else if ref, err = a.pickSandbox(ctx, tools); err != nil {
		return a.fail(c, err, execFailure)
	}
	sb, err := tools.Target(ctx, ref)
	if err != nil {
		return a.fail(c, err, execFailure)
	}
	if fresh {
		if session, err = agenttools.NewShellName(); err != nil {
			return a.fail(c, err, execFailure)
		}
	}
	cols, rows, _ := a.term.Size()
	sh, err := tools.OpenShell(ctx, sb, agenttools.ShellRequest{Name: session, Term: a.remoteTerm(), Cols: cols, Rows: rows})
	if err != nil {
		return a.fail(c, err, execFailure)
	}
	return a.attachShell(ctx, c, sb, ref, sh, cols, rows)
}

// attachShell connects the terminal to a shell session until the shell
// exits, the user detaches, or the connection drops. Only an exit ends the
// shell; the other two leave it running for the next `aerolvm shell`.
func (a *app) attachShell(ctx context.Context, c *commonFlags, sb *microvm.Sandbox, ref string, sh agenttools.Shell, cols, rows int) int {
	reopen := "aerolvm shell " + ref
	if sh.Session.Name != agenttools.DefaultShellSession {
		reopen += " --session " + sh.Session.Name
	}
	if sh.Created {
		a.note("aerolvm: new shell in %s. exit or Ctrl-D ends it; Ctrl-] detaches and leaves it running.", ref)
	} else {
		a.note("aerolvm: back in the running shell in %s. Ctrl-] detaches.", ref)
	}

	ctx, received, stop := a.notifySignals(ctx)
	defer stop()
	var outMu sync.Mutex
	write := func(w io.Writer) func([]byte) {
		return func(b []byte) { outMu.Lock(); _, _ = w.Write(b); outMu.Unlock() }
	}
	handle, err := sb.AttachSession(ctx, sh.Session.ID, microvm.SessionAttachOptions{
		OnStdout: write(a.stdout), OnStderr: write(a.stderr), Cols: cols, Rows: rows,
	})
	if err != nil {
		return a.fail(c, err, execFailure)
	}
	restore, err := a.term.MakeRaw()
	if err != nil {
		_ = handle.Close()
		return a.fail(c, err, execFailure)
	}

	detached := make(chan struct{})
	go pumpShellInput(a.stdin, handle.Write, detached)
	go agenttools.ForwardResizes(ctx, a.resizes(ctx), handle.Resize)
	type exit struct {
		code   int
		signal string
		err    error
	}
	done := make(chan exit, 1)
	go func() {
		code, signal, err := handle.Wait()
		done <- exit{code, signal, err}
	}()

	// The terminal is restored before any note: in raw mode a newline
	// doesn't return the carriage. A shell left running was usually cut
	// off mid-prompt, so its note starts on a line of its own.
	left := func(how string) {
		fmt.Fprintln(a.stderr)
		a.note("aerolvm: %s; the shell keeps running. Reopen it with: %s", how, reopen)
	}
	var e exit
	select {
	case e = <-done:
		restore()
	case <-detached:
		_ = handle.Close()
		restore()
		left("detached")
		return exitOK
	case <-ctx.Done():
		_ = handle.Close()
		restore()
		e.err = ctx.Err()
	}
	// A local SIGINT/SIGTERM cancels ctx, which also ends Wait; either
	// branch can see it first.
	if sig := received(); sig != nil {
		left("detached by " + sig.String())
		return signalExit(sig)
	}
	if e.err != nil {
		left("lost the connection (" + agenttools.Classify(e.err).Message + ")")
		return execFailure
	}
	return agenttools.ExitStatus(e.code, e.signal)
}

// pumpShellInput copies keystrokes to the shell until the detach key or the
// end of stdin, then closes detached. A failed send stops it quietly: the
// session stream is ending, and Wait reports why.
func pumpShellInput(in io.Reader, send func([]byte) error, detached chan<- struct{}) {
	buf := make([]byte, 32*1024)
	for {
		n, err := in.Read(buf)
		chunk := buf[:n]
		key := bytes.IndexByte(chunk, detachKey)
		if key >= 0 {
			chunk = chunk[:key]
		}
		if len(chunk) > 0 {
			if werr := send(append([]byte(nil), chunk...)); werr != nil {
				return
			}
		}
		if key >= 0 || err != nil {
			close(detached)
			return
		}
	}
}

// pickSandbox asks which sandbox to open a shell in when none was named.
// The prompt reads one line before the terminal goes raw.
func (a *app) pickSandbox(ctx context.Context, tools *agenttools.Tools) (string, error) {
	items, next, err := tools.Client().ListPage(ctx, "", microvm.WithLimit(pickLimit))
	if err != nil {
		return "", agenttools.Classify(err)
	}
	// A server without paging returns every row; offer the first pickLimit.
	more := next != ""
	var choices []*microvm.Sandbox
	for _, sb := range items {
		if !hasShell(sb) {
			continue
		}
		if len(choices) == pickLimit {
			more = true
			break
		}
		choices = append(choices, sb)
	}
	switch len(choices) {
	case 0:
		return "", &agenttools.Error{
			Code:    agenttools.CodeNotFound,
			Message: "no sandbox to open a shell in",
			Hint:    "create one with: aerolvm create --name dev --image ubuntu:24.04",
		}
	case 1:
		a.note("aerolvm: opening a shell in %s, your only sandbox with a shell", sandboxRef(choices[0]))
		return sandboxRef(choices[0]), nil
	}
	fmt.Fprintln(a.stderr, "Open a shell in which sandbox?")
	tw := tabwriter.NewWriter(a.stderr, 0, 4, 2, ' ', 0)
	for i, sb := range choices {
		fmt.Fprintf(tw, "  %d)\t%s\t%s\t%s\t%s\n", i+1, dash(sb.Name), sb.ID, sb.Status, dash(sb.Image))
	}
	_ = tw.Flush()
	if more {
		a.note("Only the first %d are listed; name a sandbox to open another: aerolvm shell <sandbox>", pickLimit)
	}
	fmt.Fprintf(a.stderr, "Number [1-%d]: ", len(choices))
	line := readLine(a.stdin)
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(choices) {
		return "", &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: fmt.Sprintf("%q is not a number from 1 to %d", strings.TrimSpace(line), len(choices)),
			Hint:    "name the sandbox instead: aerolvm shell <sandbox>",
		}
	}
	return sandboxRef(choices[n-1]), nil
}

// hasShell reports whether sb is one a shell can open in: running or
// stopped (Target starts it), and not a runtime without a shell.
func hasShell(sb *microvm.Sandbox) bool {
	switch sb.Status {
	case models.SandboxStatusStarted, models.SandboxStatusStopped:
	default:
		return false
	}
	return agenttools.RequireShell(sb) == nil && !agenttools.IsWasm(sb)
}

// sandboxRef is how notes and the reopen hint name a sandbox: its name
// when it has one, since that is what people type.
func sandboxRef(sb *microvm.Sandbox) string {
	if sb.Name != "" {
		return sb.Name
	}
	return sb.ID
}

// readLine reads one line a byte at a time, so nothing typed after it is
// buffered away from the shell that reads stdin next.
func readLine(r io.Reader) string {
	var line []byte
	b := make([]byte, 1)
	for len(line) < 256 {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSuffix(string(line), "\r")
}
