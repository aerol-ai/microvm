package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

// miniShell is a remote shell for the fake's live attach: it prompts,
// echoes each line, and ends on "exit N" or "die" (killed by a signal).
// It returns when stdin closes, which is how a detach reaches it.
func miniShell(_ string, in io.Reader, out func(byte, []byte), _ <-chan struct{}) (int, string) {
	out(1, []byte("$ "))
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := sc.Text()
		if n, ok := strings.CutPrefix(line, "exit "); ok {
			code, _ := strconv.Atoi(n)
			return code, ""
		}
		if line == "die" {
			return -1, "killed"
		}
		out(1, []byte(line+"\r\n$ "))
	}
	return 0, ""
}

// shellHarness is a harness on a terminal, with a live fake shell and a
// keyboard the test types into while the verb runs.
func shellHarness(t *testing.T) (*harness, *io.PipeWriter, *int, *int) {
	t.Helper()
	h := newHarness(t)
	h.env["TERM"] = "xterm-kitty"
	h.fake.Observe(func(s *agenttoolstest.Server) {
		s.LiveAttach = true
		s.ExecFunc = miniShell
	})
	raw, restores := 0, 0
	h.app.stdinIsTTY, h.app.stdoutIsTTY = true, true
	h.app.term = fakeTerm{rawCalls: &raw, restores: &restores}
	keys := h.keyboard()
	return h, keys, &raw, &restores
}

// keyboard gives the app a stdin the test types into.
func (h *harness) keyboard() *io.PipeWriter {
	r, w := io.Pipe()
	h.app.stdin = r
	h.t.Cleanup(func() { _ = w.Close() })
	return w
}

// runAsync runs a verb while the test keeps typing.
func (h *harness) runAsync(args ...string) <-chan int {
	h.stdout.Reset()
	h.stderr.Reset()
	done := make(chan int, 1)
	go func() { done <- h.app.run(context.Background(), args) }()
	return done
}

func (h *harness) wait(done <-chan int) int {
	h.t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(3 * time.Second):
		h.t.Fatalf("verb did not finish; stdout %q stderr %q", h.stdout.String(), h.stderr.String())
		return 0
	}
}

func typeKeys(t *testing.T, w io.Writer, keys string) {
	t.Helper()
	go func() { _, _ = io.WriteString(w, keys) }()
}

func (h *harness) sessionCreates() []models.CreateSessionRequest {
	var out []models.CreateSessionRequest
	h.fake.Observe(func(s *agenttoolstest.Server) { out = slices.Clone(s.SessionCreates) })
	return out
}

func TestShellOpensTypesAndExits(t *testing.T) {
	h, keys, raw, restores := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})

	done := h.runAsync("shell", "box")
	typeKeys(t, keys, "echo hi\nexit 3\n")
	if code := h.wait(done); code != 3 {
		t.Fatalf("shell = %d, want the shell's exit code 3; stderr %q", code, h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "$ echo hi\r\n$ ") {
		t.Fatalf("stdout %q", out)
	}
	if !strings.Contains(h.stderr.String(), "new shell in box") || !strings.Contains(h.stderr.String(), "Ctrl-] detaches") {
		t.Fatalf("stderr %q", h.stderr.String())
	}
	if *raw != 1 || *restores != 1 {
		t.Fatalf("raw mode %d, restored %d", *raw, *restores)
	}
	creates := h.sessionCreates()
	// xterm-kitty isn't in a sandbox's terminfo; the shell gets what it emulates.
	if len(creates) != 1 || creates[0].Name != "default" || !creates[0].PTY || creates[0].Cols != 120 || creates[0].Rows != 40 || creates[0].Env["TERM"] != "xterm-256color" {
		t.Fatalf("session create = %+v", creates)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if !slices.Equal(s.Resizes, []string{"120x40"}) {
			t.Fatalf("attach resizes %v, want the terminal size sent on attach", s.Resizes)
		}
	})
}

func TestShellDetachKeepsItRunningAndReopens(t *testing.T) {
	h, keys, _, restores := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})

	done := h.runAsync("shell", "box")
	typeKeys(t, keys, "echo kept\x1dignored after the detach key")
	if code := h.wait(done); code != exitOK {
		t.Fatalf("detach = %d; stderr %q", code, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "detached; the shell keeps running. Reopen it with: aerolvm shell box\n") || *restores != 1 {
		t.Fatalf("detach note %q, restored %d", h.stderr.String(), *restores)
	}
	waitFor(t, func() bool {
		n := 0
		h.fake.Observe(func(s *agenttoolstest.Server) { n = s.Detaches })
		return n == 1
	})

	keys = h.keyboard()
	done = h.runAsync("shell", "box")
	typeKeys(t, keys, "exit 0\n")
	if code := h.wait(done); code != 0 || !strings.Contains(h.stderr.String(), "back in the running shell in box") {
		t.Fatalf("reopen = %d %q", code, h.stderr.String())
	}
	if creates := h.sessionCreates(); len(creates) != 1 {
		t.Fatalf("reopen started another shell: %+v", creates)
	}
}

func TestShellNewAndNamedSessions(t *testing.T) {
	h, keys, _, _ := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})

	done := h.runAsync("shell", "box", "--new")
	typeKeys(t, keys, "\x1d")
	if code := h.wait(done); code != exitOK || !strings.Contains(h.stderr.String(), "aerolvm shell box --session shell-") {
		t.Fatalf("--new = %d %q", code, h.stderr.String())
	}
	keys = h.keyboard()
	done = h.runAsync("shell", "--session", "work", "box")
	typeKeys(t, keys, "exit 0\n")
	if code := h.wait(done); code != 0 {
		t.Fatalf("--session = %d %q", code, h.stderr.String())
	}
	creates := h.sessionCreates()
	if len(creates) != 2 || !strings.HasPrefix(creates[0].Name, "shell-") || creates[1].Name != "work" {
		t.Fatalf("creates = %+v", creates)
	}
}

func TestShellForwardsResizes(t *testing.T) {
	h, keys, _, _ := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	var mu sync.Mutex
	cols, rows := 120, 40
	resized := make(chan struct{}, 1)
	h.app.term = fakeTerm{resized: resized, size: func() (int, int) { mu.Lock(); defer mu.Unlock(); return cols, rows }}

	done := h.runAsync("shell", "box")
	waitFor(t, func() bool { return strings.Contains(h.stdout.String(), "$ ") })
	mu.Lock()
	cols, rows = 90, 25
	mu.Unlock()
	resized <- struct{}{}
	waitFor(t, func() bool {
		var got []string
		h.fake.Observe(func(s *agenttoolstest.Server) { got = slices.Clone(s.Resizes) })
		return slices.Equal(got, []string{"120x40", "90x25"})
	})
	typeKeys(t, keys, "exit 0\n")
	if code := h.wait(done); code != 0 {
		t.Fatalf("shell = %d %q", code, h.stderr.String())
	}
}

func TestShellEndings(t *testing.T) {
	t.Run("killed by a signal", func(t *testing.T) {
		h, keys, _, _ := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "box"})
		done := h.runAsync("shell", "box")
		typeKeys(t, keys, "die\n")
		if code := h.wait(done); code != 137 {
			t.Fatalf("killed shell = %d, want 128+9", code)
		}
	})
	t.Run("connection lost", func(t *testing.T) {
		h, _, _, restores := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "box"})
		h.fake.Observe(func(s *agenttoolstest.Server) { s.DropAttach = true })
		done := h.runAsync("shell", "box")
		if code := h.wait(done); code != execFailure || !strings.Contains(h.stderr.String(), "lost the connection") || !strings.Contains(h.stderr.String(), "Reopen it with: aerolvm shell box") || *restores != 1 {
			t.Fatalf("dropped = %d %q restored %d", code, h.stderr.String(), *restores)
		}
	})
	t.Run("local signal detaches", func(t *testing.T) {
		h, _, _, restores := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "box"})
		done := h.runAsync("shell", "box")
		waitFor(t, func() bool { return strings.Contains(h.stdout.String(), "$ ") })
		h.interrupt <- syscall.SIGTERM
		if code := h.wait(done); code != 128+int(syscall.SIGTERM) || !strings.Contains(h.stderr.String(), "detached by terminated") || *restores != 1 {
			t.Fatalf("SIGTERM = %d %q restored %d", code, h.stderr.String(), *restores)
		}
	})
	t.Run("stdin ends", func(t *testing.T) {
		h, keys, _, _ := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "box"})
		done := h.runAsync("shell", "box")
		_ = keys.Close()
		if code := h.wait(done); code != exitOK || !strings.Contains(h.stderr.String(), "detached") {
			t.Fatalf("stdin EOF = %d %q", code, h.stderr.String())
		}
	})
}

func TestShellUsageAndFailures(t *testing.T) {
	h, _, _, _ := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
	h.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})

	for _, tc := range []struct {
		name   string
		args   []string
		setup  func()
		stderr string
	}{
		{"two sandboxes", []string{"shell", "box", "other"}, nil, "expected at most one sandbox"},
		{"a command", []string{"shell", "box", "--", "ls"}, nil, "aerolvm exec <sandbox> -it --"},
		{"both session flags", []string{"shell", "box", "--new", "--session", "x"}, nil, "contradict"},
		{"bad flag", []string{"shell", "box", "--nope"}, nil, "nope"},
		{"stdin not a terminal", []string{"shell", "box"}, func() { h.app.stdinIsTTY = false }, "shell needs a terminal"},
		{"stdout not a terminal", []string{"shell", "box"}, func() { h.app.stdoutIsTTY = false }, "use: aerolvm exec <sandbox> --"},
		{"no token", []string{"shell", "box"}, func() { delete(h.env, "SB_PAT_TOKEN") }, "SB_PAT_TOKEN"},
		{"unknown sandbox", []string{"shell", "nope"}, nil, `sandbox "nope" not found`},
		{"wasm", []string{"shell", "wasm"}, nil, "WASM sandboxes have no interactive shell"},
		{"isolate", []string{"shell", "iso"}, nil, "isolate sandboxes have no shell"},
		{"raw mode refused", []string{"shell", "box"}, func() { h.app.term = errTerm{} }, "raw mode"},
		{"sessions fail", []string{"shell", "box"}, func() { h.fake.Observe(func(s *agenttoolstest.Server) { s.FailSessions = true }) }, "sessions failed"},
		{"attach fails", []string{"shell", "box"}, func() { h.fake.Observe(func(s *agenttoolstest.Server) { s.FailAttach = true }) }, "session attach"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.app.stdinIsTTY, h.app.stdoutIsTTY, h.app.term = true, true, fakeTerm{}
			h.env["SB_PAT_TOKEN"] = agenttoolstest.Token
			h.fake.Observe(func(s *agenttoolstest.Server) { s.FailSessions, s.FailAttach = false, false })
			if tc.setup != nil {
				tc.setup()
			}
			if code := h.run(tc.args...); code != execFailure || !strings.Contains(h.stderr.String(), tc.stderr) {
				t.Fatalf("%v = %d, stderr %q; want 125 and %q", tc.args, code, h.stderr.String(), tc.stderr)
			}
		})
	}
}

func TestShellStartsAStoppedSandbox(t *testing.T) {
	h, keys, _, _ := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box", Status: models.SandboxStatusStopped})
	done := h.runAsync("shell", "box")
	typeKeys(t, keys, "exit 0\n")
	if code := h.wait(done); code != 0 {
		t.Fatalf("shell = %d %q", code, h.stderr.String())
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if s.StartCalls != 1 {
			t.Fatalf("start calls = %d", s.StartCalls)
		}
	})
}

func TestShellPicker(t *testing.T) {
	t.Run("nothing to open", func(t *testing.T) {
		h, _, _, _ := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
		h.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
		h.fake.AddSandbox(models.Sandbox{Name: "broken", Status: models.SandboxStatusError})
		if code := h.run("shell"); code != execFailure || !strings.Contains(h.stderr.String(), "no sandbox to open a shell in") || !strings.Contains(h.stderr.String(), "aerolvm create") {
			t.Fatalf("empty picker = %d %q", code, h.stderr.String())
		}
	})
	t.Run("the only one is used", func(t *testing.T) {
		h, keys, _, _ := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
		h.fake.AddSandbox(models.Sandbox{})
		done := h.runAsync("shell")
		typeKeys(t, keys, "exit 0\n")
		if code := h.wait(done); code != 0 || !strings.Contains(h.stderr.String(), "opening a shell in sb-") {
			t.Fatalf("one sandbox = %d %q", code, h.stderr.String())
		}
	})
	t.Run("asks for a number", func(t *testing.T) {
		h, keys, _, _ := shellHarness(t)
		h.fake.AddSandbox(models.Sandbox{Name: "api", Image: "node:22"})
		h.fake.AddSandbox(models.Sandbox{Name: "db", Status: models.SandboxStatusStopped})
		done := h.runAsync("shell")
		typeKeys(t, keys, " 2 \r\nexit 4\n")
		if code := h.wait(done); code != 4 {
			t.Fatalf("picked = %d %q", code, h.stderr.String())
		}
		stderr := h.stderr.String()
		if !strings.Contains(stderr, "Open a shell in which sandbox?") || !strings.Contains(stderr, "1)  api") || !strings.Contains(stderr, "node:22") || !strings.Contains(stderr, "2)  db") || !strings.Contains(stderr, "Number [1-2]: ") || !strings.Contains(stderr, "new shell in db") {
			t.Fatalf("picker stderr %q", stderr)
		}
	})
	t.Run("a bad answer", func(t *testing.T) {
		for _, answer := range []string{"9\n", "x\n", ""} {
			h, keys, _, _ := shellHarness(t)
			h.fake.AddSandbox(models.Sandbox{Name: "a"})
			h.fake.AddSandbox(models.Sandbox{Name: "b"})
			done := h.runAsync("shell")
			if answer == "" {
				_ = keys.Close()
			} else {
				typeKeys(t, keys, answer)
			}
			if code := h.wait(done); code != execFailure || !strings.Contains(h.stderr.String(), "is not a number from 1 to 2") || !strings.Contains(h.stderr.String(), "aerolvm shell <sandbox>") {
				t.Fatalf("answer %q = %d %q", answer, code, h.stderr.String())
			}
		}
	})
	t.Run("more than fit", func(t *testing.T) {
		h, keys, _, _ := shellHarness(t)
		h.fake.Observe(func(s *agenttoolstest.Server) { s.IgnoreLimit = true })
		for i := range pickLimit + 2 {
			h.fake.AddSandbox(models.Sandbox{Name: fmt.Sprintf("box-%02d", i)})
		}
		done := h.runAsync("shell")
		typeKeys(t, keys, "1\nexit 0\n")
		if code := h.wait(done); code != 0 || !strings.Contains(h.stderr.String(), "Only the first 20 are listed") || strings.Contains(h.stderr.String(), "21)") {
			t.Fatalf("long list = %d %q", code, h.stderr.String())
		}
	})
	t.Run("list fails", func(t *testing.T) {
		h, _, _, _ := shellHarness(t)
		h.env["SB_API_URL"] = "http://127.0.0.1:1"
		if code := h.run("shell"); code != execFailure {
			t.Fatalf("unreachable = %d %q", code, h.stderr.String())
		}
	})
}

func TestPumpShellInputAndReadLine(t *testing.T) {
	var sent []string
	detached := make(chan struct{})
	pumpShellInput(strings.NewReader("ls\x1drm -rf /"), func(b []byte) error { sent = append(sent, string(b)); return nil }, detached)
	if _, open := <-detached; open || !slices.Equal(sent, []string{"ls"}) {
		t.Fatalf("sent %q, want only what came before the detach key", sent)
	}

	// A failed send means the stream is ending: stop without detaching,
	// so the caller reports the stream's end instead.
	detached = make(chan struct{})
	pumpShellInput(strings.NewReader("ls"), func([]byte) error { return errors.New("closed") }, detached)
	select {
	case <-detached:
		t.Fatal("a failed send detached")
	default:
	}

	for _, tc := range []struct{ in, want string }{
		{"3\r\nrest", "3"},
		{"no newline", "no newline"},
		{"", ""},
		{strings.Repeat("9", 300), strings.Repeat("9", 256)},
	} {
		if got := readLine(strings.NewReader(tc.in)); got != tc.want {
			t.Errorf("readLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// It reads no further than the line, leaving the rest for the shell.
	r := strings.NewReader("1\nexit\n")
	_ = readLine(r)
	if rest, _ := io.ReadAll(r); string(rest) != "exit\n" {
		t.Fatalf("readLine over-read; left %q", rest)
	}
}

func TestRemoteTerm(t *testing.T) {
	for _, tc := range []struct{ local, want string }{
		{"", "xterm-256color"},
		{"xterm-kitty", "xterm-256color"},
		{"xterm-ghostty", "xterm-256color"},
		{"alacritty", "xterm-256color"},
		{"xterm-256color", "xterm-256color"},
		{"screen-256color", "screen-256color"},
		{"tmux-256color", "tmux-256color"},
		{" vt100 ", "vt100"},
		{"dumb", "dumb"},
	} {
		a := &app{getenv: func(string) string { return tc.local }}
		if got := a.remoteTerm(); got != tc.want {
			t.Errorf("TERM=%q: remoteTerm = %q, want %q", tc.local, got, tc.want)
		}
	}
}

// waitFor polls cond until it holds, failing the test after two seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestResizesSkipsUnknownAndKeepsTheLatest(t *testing.T) {
	// Each change reads the size once, in order: unknown, 80x24, 100x30,
	// then unknown again as a fence. changes is unbuffered, so the fence's
	// send returns only after the watcher finished with 100x30, and an
	// unknown size leaves the queue alone.
	var mu sync.Mutex
	script := [][2]int{{0, 0}, {80, 24}, {100, 30}, {0, 0}}
	changes := make(chan struct{})
	a := &app{term: fakeTerm{resized: changes, size: func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		next := script[0]
		script = script[1:]
		return next[0], next[1]
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sizes := a.resizes(ctx)
	for range 4 {
		changes <- struct{}{}
	}
	select {
	case got := <-sizes:
		if got != (agenttools.TermSize{Cols: 100, Rows: 30}) {
			t.Fatalf("got %+v, want only the latest size", got)
		}
	default:
		t.Fatal("no size reported")
	}
	select {
	case got := <-sizes:
		t.Fatalf("a stale size was queued: %+v", got)
	default:
	}
}
