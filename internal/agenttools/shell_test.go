package agenttools

import (
	"context"
	"io"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestOpenShellCreatesThenReuses(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box", Runtime: models.RuntimeDocker})
	sb := resolveTarget(t, tools, "box")

	first, err := tools.OpenShell(ctx, sb, ShellRequest{Term: "xterm-256color", Cols: 100, Rows: 30})
	if err != nil || !first.Created || first.Session.Name != DefaultShellSession || !first.Session.PTY {
		t.Fatalf("first open = (%+v, %v)", first, err)
	}
	var creates []models.CreateSessionRequest
	fake.Observe(func(s *agenttoolstest.Server) { creates = slices.Clone(s.SessionCreates) })
	want := models.CreateSessionRequest{Name: "default", PTY: true, Cols: 100, Rows: 30, Env: map[string]string{"TERM": "xterm-256color"}}
	if len(creates) != 1 || creates[0].Name != want.Name || !creates[0].PTY || creates[0].Cols != 100 || creates[0].Rows != 30 || creates[0].Env["TERM"] != "xterm-256color" || creates[0].Command != "" {
		t.Fatalf("create = %+v, want %+v (a login shell: no command)", creates, want)
	}

	// The shell outlives the call: opening it again lands in it.
	again, err := tools.OpenShell(ctx, sb, ShellRequest{Term: "vt100"})
	if err != nil || again.Created || again.Session.ID != first.Session.ID {
		t.Fatalf("second open = (%+v, %v), want reuse of %s", again, err, first.Session.ID)
	}
	fake.Observe(func(s *agenttoolstest.Server) { creates = slices.Clone(s.SessionCreates) })
	if len(creates) != 1 {
		t.Fatalf("reopen created a session: %+v", creates)
	}

	// A named shell is its own session, and no TERM means no env.
	named, err := tools.OpenShell(ctx, sb, ShellRequest{Name: " work "})
	if err != nil || !named.Created || named.Session.Name != "work" {
		t.Fatalf("named open = (%+v, %v)", named, err)
	}
	fake.Observe(func(s *agenttoolstest.Server) { creates = slices.Clone(s.SessionCreates) })
	if len(creates) != 2 || creates[1].Env != nil {
		t.Fatalf("named create = %+v", creates)
	}
}

func TestOpenShellPicksNewestRunningShell(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	row := fake.AddSandbox(models.Sandbox{Name: "box"})
	at := func(sec int) time.Time { return time.Date(2026, 10, 9, 9, 0, sec, 0, time.UTC) }
	for _, s := range []models.Session{
		{ID: "old", Name: "default", PTY: true, Status: models.SessionStatusRunning, CreatedAt: at(1)},
		{ID: "newest", Name: "default", PTY: true, Status: models.SessionStatusRunning, CreatedAt: at(3)},
		{ID: "mid", Name: "default", PTY: true, Status: models.SessionStatusRunning, CreatedAt: at(2)},
		// Not shells to land in: ended, no PTY, or another name.
		{ID: "exited", Name: "default", PTY: true, Status: models.SessionStatusExited, CreatedAt: at(9)},
		{ID: "pipes", Name: "default", PTY: false, Status: models.SessionStatusRunning, CreatedAt: at(9)},
		{ID: "other", Name: "work", PTY: true, Status: models.SessionStatusRunning, CreatedAt: at(9)},
	} {
		fake.AddSession(row.ID, s)
	}
	sb := resolveTarget(t, tools, "box")
	sh, err := tools.OpenShell(ctx, sb, ShellRequest{})
	if err != nil || sh.Created || sh.Session.ID != "newest" {
		t.Fatalf("open = (%+v, %v), want the newest running default shell", sh, err)
	}

	// Only ended or pipe sessions with the name: a new shell is started.
	tools2, fake2, _ := newTestTools(t, SourceCLI)
	row2 := fake2.AddSandbox(models.Sandbox{Name: "box"})
	fake2.AddSession(row2.ID, models.Session{ID: "exited", Name: "default", PTY: true, Status: models.SessionStatusExited})
	fake2.AddSession(row2.ID, models.Session{ID: "pipes", Name: "default", Status: models.SessionStatusRunning})
	sh, err = tools2.OpenShell(ctx, resolveTarget(t, tools2, "box"), ShellRequest{})
	if err != nil || !sh.Created || sh.Session.ID == "exited" || sh.Session.ID == "pipes" {
		t.Fatalf("open past ended shells = (%+v, %v)", sh, err)
	}
}

func TestOpenShellRefusals(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
	fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	fake.AddSandbox(models.Sandbox{Name: "box"})
	for _, tc := range []struct {
		ref, code string
	}{
		{"wasm", CodeUnsupportedRuntime},
		{"iso", CodeUnsupportedRuntime},
	} {
		sb, err := tools.Resolve(ctx, tc.ref)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tools.OpenShell(ctx, sb, ShellRequest{}); !IsCode(err, tc.code) {
			t.Errorf("%s: err = %v, want %s", tc.ref, err, tc.code)
		}
	}
	if got := requestsMatching(fake, "GET /v1/sandboxes/"); slices.ContainsFunc(got, func(r string) bool { return regexp.MustCompile(`/sessions$`).MatchString(r) }) {
		t.Fatalf("a refused shell still listed sessions: %v", got)
	}

	fake.Observe(func(s *agenttoolstest.Server) { s.FailSessions = true })
	if _, err := tools.OpenShell(ctx, resolveTarget(t, tools, "box"), ShellRequest{}); err == nil || IsCode(err, CodeUnsupportedRuntime) {
		t.Fatalf("failing sessions = %v", err)
	}
}

func TestNewShellNameAndExitStatus(t *testing.T) {
	a, err := NewShellName()
	if err != nil || !regexp.MustCompile(`^shell-[0-9a-f]{8}$`).MatchString(a) {
		t.Fatalf("NewShellName = %q, %v", a, err)
	}
	if b, _ := NewShellName(); b == a {
		t.Fatalf("two shell names collided: %q", a)
	}
	for _, tc := range []struct {
		code   int
		signal string
		want   int
	}{
		{0, "", 0},
		{3, "", 3},
		{-1, "killed", 137},
		{-1, "SIGHUP", 129},
		{7, "no such signal", 7},
	} {
		if got := ExitStatus(tc.code, tc.signal); got != tc.want {
			t.Errorf("ExitStatus(%d, %q) = %d, want %d", tc.code, tc.signal, got, tc.want)
		}
	}
}

func TestForwardResizes(t *testing.T) {
	var got []TermSize
	resize := func(cols, rows int) error {
		got = append(got, TermSize{cols, rows})
		return io.ErrClosedPipe // a send failure is dropped, not fatal
	}
	sizes := make(chan TermSize, 3)
	sizes <- TermSize{100, 30}
	sizes <- TermSize{0, 30} // an unknown size is skipped
	sizes <- TermSize{80, 24}
	close(sizes)
	ForwardResizes(context.Background(), sizes, resize)
	if !slices.Equal(got, []TermSize{{100, 30}, {80, 24}}) {
		t.Fatalf("forwarded %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ForwardResizes(ctx, make(chan TermSize), resize) // returns on a done ctx
}

func TestExecTTYForwardsResizes(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")

	stdinR, stdinW := io.Pipe()
	sizes := make(chan TermSize, 1)
	done := make(chan error, 1)
	go func() {
		_, err := tools.Exec(ctx, sb, ExecRequest{Command: "cat", TTY: true, Cols: 120, Rows: 40, Stdin: stdinR, Resize: sizes, Env: map[string]string{"TERM": "vt100"}})
		done <- err
	}()
	sizes <- TermSize{90, 20}
	waitFor(t, func() bool {
		var n int
		fake.Observe(func(s *agenttoolstest.Server) { n = len(s.Resizes) })
		return n == 1
	})
	_ = stdinW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if !slices.Equal(s.Resizes, []string{"90x20"}) || !s.LastExecStart.TTY || s.LastExecStart.Cols != 120 || s.LastExecStart.Env["TERM"] != "vt100" {
			t.Fatalf("resizes %v, start %+v", s.Resizes, s.LastExecStart)
		}
	})
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
