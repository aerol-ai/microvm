package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

type harness struct {
	t      *testing.T
	app    *app
	fake   *agenttoolstest.Server
	stdout *syncBuffer
	stderr *syncBuffer
	env    map[string]string
	// interrupt delivers a fake SIGINT/SIGTERM to a running verb.
	interrupt chan os.Signal
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

// fakeTerm is a 120x40 terminal. size overrides that; resized delivers
// resize notifications; rawCalls and restores count raw-mode switches;
// secret answers a hidden prompt.
type fakeTerm struct {
	rawCalls *int
	restores *int
	size     func() (int, int)
	resized  chan struct{}
	secret   func() (string, error)
}

func (f fakeTerm) Size() (int, int, bool) {
	if f.size != nil {
		cols, rows := f.size()
		return cols, rows, cols > 0
	}
	return 120, 40, true
}

func (f fakeTerm) MakeRaw() (func(), error) {
	if f.rawCalls != nil {
		*f.rawCalls++
	}
	return func() {
		if f.restores != nil {
			*f.restores++
		}
	}, nil
}

func (f fakeTerm) NotifyResize() (<-chan struct{}, func()) { return f.resized, func() {} }

func (f fakeTerm) ReadSecret() (string, error) {
	if f.secret == nil {
		return "", errors.New("no secret scripted")
	}
	return f.secret()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := agenttoolstest.New(t)
	h := &harness{
		t: t, fake: fake, stdout: &syncBuffer{}, stderr: &syncBuffer{},
		env:       map[string]string{"SB_API_URL": fake.URL, "SB_PAT_TOKEN": agenttoolstest.Token},
		interrupt: make(chan os.Signal, 1),
	}
	h.app = &app{
		stdin:       strings.NewReader(""),
		stdout:      h.stdout,
		stderr:      h.stderr,
		getenv:      func(k string) string { return h.env[k] },
		stdinIsTTY:  true,
		stdoutIsTTY: false,
		term:        fakeTerm{},
		newTools:    agenttools.New,
	}
	h.app.notifySignals = func(ctx context.Context) (context.Context, func() os.Signal, func()) {
		ctx, cancel := context.WithCancel(ctx)
		var got os.Signal
		var mu sync.Mutex
		done := make(chan struct{})
		go func() {
			select {
			case sig := <-h.interrupt:
				mu.Lock()
				got = sig
				mu.Unlock()
				cancel()
			case <-done:
			}
		}()
		return ctx, func() os.Signal { mu.Lock(); defer mu.Unlock(); return got }, func() { close(done); cancel() }
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	return h.app.run(context.Background(), args)
}

func (h *harness) jsonOut(v any) {
	h.t.Helper()
	if err := json.Unmarshal([]byte(h.stdout.String()), v); err != nil {
		h.t.Fatalf("stdout is not JSON: %v\n%s", err, h.stdout.String())
	}
}

func (h *harness) errorEnvelope() agenttools.Error {
	h.t.Helper()
	var env struct {
		Error agenttools.Error `json:"error"`
	}
	if err := json.Unmarshal([]byte(h.stderr.String()), &env); err != nil {
		h.t.Fatalf("stderr is not an error envelope: %v\n%s", err, h.stderr.String())
	}
	return env.Error
}

func TestHelpAndUsage(t *testing.T) {
	h := newHarness(t)
	if code := h.run(); code != exitUsage || !strings.Contains(h.stderr.String(), "Work in a sandbox:") || h.stdout.String() != "" {
		t.Fatalf("no args = %d, stderr %q", code, h.stderr.String())
	}
	if code := h.run("--help"); code != exitOK || !strings.Contains(h.stdout.String(), "exec") {
		t.Fatalf("--help = %d", code)
	}
	if code := h.run("help", "exec"); code != exitOK || !strings.Contains(h.stdout.String(), "--no-stdin") {
		t.Fatalf("help exec = %d", code)
	}
	if code := h.run("help", "nope"); code != exitOK || !strings.Contains(h.stdout.String(), "Work in a sandbox:") {
		t.Fatalf("help nope = %d", code)
	}
	if code := h.run("bogus"); code != exitUsage || !strings.Contains(h.stderr.String(), `unknown command "bogus"`) {
		t.Fatalf("unknown command = %d", code)
	}
	for _, v := range h.app.verbs() {
		if code := h.run(v.name, "--help"); code != exitOK || h.stdout.String() != v.help || !strings.Contains(v.help, "Usage: aerolvm "+v.name) {
			t.Fatalf("%s --help = %d %q", v.name, code, h.stdout.String())
		}
	}
	// --help after -- belongs to the remote command.
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	if code := h.run("exec", "box", "--", "echo", "--help"); code != 0 || h.stdout.String() != "--help\n" {
		t.Fatalf("exec -- echo --help = %d %q", code, h.stdout.String())
	}
	if code := h.run("--version"); code != exitOK || strings.TrimSpace(h.stdout.String()) != versionString() {
		t.Fatalf("--version = %d %q", code, h.stdout.String())
	}
	if code := h.run("get", "--nope"); code != exitUsage || !strings.Contains(h.stderr.String(), "-nope") {
		t.Fatalf("bad flag = %d %q", code, h.stderr.String())
	}
	if code := h.run("get", "--json", "a", "b"); code != exitUsage || h.errorEnvelope().Code != "usage" {
		t.Fatalf("usage with --json = %d", code)
	}
}

// TestJSONContract pins §5.2 rules 2-4: stdout is the wire type (plus a
// few CLI fields), errors are an envelope on stderr, stdout stays empty on
// failure.
func TestJSONContract(t *testing.T) {
	h := newHarness(t)
	if code := h.run("create", "--name", "agent", "--image", "alpine", "--tag", "team=x", "--env", "A=1", "--destroy-if-idle", "2h", "--stop-if-idle", "30m", "--cpu", "1", "--memory-mb", "512", "--block-network", "--json"); code != exitOK {
		t.Fatalf("create = %d %s", code, h.stderr.String())
	}
	var created map[string]any
	h.jsonOut(&created)
	if created["created"] != true || created["name"] != "agent" || created["id"] == "" {
		t.Fatalf("create JSON = %v", created)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		lc := s.LastCreate
		if lc.Tags["team"] != "x" || lc.Tags[agenttools.CreatedByTag] != "cli" || lc.Lifecycle.DestroyIfIdleFor != 2*time.Hour || !lc.NetworkBlockAll || lc.Env["A"] != "1" {
			t.Fatalf("create request = %+v", lc)
		}
	})
	if code := h.run("create", "--name", "agent", "--json"); code != exitOK {
		t.Fatal(code)
	}
	h.jsonOut(&created)
	if created["created"] != false {
		t.Fatalf("repeat create = %v", created)
	}

	if code := h.run("get", "agent", "--json"); code != exitOK {
		t.Fatal(code)
	}
	var sb models.Sandbox
	h.jsonOut(&sb)
	if sb.Name != "agent" {
		t.Fatalf("get JSON = %+v", sb)
	}

	if code := h.run("list", "--json", "--limit", "1"); code != exitOK {
		t.Fatal(code)
	}
	var list struct {
		Sandboxes     []models.Sandbox `json:"sandboxes"`
		NextPageToken string           `json:"next_page_token"`
	}
	h.jsonOut(&list)
	if len(list.Sandboxes) != 1 {
		t.Fatalf("list JSON = %+v", list)
	}

	if code := h.run("get", "missing", "--json"); code != exitError {
		t.Fatalf("missing = %d", code)
	}
	if h.stdout.String() != "" {
		t.Fatalf("stdout must stay empty on error: %q", h.stdout.String())
	}
	if e := h.errorEnvelope(); e.Code != agenttools.CodeNotFound || e.HTTPStatus != 404 || e.Retryable {
		t.Fatalf("error envelope = %+v", e)
	}
	// AEROLVM_OUTPUT=json makes JSON the default.
	h.env["AEROLVM_OUTPUT"] = "json"
	if code := h.run("version"); code != exitOK || !strings.Contains(h.stdout.String(), `"version"`) {
		t.Fatalf("AEROLVM_OUTPUT=json version = %q", h.stdout.String())
	}
}

func TestTextOutputAndNoANSI(t *testing.T) {
	h := newHarness(t)
	if code := h.run("create", "--name", "agent", "--image", "alpine"); code != exitOK || !strings.HasPrefix(h.stdout.String(), "sb-") || !strings.Contains(h.stderr.String(), "created sandbox agent") {
		t.Fatalf("create text = %q / %q", h.stdout.String(), h.stderr.String())
	}
	if code := h.run("create", "--name", "agent"); code != exitOK || !strings.Contains(h.stderr.String(), "using existing") {
		t.Fatal("repeat create text")
	}
	for _, args := range [][]string{
		{"list"}, {"get", "agent"}, {"health"}, {"version"}, {"get", "missing"}, {"exec", "agent", "--", "echo hi"},
	} {
		h.run(args...)
		for _, out := range []string{h.stdout.String(), h.stderr.String()} {
			if strings.Contains(out, "\x1b[") {
				t.Fatalf("%v printed ANSI escapes: %q", args, out)
			}
		}
	}
	if code := h.run("list"); code != exitOK || !strings.Contains(h.stdout.String(), "ID") || !strings.Contains(h.stdout.String(), "agent") {
		t.Fatalf("list text = %q", h.stdout.String())
	}
	if code := h.run("get", "missing"); code != exitError || !strings.Contains(h.stderr.String(), `aerolvm: sandbox "missing" not found`) {
		t.Fatalf("text error = %q", h.stderr.String())
	}
	if code := h.run("health"); code != exitOK || !strings.HasPrefix(h.stdout.String(), "ok") {
		t.Fatalf("health = %q", h.stdout.String())
	}
}

// TestExecExitCodes pins §5.2 rule 5.
func TestExecExitCodes(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	tests := []struct {
		args   []string
		code   int
		stdout string
	}{
		{[]string{"exec", "box", "--", "echo hello"}, 0, "hello\n"},
		{[]string{"exec", "box", "--", "exit 3"}, 3, ""},
		{[]string{"exec", "box", "--", "signal terminated"}, 143, ""},
		{[]string{"exec", "box", "--timeout", "100ms", "--", "sleep"}, 124, ""},
		{[]string{"exec", "missing", "--", "echo"}, execFailure, ""},
		{[]string{"exec", "box"}, execFailure, ""},
		{[]string{"exec"}, execFailure, ""},
		{[]string{"exec", "box", "--bad", "--", "x"}, execFailure, ""},
		{[]string{"exec", "box", "-i", "--no-stdin", "--", "x"}, execFailure, ""},
		{[]string{"exec", "box", "--timeout", "-1s", "--", "x"}, execFailure, ""},
		{[]string{"exec", "box", "--", "signal mystery"}, execFailure, ""},
	}
	for _, tt := range tests {
		if code := h.run(tt.args...); code != tt.code || h.stdout.String() != tt.stdout {
			t.Fatalf("%v = %d %q (stderr %q), want %d %q", tt.args, code, h.stdout.String(), h.stderr.String(), tt.code, tt.stdout)
		}
	}
	// Several words are quoted for /bin/sh -c (the fake isn't a shell, so
	// check the command line it received).
	if code := h.run("exec", "box", "--", "echo", "a b"); code != 0 {
		t.Fatal(code)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if last := s.ExecCommands[len(s.ExecCommands)-1]; last != "echo 'a b'" {
			t.Fatalf("command line = %q", last)
		}
	})
	// --json prints the result and still exits with the remote code.
	if code := h.run("exec", "box", "--json", "--", "exit 4"); code != 4 {
		t.Fatalf("exec --json exit = %d", code)
	}
	var res agenttools.ExecResult
	h.jsonOut(&res)
	if res.ExitCode != 4 {
		t.Fatalf("exec --json = %+v", res)
	}
	// JSON output is not HTML-escaped: agents read "&&", not "\u0026\u0026".
	if code := h.run("exec", "box", "--json", "--", "echo <a> && b"); code != 0 || !strings.Contains(h.stdout.String(), `"stdout": "<a> && b\n"`) {
		t.Fatalf("exec --json = %d %s", code, h.stdout.String())
	}
}

func TestExecInterruptSendsKill(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	go func() {
		time.Sleep(100 * time.Millisecond)
		h.interrupt <- syscall.SIGINT
	}()
	if code := h.run("exec", "box", "--", "sleep"); code != 130 {
		t.Fatalf("interrupted exec = %d, want 130", code)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if len(s.Signals) != 1 || s.Signals[0] != "KILL" {
			t.Fatalf("signals = %v", s.Signals)
		}
	})
}

// TestExecStdin is D19 reconciled with D10.
func TestExecStdin(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
	piped := func(s string) { h.app.stdin, h.app.stdinIsTTY = strings.NewReader(s), false }

	piped("x")
	if code := h.run("exec", "box", "--", "cat"); code != 0 || h.stdout.String() != "x" {
		t.Fatalf("piped stdin = %d %q", code, h.stdout.String())
	}
	piped("x")
	if code := h.run("exec", "box", "--no-stdin", "--", "cat"); code != 0 || h.stdout.String() != "" {
		t.Fatalf("--no-stdin = %q", h.stdout.String())
	}
	h.app.stdin, h.app.stdinIsTTY = strings.NewReader("typed"), true
	if code := h.run("exec", "box", "--", "cat"); code != 0 || h.stdout.String() != "" {
		t.Fatalf("terminal stdin without -i must not forward: %q", h.stdout.String())
	}
	h.app.stdin = strings.NewReader("typed")
	if code := h.run("exec", "box", "-i", "--", "cat"); code != 0 || h.stdout.String() != "typed" {
		t.Fatalf("-i = %q", h.stdout.String())
	}
	// WASM: the automatic forward is skipped (buffered exec works)...
	piped("x")
	if code := h.run("exec", "wasm", "--", "echo ok"); code != 0 || h.stdout.String() != "ok\n" {
		t.Fatalf("wasm with piped stdin = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	// ...and an explicit -i is refused.
	if code := h.run("exec", "wasm", "-i", "--json", "--", "cat"); code != execFailure || h.errorEnvelope().Code != agenttools.CodeUnsupportedRuntime {
		t.Fatalf("wasm -i = %d %q", code, h.stderr.String())
	}
}

func TestExecTTY(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	if code := h.run("exec", "box", "-t", "--", "echo"); code != execFailure || !strings.Contains(h.stderr.String(), "-t needs a terminal") {
		t.Fatalf("-t without a terminal = %d %q", code, h.stderr.String())
	}
	raw := 0
	h.app.stdoutIsTTY, h.app.term = true, fakeTerm{rawCalls: &raw}
	h.app.stdin = strings.NewReader("")
	if code := h.run("exec", "box", "-t", "-i", "--", "echo tty"); code != 0 || h.stdout.String() != "tty\n" || raw != 1 {
		t.Fatalf("-t = %d %q raw %d", code, h.stdout.String(), raw)
	}

	// docker's -it works, and a remote terminal gets a TERM it knows.
	h.env["TERM"] = "xterm-ghostty"
	for _, combined := range []string{"-it", "-ti"} {
		if code := h.run("exec", "box", combined, "--", "echo tty"); code != 0 || h.stdout.String() != "tty\n" {
			t.Fatalf("%s = %d %q %q", combined, code, h.stdout.String(), h.stderr.String())
		}
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if st := s.LastExecStart; !st.TTY || st.Cols != 120 || st.Rows != 40 || st.Env["TERM"] != "xterm-256color" {
			t.Fatalf("exec start = %+v", st)
		}
	})
	if code := h.run("exec", "box", "-it", "--env", "TERM=vt220", "--", "echo tty"); code != 0 {
		t.Fatalf("explicit TERM = %d", code)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if s.LastExecStart.Env["TERM"] != "vt220" {
			t.Fatalf("an explicit --env TERM was overridden: %+v", s.LastExecStart.Env)
		}
	})
	// No TTY, no TERM: a piped exec keeps the image's environment.
	h.app.stdoutIsTTY = false
	if code := h.run("exec", "box", "--", "echo plain"); code != 0 {
		t.Fatalf("plain = %d", code)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if _, set := s.LastExecStart.Env["TERM"]; set {
			t.Fatalf("a non-TTY exec got TERM: %+v", s.LastExecStart.Env)
		}
	})
	// After "--", -it belongs to the remote command.
	if code := h.run("exec", "box", "--", "echo", "-it"); code != 0 || h.stdout.String() != "-it\n" {
		t.Fatalf("-it after -- = %d %q", code, h.stdout.String())
	}
}

func TestExecTTYForwardsResizes(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	var mu sync.Mutex
	cols, rows := 120, 40
	resized := make(chan struct{}, 1)
	h.app.stdoutIsTTY = true
	h.app.term = fakeTerm{resized: resized, size: func() (int, int) { mu.Lock(); defer mu.Unlock(); return cols, rows }}
	keys := h.keyboard()
	done := h.runAsync("exec", "box", "-it", "--", "cat")
	waitFor(t, func() bool {
		n := 0
		h.fake.Observe(func(s *agenttoolstest.Server) { n = s.StreamDials })
		return n == 1
	})
	mu.Lock()
	cols, rows = 100, 30
	mu.Unlock()
	resized <- struct{}{}
	var got []string
	waitFor(t, func() bool {
		h.fake.Observe(func(s *agenttoolstest.Server) { got = slices.Clone(s.Resizes) })
		return slices.Equal(got, []string{"100x30"})
	})
	_ = keys.Close()
	if code := h.wait(done); code != 0 {
		t.Fatalf("exec = %d %q", code, h.stderr.String())
	}
}

func TestExpandShortFlags(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"box", "-it", "--", "bash"}, []string{"box", "-i", "-t", "--", "bash"}},
		{[]string{"-ti", "box"}, []string{"-i", "-t", "box"}},
		{[]string{"box", "--", "ls", "-it"}, []string{"box", "--", "ls", "-it"}},
		{[]string{"box", "-i", "-t"}, []string{"box", "-i", "-t"}},
		{nil, []string{}},
	} {
		if got := expandShortFlags(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("expandShortFlags(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBackgroundAndLogs(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	if code := h.run("exec", "box", "--background", "--", "npm run dev"); code != 0 {
		t.Fatalf("background = %d %s", code, h.stderr.String())
	}
	sid := strings.TrimSpace(h.stdout.String())
	if !strings.HasPrefix(sid, "ses-") || !strings.Contains(h.stderr.String(), "aerolvm logs box "+sid) {
		t.Fatalf("background output %q / %q", sid, h.stderr.String())
	}
	if code := h.run("exec", "box", "--background", "--json", "--", "x"); code != 0 || !strings.Contains(h.stdout.String(), `"session_id"`) {
		t.Fatalf("background --json = %q", h.stdout.String())
	}
	if code := h.run("logs", "box", sid); code != 0 || !strings.Contains(h.stdout.String(), "started npm run dev") {
		t.Fatalf("logs = %d %q", code, h.stdout.String())
	}
	if code := h.run("logs", "box", sid, "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"output"`) {
		t.Fatalf("logs --json = %q", h.stdout.String())
	}
	if code := h.run("logs", "box", sid, "--follow"); code != 0 || !strings.Contains(h.stdout.String(), "started npm run dev") || !strings.Contains(h.stderr.String(), "exited with code 0") {
		t.Fatalf("logs --follow = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("logs", "box", "ses-404"); code != exitError {
		t.Fatalf("missing session = %d", code)
	}
	if code := h.run("logs", "box"); code != exitUsage {
		t.Fatalf("logs usage = %d", code)
	}
}

func TestCpAndLs(t *testing.T) {
	h := newHarness(t)
	box := h.fake.AddSandbox(models.Sandbox{Name: "box"})
	dir := t.TempDir()
	local := filepath.Join(dir, "data.csv")
	if err := os.WriteFile(local, []byte("a,b\n1,2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := h.run("cp", local, "box:/work/"); code != 0 {
		t.Fatalf("upload = %d %s", code, h.stderr.String())
	}
	if got, _ := h.fake.File(box.ID, "/work/data.csv"); string(got) != "a,b\n1,2\n" {
		t.Fatalf("uploaded %q", got)
	}
	h.app.stdin = strings.NewReader("from stdin")
	if code := h.run("cp", "-", "box:/work/in.txt", "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"bytes": 10`) {
		t.Fatalf("stdin upload = %d %q", code, h.stdout.String())
	}
	if code := h.run("cp", "box:/work/data.csv", dir); code != 0 {
		t.Fatalf("download into dir = %d %s", code, h.stderr.String())
	}
	out := filepath.Join(dir, "copy.csv")
	if code := h.run("cp", "box:/work/data.csv", out); code != 0 {
		t.Fatal(code)
	}
	if got, _ := os.ReadFile(out); string(got) != "a,b\n1,2\n" {
		t.Fatalf("downloaded %q", got)
	}
	if code := h.run("cp", "box:/work/in.txt", "-"); code != 0 || h.stdout.String() != "from stdin" {
		t.Fatalf("download to stdout = %q", h.stdout.String())
	}
	usage := [][]string{{"cp", "a", "b"}, {"cp", "x:/a", "y:/b"}, {"cp", "one"}, {"cp", "-", "box:/dir/"}, {"cp", "box:", out}}
	for _, args := range usage {
		if code := h.run(args...); code != exitUsage {
			t.Fatalf("%v = %d, want usage", args, code)
		}
	}
	if code := h.run("cp", dir, "box:/x"); code != exitError || !strings.Contains(h.stderr.String(), "tar") {
		t.Fatalf("directory upload = %d %q", code, h.stderr.String())
	}
	if code := h.run("cp", "box:/missing", out); code != exitError {
		t.Fatalf("missing download = %d", code)
	}
	if code := h.run("cp", filepath.Join(dir, "nope"), "box:/x"); code != exitError {
		t.Fatalf("missing local = %d", code)
	}

	if code := h.run("ls", "box:/work"); code != 0 || !strings.Contains(h.stdout.String(), "data.csv") {
		t.Fatalf("ls = %d %q", code, h.stdout.String())
	}
	if code := h.run("ls", "box:/work", "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"entries"`) {
		t.Fatalf("ls --json = %q", h.stdout.String())
	}
	if code := h.run("ls", "box"); code != 0 {
		t.Fatalf("ls without path = %d", code)
	}
	if code := h.run("ls"); code != exitUsage {
		t.Fatalf("ls usage = %d", code)
	}
}

func TestRemotePath(t *testing.T) {
	for arg, want := range map[string][2]string{
		"box:/work/a": {"box", "/work/a"},
		"sb-0123:x":   {"sb-0123", "x"},
	} {
		ref, p, ok := remotePath(arg)
		if !ok || ref != want[0] || p != want[1] {
			t.Fatalf("remotePath(%q) = %q %q %v", arg, ref, p, ok)
		}
	}
	for _, local := range []string{"./a:b", `C:\data`, "plain", ":x", "dir/x:y"} {
		if _, _, ok := remotePath(local); ok {
			t.Fatalf("remotePath(%q) must be local", local)
		}
	}
}

func TestLifecycleVerbs(t *testing.T) {
	h := newHarness(t)
	a := h.fake.AddSandbox(models.Sandbox{Name: "a"})
	h.fake.AddSandbox(models.Sandbox{Name: "b"})
	if code := h.run("stop", "a", "b"); code != 0 || strings.Count(h.stdout.String(), "sb-") != 2 {
		t.Fatalf("stop = %d %q", code, h.stdout.String())
	}
	if code := h.run("start", "a", "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"status": "started"`) {
		t.Fatalf("start = %q", h.stdout.String())
	}
	if code := h.run("expose", "a", "3000"); code != 0 || !strings.HasPrefix(h.stdout.String(), "https://3000-") {
		t.Fatalf("expose = %q", h.stdout.String())
	}
	if code := h.run("expose", "a", "3000", "--json"); code != 0 || !strings.Contains(h.stdout.String(), "public_url") {
		t.Fatalf("expose --json = %q", h.stdout.String())
	}
	if code := h.run("expose", "a", "99999"); code != exitUsage {
		t.Fatalf("bad port = %d", code)
	}
	if code := h.run("snapshot", "a", "deps"); code != 0 || strings.TrimSpace(h.stdout.String()) != "deps" {
		t.Fatalf("snapshot = %q", h.stdout.String())
	}
	if code := h.run("snapshot", "a", "deps", "--json"); code != 0 || !strings.Contains(h.stdout.String(), "snapshots/deps") {
		t.Fatalf("snapshot --json = %q", h.stdout.String())
	}
	if code := h.run("destroy", "a", "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"destroyed": true`) {
		t.Fatalf("destroy = %d %q", code, h.stdout.String())
	}
	if _, ok := h.fake.Sandbox(a.ID); ok {
		t.Fatal("a still exists")
	}
	// Already gone counts as destroyed (§5.2 rule 7).
	if code := h.run("destroy", "a", "b"); code != 0 || !strings.Contains(h.stderr.String(), "a: already gone") {
		t.Fatalf("destroy again = %d %q", code, h.stderr.String())
	}
	if code := h.run("stop", "missing", "--json"); code != exitError {
		t.Fatalf("stop missing = %d", code)
	}
	for _, args := range [][]string{{"start"}, {"snapshot", "a"}, {"expose", "a"}, {"get"}, {"create", "extra"}, {"list", "x"}, {"list", "--limit", "-1"}, {"health", "x"}} {
		if code := h.run(args...); code != exitUsage {
			t.Fatalf("%v = %d, want usage", args, code)
		}
	}
}

// TestDebugRedactsToken is the §6 required proof: --debug logs never carry
// the token.
func TestDebugRedactsToken(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	if code := h.run("get", "box", "--debug"); code != 0 {
		t.Fatal(code)
	}
	logs := h.stderr.String()
	if !strings.Contains(logs, "aerolvm debug: > GET /v1/sandboxes?name=box") || !strings.Contains(logs, "Authorization: [REDACTED]") {
		t.Fatalf("debug output = %q", logs)
	}
	if strings.Contains(logs, agenttoolstest.Token) {
		t.Fatal("--debug printed the token")
	}
	h.env["SB_API_URL"] = "http://127.0.0.1:1"
	if code := h.run("health", "--debug"); code != exitError || !strings.Contains(h.stderr.String(), "< error after") {
		t.Fatalf("debug transport error = %q", h.stderr.String())
	}
}

func TestMissingToken(t *testing.T) {
	h := newHarness(t)
	h.env["SB_PAT_TOKEN"] = ""
	t.Setenv("SB_PAT_TOKEN", "")
	for _, args := range [][]string{{"list"}, {"get", "x"}, {"health"}, {"create"}, {"stop", "x"}, {"expose", "x", "1"}, {"snapshot", "x", "y"}, {"cp", "box:/a", "-"}, {"ls", "box:/"}, {"logs", "x", "y"}} {
		if code := h.run(args...); code != exitError || !strings.Contains(h.stderr.String(), "SB_PAT_TOKEN") {
			t.Fatalf("%v without a token = %d %q", args, code, h.stderr.String())
		}
	}
	if code := h.run("exec", "x", "--", "y"); code != execFailure {
		t.Fatalf("exec without a token = %d", code)
	}
}

func TestParseArgsAndQuoting(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cwd := fs.String("cwd", "", "")
	pos, rest, err := parseArgs(fs, []string{"sb", "--cwd", "/app", "extra", "--", "make", "--cwd", "x"})
	if err != nil || *cwd != "/app" || strings.Join(pos, ",") != "sb,extra" || strings.Join(rest, ",") != "make,--cwd,x" {
		t.Fatalf("parseArgs = %v %v %v cwd=%q", pos, rest, err, *cwd)
	}
	for in, want := range map[string]string{"plain": "plain", "a b": "'a b'", "it's": `'it'\''s'`, "": "''", "/x/y.go": "/x/y.go"} {
		if got := shellQuote(in); got != want {
			t.Fatalf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
	if shellCommand([]string{"ls | wc -l"}) != "ls | wc -l" || shellCommand([]string{"echo", "a b"}) != "echo 'a b'" {
		t.Fatal("shellCommand")
	}
	l := kvList{}
	if err := l.Set("novalue"); err == nil || l.Set("=x") == nil {
		t.Fatal("kvList must reject a missing key")
	}
	_ = l.Set("b=2")
	_ = l.Set("a=1")
	if l.String() != "a=1,b=2" {
		t.Fatalf("kvList.String = %q", l.String())
	}
	if signalExit(syscall.SIGTERM) != 143 || signalExit(fakeSignal{}) != execFailure {
		t.Fatal("signalExit")
	}
}

type fakeSignal struct{}

func (fakeSignal) String() string { return "fake" }
func (fakeSignal) Signal()        {}

func TestNotifyInterrupts(t *testing.T) {
	ctx, received, stop := notifyInterrupts(context.Background())
	if received() != nil {
		t.Fatal("no signal yet")
	}
	stop()
	<-ctx.Done()
}

func TestNewAppDefaults(t *testing.T) {
	a := newApp()
	if a.stdout != os.Stdout || a.newTools == nil || a.notifySignals == nil {
		t.Fatal("newApp wiring")
	}
	if _, _, ok := (osTerminal{}).Size(); ok {
		t.Log("test stdout is a terminal")
	}
	restore, err := (osTerminal{}).MakeRaw()
	if err == nil {
		restore()
	}
}

// TestCreateAllowHost covers P2-3: --allow-host is repeatable and becomes
// the create's allow list; it can't be combined with --block-network.
func TestCreateAllowHost(t *testing.T) {
	h := newHarness(t)
	if code := h.run("create", "--name", "egress", "--allow-host", "pypi.org", "--allow-host", "*.pythonhosted.org"); code != exitOK {
		t.Fatalf("create = %d %s", code, h.stderr.String())
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if got := s.LastCreate.NetworkAllowOut; len(got) != 2 || got[0] != "pypi.org" || got[1] != "*.pythonhosted.org" || s.LastCreate.NetworkBlockAll {
			t.Fatalf("create request = %+v", s.LastCreate)
		}
	})
	if code := h.run("create", "--block-network", "--allow-host", "pypi.org", "--json"); code != exitUsage || h.errorEnvelope().Code != "usage" {
		t.Fatalf("--block-network with --allow-host = %d", code)
	}
	if code := h.run("create", "--name", "egress2", "--allow-host", "pypi.org, github.com:22"); code != exitOK {
		t.Fatalf("comma list = %d %s", code, h.stderr.String())
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if got := s.LastCreate.NetworkAllowOut; len(got) != 2 || got[1] != "github.com:22" {
			t.Fatalf("comma list = %v", got)
		}
	})
}
