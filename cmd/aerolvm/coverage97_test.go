package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

type errTerm struct{}

func (errTerm) Size() (int, int, bool) { return 80, 24, true }
func (errTerm) MakeRaw() (func(), error) {
	return nil, errors.New("terminal refused raw mode")
}
func (errTerm) NotifyResize() (<-chan struct{}, func()) { return nil, func() {} }
func (errTerm) ReadSecret() (string, error) {
	return "", errors.New("terminal refused to read")
}

func TestCLIUncoveredBranches(t *testing.T) {
	h := newHarness(t)
	box := h.fake.AddSandbox(models.Sandbox{
		Name: "box", Image: "old", PublicURL: "https://box.example.test",
	})
	h.fake.AddSandbox(models.Sandbox{Name: "other"})
	h.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})

	if code := h.run("exec", "box", "--", "stderr", "oops"); code != 0 || !strings.Contains(h.stderr.String(), "oops") {
		t.Fatalf("stderr sink = %d %q", code, h.stderr.String())
	}
	if code := h.run("create", "--name", "box", "--image", "new"); code != 0 || !strings.Contains(h.stderr.String(), "already exists") {
		t.Fatalf("image warning = %d %q", code, h.stderr.String())
	}
	h.fake.FailCreates = 1
	if code := h.run("create", "--name", "fresh"); code != exitError {
		t.Fatalf("create failure = %d", code)
	}
	h.fake.IgnoreLimit = true
	if code := h.run("list", "--limit", "1"); code != 0 || strings.Count(h.stdout.String(), "sb-") != 1 {
		t.Fatalf("client-side page trim = %d %q", code, h.stdout.String())
	}
	h.fake.IgnoreLimit = false
	if code := h.run("list", "--limit", "1"); code != 0 || !strings.Contains(h.stderr.String(), "--page-token") {
		t.Fatalf("next page note = %d %q", code, h.stderr.String())
	}
	if code := h.run("get", "box"); code != 0 || !strings.Contains(h.stdout.String(), "https://box.example.test") {
		t.Fatalf("get url = %d %q", code, h.stdout.String())
	}
	if code := h.run("expose", "box", "9", "--tcp"); code != 0 || strings.TrimSpace(h.stdout.String()) != "127.0.0.1:40009" {
		t.Fatalf("tcp expose = %d %q", code, h.stdout.String())
	}
	if code := h.run("health", "--json"); code != 0 || !strings.Contains(h.stdout.String(), "fake") {
		t.Fatalf("health json = %d %q", code, h.stdout.String())
	}
	h.fake.FailStart = true
	if code := h.run("start", "box"); code != exitError {
		t.Fatalf("start failure = %d %q", code, h.stderr.String())
	}
	if code := h.run("exec", "iso", "--background", "--", "sleep"); code != execFailure {
		t.Fatalf("isolate background = %d %q", code, h.stderr.String())
	}
	h.app.stdoutIsTTY = true
	h.app.term = errTerm{}
	if code := h.run("exec", "box", "-t", "-i", "--", "echo"); code != execFailure || !strings.Contains(h.stderr.String(), "raw mode") {
		t.Fatalf("raw mode = %d %q", code, h.stderr.String())
	}
	if code := h.run("logs", "missing", "ses-1"); code != exitError {
		t.Fatalf("logs missing sandbox = %d", code)
	}
	if code := h.run("logs", "box", "ses-404", "--json"); code != exitError {
		t.Fatalf("logs json missing = %d %q", code, h.stderr.String())
	}
	h.fake.PutFile(box.ID, "/work/sub/", nil)
	if code := h.run("ls", "box:/work"); code != 0 || !strings.Contains(h.stdout.String(), "sub/") {
		t.Fatalf("dir listing = %d %q", code, h.stdout.String())
	}
	for i := 0; i < agenttools.MaxListEntries+2; i++ {
		h.fake.PutFile(box.ID, "/work/f"+strconv.Itoa(i), []byte("x"))
	}
	if code := h.run("ls", "box:/work"); code != 0 || !strings.Contains(h.stderr.String(), "listing cut") {
		t.Fatalf("truncated listing = %d %q", code, h.stderr.String())
	}

	for _, args := range [][]string{
		{"create", "--nope"},
		{"list", "--nope"},
		{"logs", "--nope"},
		{"expose", "--nope"},
		{"snapshot", "--nope"},
		{"health", "--nope"},
		{"version", "--nope"},
		{"cp", "--nope"},
		{"ls", "--nope"},
		{"start", "--nope"},
	} {
		if code := h.run(args...); code != exitUsage {
			t.Fatalf("%v = %d, want usage", args, code)
		}
	}
}

func TestCLICopyAndListFailures(t *testing.T) {
	h := newHarness(t)
	box := h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	h.fake.PutFile(box.ID, "/work/note.txt", []byte("hi"))

	if code := h.run("cp", "box:/work/note.txt", "iso:/work/note.txt"); code != exitUsage || !strings.Contains(h.stderr.String(), "two sandboxes") {
		t.Fatalf("sandbox to sandbox = %d %q", code, h.stderr.String())
	}
	if code := h.run("cp", "box:/missing", "-"); code == 0 {
		t.Fatal("missing download succeeded")
	}
	if code := h.run("cp", "nope:/work/note.txt", t.TempDir()+"/out.txt"); code == 0 {
		t.Fatal("download from a missing sandbox succeeded")
	}
	missingDir := filepath.Join(t.TempDir(), "missing", "out.txt")
	if code := h.run("cp", "box:/work/note.txt", missingDir); code == 0 {
		t.Fatal("download into a missing directory succeeded")
	}
	if code := h.run("cp", filepath.Join(t.TempDir(), "no-such-file"), "box:/work/in.txt"); code == 0 {
		t.Fatal("upload of a missing file succeeded")
	}
	if code := h.run("cp", "/etc/hosts", "iso:/work/hosts"); code == 0 {
		t.Fatal("upload into an isolate sandbox succeeded")
	}
	if code := h.run("ls", "missing:/work"); code == 0 {
		t.Fatal("ls of a missing sandbox succeeded")
	}
	if code := h.run("ls", "iso:/work"); code == 0 {
		t.Fatal("ls of an isolate sandbox succeeded")
	}
}

func TestCLIFollowLogsSignalAndDetach(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.fake.AttachExitSignal = "TERM"
	if code := h.run("exec", "box", "--background", "--", "sleep", "30"); code != 0 {
		t.Fatalf("background = %d %s", code, h.stderr.String())
	}
	sid := strings.TrimSpace(strings.SplitN(h.stdout.String(), "\n", 2)[0])
	if code := h.run("logs", "--follow", "box", sid); code != 0 || !strings.Contains(h.stderr.String(), "exited by signal TERM") {
		t.Fatalf("follow signal = %d %q", code, h.stderr.String())
	}
	if code := h.run("logs", "--follow", "box", "missing-session"); code == 0 {
		t.Fatal("follow of a missing session succeeded")
	}
	h.fake.Observe(func(s *agenttoolstest.Server) { s.DropAttach = true })
	if code := h.run("logs", "--follow", "box", sid); code == 0 {
		t.Fatal("follow of a dropped attach succeeded")
	}
	// The attach handler reads these under the fake's mutex. A websocket
	// close does not order that read before a bare field write, so the
	// race detector reports it. Assign through Observe, which holds the
	// same mutex.
	ready := make(chan struct{})
	h.fake.Observe(func(s *agenttoolstest.Server) {
		s.DropAttach = false
		s.HangAttach = true
		s.AttachReady = ready
	})
	done := make(chan int, 1)
	go func() { done <- h.run("logs", "--follow", "box", sid) }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("follow did not attach")
	}
	h.interrupt <- os.Interrupt
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(h.stderr.String(), "detached") {
			t.Fatalf("detach = %d %q", code, h.stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow did not detach")
	}
}

func TestCoverage97VerbFailures(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.fake.FailDestroy = true
	h.fake.FailExpose = true
	if code := h.run("destroy", "box"); code == 0 {
		t.Fatal("destroy failure was ignored")
	}
	if code := h.run("expose", "missing", "80"); code == 0 {
		t.Fatal("expose of a missing sandbox succeeded")
	}
	if code := h.run("expose", "box", "80"); code == 0 {
		t.Fatal("expose failure was ignored")
	}
	if code := h.run("snapshot", "missing", "snap"); code == 0 {
		t.Fatal("snapshot of a missing sandbox succeeded")
	}
}

func TestCoverage97MCPStdinAndFlagEcho(t *testing.T) {
	h := newHarness(t)
	h.app.stdin = strings.NewReader("{")
	if code := h.run("mcp"); code == 0 && !strings.Contains(h.stderr.String(), "mcp") {
		t.Fatalf("mcp = %d %q", code, h.stderr.String())
	}
	if code := h.app.optionError(&commonFlags{}, errors.New("plain")); code == 0 {
		t.Fatal("plain option error was accepted")
	}
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "")
	debug := fs.Bool("debug", false, "")
	ephemeral := fs.Bool("ephemeral", false, "")
	if err := fs.Parse([]string{"--json", "--debug", "--ephemeral"}); err != nil {
		t.Fatal(err)
	}
	got := explicitFlags(fs)
	if len(got) != 1 || got[0] != "--ephemeral" || !*jsonFlag || !*debug || !*ephemeral {
		t.Fatalf("explicit flags = %q", got)
	}
}

func TestCoverage97ListAgainstClosedAPI(t *testing.T) {
	h := newHarness(t)
	h.fake.Close()
	if code := h.run("list"); code == 0 {
		t.Fatal("list succeeded against a closed API")
	}
}
