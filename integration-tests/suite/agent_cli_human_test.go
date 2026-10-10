//go:build integration

package suite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-217..230: the aerolvm CLI as a person uses it, against a live
// deployment: `shell` and `exec -it` in a real pseudo-terminal, `login` /
// `logout` with a private config directory, and the remaining verbs (start,
// stop, list, get, ls, logs, snapshot, health, version, mcp config). The CLI
// is built from this tree (aerolvmBinary), so a run tests the branch.

// cliEnv is an environment with nothing inherited that could pick the
// server or token (SB_*, XDG_CONFIG_HOME) or the terminal type, plus extra.
// A run never reads or writes the operator's own aerolvm login.
func cliEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "SB_") || k == "XDG_CONFIG_HOME" || k == "TERM" || k == "AEROLVM_OUTPUT" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// tokenEnv is cliEnv with the scenario's server and token, and a private,
// empty config directory, so no saved login is in play.
func tokenEnv(t *testing.T, extra ...string) []string {
	return cliEnv(append([]string{"SB_API_URL=" + sc.BaseURL, "SB_PAT_TOKEN=" + sc.PAT, "XDG_CONFIG_HOME=" + t.TempDir()}, extra...)...)
}

// runCLI runs aerolvm with exactly env, without a terminal.
func runCLI(t *testing.T, env []string, stdin io.Reader, args ...string) cliResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, aerolvmBinary(t), args...)
	cmd.Env = env
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("aerolvm %v: %v", args, err)
	}
	return res
}

// mustCLI runs aerolvm and fails the test unless it exits 0.
func mustCLI(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	r := runCLI(t, env, nil, args...)
	if r.code != 0 {
		t.Fatalf("aerolvm %v = %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

// termCLI is aerolvm running in a real pseudo-terminal, as a person runs it:
// raw mode, window size, SIGWINCH and Ctrl-C all go through the kernel.
type termCLI struct {
	t      *testing.T
	cmd    *exec.Cmd
	tty    *os.File
	mu     sync.Mutex
	out    bytes.Buffer
	exited chan struct{}
	code   int
}

func startTermCLI(t *testing.T, env []string, rows, cols uint16, args ...string) *termCLI {
	t.Helper()
	cmd := exec.Command(aerolvmBinary(t), args...)
	cmd.Env = env
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		t.Fatalf("start aerolvm %v in a pty: %v", args, err)
	}
	tc := &termCLI{t: t, cmd: cmd, tty: tty, exited: make(chan struct{})}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 32<<10)
		for {
			n, err := tty.Read(buf)
			if n > 0 {
				tc.mu.Lock()
				tc.out.Write(buf[:n])
				tc.mu.Unlock()
			}
			if err != nil { // EIO once the child closes the terminal
				return
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			code = -1
		}
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
		}
		tc.mu.Lock()
		tc.code = code
		tc.mu.Unlock()
		close(tc.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = tty.Close()
	})
	return tc
}

func (tc *termCLI) text() string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.out.String()
}

// mark is the transcript length now; expectFrom only looks after it, so an
// earlier match of the same pattern doesn't count.
func (tc *termCLI) mark() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.out.Len()
}

func (tc *termCLI) expect(pattern string) []string { tc.t.Helper(); return tc.expectFrom(0, pattern) }

func (tc *termCLI) expectFrom(from int, pattern string) []string {
	tc.t.Helper()
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(90 * time.Second)
	for {
		text := tc.text()
		if from > len(text) {
			from = len(text)
		}
		if m := re.FindStringSubmatch(text[from:]); m != nil {
			return m
		}
		select {
		case <-tc.exited:
			if m := re.FindStringSubmatch(tc.text()[from:]); m != nil {
				return m
			}
			tc.t.Fatalf("aerolvm exited (code %d) before printing /%s/; transcript:\n%s", tc.code, pattern, tc.text())
		default:
		}
		if time.Now().After(deadline) {
			tc.t.Fatalf("no /%s/ within 90s; transcript:\n%s", pattern, tc.text())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (tc *termCLI) send(s string) {
	tc.t.Helper()
	if _, err := tc.tty.Write([]byte(s)); err != nil {
		tc.t.Fatalf("type %q: %v", s, err)
	}
}

// run types a shell command line and waits for marker in its output.
// Markers are computed by the shell ($((…))), so the echo of the typed line
// never matches them.
func (tc *termCLI) run(line, marker string) {
	tc.t.Helper()
	from := tc.mark()
	tc.send(line + "\r")
	tc.expectFrom(from, regexp.QuoteMeta(marker))
}

func (tc *termCLI) resize(rows, cols uint16) {
	tc.t.Helper()
	if err := pty.Setsize(tc.tty, &pty.Winsize{Rows: rows, Cols: cols}); err != nil {
		tc.t.Fatalf("resize: %v", err)
	}
}

func (tc *termCLI) wait() int {
	tc.t.Helper()
	select {
	case <-tc.exited:
	case <-time.After(90 * time.Second):
		tc.t.Fatalf("aerolvm didn't exit within 90s; transcript:\n%s", tc.text())
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.code
}

// createCLISandbox creates a sandbox through the CLI with the token env and
// destroys it when the test ends.
func createCLISandbox(t *testing.T, image string) string {
	t.Helper()
	name := harness.UniqueName(sc, t)
	destroyByNameOnCleanup(t, client(t), name)
	mustCLI(t, tokenEnv(t), "create", "--name", name, "--image", image, "--destroy-if-idle", "1h")
	return name
}

func sessionsOf(t *testing.T, name string) []sdktypes.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sb, err := client(t).SDK().GetByName(ctx, name)
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	sessions, err := sb.ListSessions(ctx)
	if err != nil {
		t.Fatalf("list sessions of %s: %v", name, err)
	}
	return sessions
}

// UC-217 — `aerolvm shell` in a real terminal.
func TestAerolvmShellTerminal(t *testing.T) {
	harness.Require(t, sc, "UC-217")
	name := createCLISandbox(t, harness.DefaultImage)

	// xterm-kitty isn't in an alpine image's terminfo; the shell gets the
	// xterm-256color it emulates.
	sh := startTermCLI(t, tokenEnv(t, "TERM=xterm-kitty"), 30, 100, "shell", name)
	sh.expect(`new shell in ` + regexp.QuoteMeta(name))
	sh.run(`echo "T=$TERM S=$(stty size)" ready-$((40+2))`, "ready-42")
	if !strings.Contains(sh.text(), "T=xterm-256color S=30 100") {
		t.Fatalf("TERM / initial size not passed through:\n%s", sh.text())
	}

	sh.resize(40, 120)
	time.Sleep(time.Second) // SIGWINCH → resize frame → TIOCSWINSZ in the sandbox
	sh.run(`echo "S=$(stty size)" resized-$((40+3))`, "resized-43")
	if !strings.Contains(sh.text(), "S=40 120") {
		t.Fatalf("window resize didn't reach the sandbox:\n%s", sh.text())
	}

	sh.send("exit 7\r")
	if code := sh.wait(); code != 7 {
		t.Fatalf("shell exit code = %d, want the remote 7\n%s", code, sh.text())
	}
}

// UC-218 — Ctrl-] detaches and the shell keeps running; reopening lands in
// the same shell with its recent output; after `exit` the next one is new.
func TestAerolvmShellDetachReopen(t *testing.T) {
	harness.Require(t, sc, "UC-218")
	name := createCLISandbox(t, harness.DefaultImage)
	env := tokenEnv(t, "TERM=xterm-256color")

	sh := startTermCLI(t, env, 30, 100, "shell", name)
	sh.expect(`new shell in`)
	sh.run(`export KEPT=still-here; echo marker-$((6*7))`, "marker-42")
	sh.send("\x1d") // Ctrl-]
	if code := sh.wait(); code != 0 {
		t.Fatalf("detach exit = %d\n%s", code, sh.text())
	}
	if !strings.Contains(sh.text(), "detached; the shell keeps running. Reopen it with: aerolvm shell "+name) {
		t.Fatalf("no reopen hint after detach:\n%s", sh.text())
	}

	sh = startTermCLI(t, env, 30, 100, "shell", name)
	sh.expect(`back in the running shell in ` + regexp.QuoteMeta(name))
	sh.expect(`marker-42`) // replayed from the session's buffer
	sh.run(`echo "got=$KEPT" again-$((1+1))`, "again-2")
	if !strings.Contains(sh.text(), "got=still-here") {
		t.Fatalf("reopen landed in a different shell:\n%s", sh.text())
	}
	sh.send("exit\r")
	if code := sh.wait(); code != 0 {
		t.Fatalf("exit = %d\n%s", code, sh.text())
	}

	sh = startTermCLI(t, env, 30, 100, "shell", name)
	sh.expect(`new shell in`)
	sh.run(`echo "got=${KEPT:-unset}" fresh-$((2+2))`, "fresh-4")
	if !strings.Contains(sh.text(), "got=unset") {
		t.Fatalf("a shell that exited was reopened:\n%s", sh.text())
	}
	sh.send("exit\r")
	sh.wait()
}

// UC-219 — the client dying mid-shell (as on a lost network) leaves the
// shell running in the sandbox, and the next `aerolvm shell` is back in it.
func TestAerolvmShellSurvivesDroppedClient(t *testing.T) {
	harness.Require(t, sc, "UC-219")
	name := createCLISandbox(t, harness.DefaultImage)
	env := tokenEnv(t, "TERM=xterm-256color")

	sh := startTermCLI(t, env, 30, 100, "shell", name)
	sh.expect(`new shell in`)
	sh.run(`export SURVIVOR=yes; echo armed-$((5*5))`, "armed-25")
	// SIGKILL: no close frame, no terminal restore, the socket just drops.
	if err := sh.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	sh.wait()

	var shells int
	for _, s := range sessionsOf(t, name) {
		if s.Name == "default" && s.PTY && s.Status == sdktypes.SessionStatusRunning {
			shells++
		}
	}
	if shells != 1 {
		t.Fatalf("running default shells after the client died = %d, want 1", shells)
	}

	sh = startTermCLI(t, env, 30, 100, "shell", name)
	sh.expect(`back in the running shell`)
	sh.run(`echo "got=$SURVIVOR" check-$((3*3))`, "check-9")
	if !strings.Contains(sh.text(), "got=yes") {
		t.Fatalf("the shell didn't survive the dropped client:\n%s", sh.text())
	}
	sh.send("exit\r")
	sh.wait()
}

// UC-220 — `--new` starts a separate shell and `--session` reopens it; the
// shared default shell can't see into it.
func TestAerolvmShellNamedSessions(t *testing.T) {
	harness.Require(t, sc, "UC-220")
	name := createCLISandbox(t, harness.DefaultImage)
	env := tokenEnv(t, "TERM=xterm-256color")

	sh := startTermCLI(t, env, 30, 100, "shell", name, "--new")
	sh.expect(`new shell in`)
	sh.run(`export MINE=private; echo own-$((8*8))`, "own-64")
	sh.send("\x1d")
	sh.wait()
	m := regexp.MustCompile(`aerolvm shell \S+ --session (shell-[0-9a-f]{8})`).FindStringSubmatch(sh.text())
	if m == nil {
		t.Fatalf("detaching a --new shell printed no --session to reopen it:\n%s", sh.text())
	}

	sh = startTermCLI(t, env, 30, 100, "shell", name)
	sh.expect(`new shell in`)
	sh.run(`echo "default=${MINE:-unset}" d-$((9*9))`, "d-81")
	if !strings.Contains(sh.text(), "default=unset") {
		t.Fatalf("the default shell shares state with a --new one:\n%s", sh.text())
	}
	sh.send("exit\r")
	sh.wait()

	sh = startTermCLI(t, env, 30, 100, "shell", name, "--session", m[1])
	sh.expect(`back in the running shell`)
	sh.run(`echo "named=$MINE" n-$((7*7))`, "n-49")
	if !strings.Contains(sh.text(), "named=private") {
		t.Fatalf("--session %s didn't reopen the --new shell:\n%s", m[1], sh.text())
	}
	sh.send("exit 0\r")
	if code := sh.wait(); code != 0 {
		t.Fatalf("exit = %d", code)
	}
}

// UC-221 — with no sandbox named, `shell` offers a list and opens the one
// picked; without a terminal it refuses and opens nothing.
func TestAerolvmShellPickerAndNoTerminal(t *testing.T) {
	harness.Require(t, sc, "UC-221")
	name := createCLISandbox(t, harness.DefaultImage)
	env := tokenEnv(t, "TERM=xterm-256color")

	sh := startTermCLI(t, env, 40, 160, "shell")
	sh.expect(`(Number \[1-\d+\]: |your only sandbox with a shell)`)
	if strings.Contains(sh.text(), "your only sandbox") {
		if !strings.Contains(sh.text(), name) {
			t.Fatalf("the only sandbox offered isn't ours:\n%s", sh.text())
		}
	} else {
		var choice string
		for _, m := range regexp.MustCompile(`(?m)^\s*(\d+)\)\s+(\S+)`).FindAllStringSubmatch(sh.text(), -1) {
			if m[2] == name {
				choice = m[1]
			}
		}
		if choice == "" {
			t.Fatalf("%s isn't in the picker:\n%s", name, sh.text())
		}
		sh.send(choice + "\r")
	}
	sh.expect(`new shell in ` + regexp.QuoteMeta(name))
	sh.run(`echo picked-$((2*21))`, "picked-42")
	sh.send("exit\r")
	sh.wait()

	before := len(sessionsOf(t, name))
	r := runCLI(t, env, strings.NewReader(""), "shell", name)
	if r.code != 125 || !strings.Contains(r.stderr, "shell needs a terminal") || !strings.Contains(r.stderr, "aerolvm exec") {
		t.Fatalf("shell without a terminal = %d %q", r.code, r.stderr)
	}
	if after := len(sessionsOf(t, name)); after != before {
		t.Fatalf("a refused shell still opened a session (%d → %d)", before, after)
	}
}

// UC-222 — `aerolvm shell` and an SSH login land in the same default shell.
func TestAerolvmShellSharesSSHSession(t *testing.T) {
	harness.Require(t, sc, "UC-222")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Created through the SDK: only the create response carries the key.
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t)})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)

	sh := startTermCLI(t, tokenEnv(t, "TERM=xterm-256color"), 30, 100, "shell", sb.Name)
	sh.expect(`new shell in`)
	sh.run(`export SHARED=from-cli-$((40+2)); echo set-$((1+1))`, "set-2")
	sh.send("\x1d")
	if code := sh.wait(); code != 0 {
		t.Fatalf("detach = %d", code)
	}

	signer, err := ssh.ParsePrivateKey([]byte(sb.SSHPrivateKey))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	port := os.Getenv("AEROL_SSH_PORT")
	if port == "" {
		port = "2220"
	}
	cfg := &ssh.ClientConfig{
		User:            sb.ID, // "<id>" = the default session, the one shell opened
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // throwaway test gateway
		Timeout:         15 * time.Second,
	}
	var conn *ssh.Client
	deadline := time.Now().Add(90 * time.Second)
	for {
		conn, err = ssh.Dial("tcp", net.JoinHostPort(sc.Domain, port), cfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ssh dial: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
	defer conn.Close()
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatalf("ssh session: %v", err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 30, 100, ssh.TerminalModes{}); err != nil {
		t.Fatalf("ssh pty: %v", err)
	}
	stdin, _ := sess.StdinPipe()
	var out syncBuf
	sess.Stdout = &out
	if err := sess.Shell(); err != nil {
		t.Fatalf("ssh shell: %v", err)
	}
	_, _ = io.WriteString(stdin, "echo \"ssh-sees=$SHARED\" seen-$((3+4))\n")
	deadline = time.Now().Add(60 * time.Second)
	for !strings.Contains(out.String(), "seen-7") {
		if time.Now().After(deadline) {
			t.Fatalf("no answer over SSH:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "ssh-sees=from-cli-42") {
		t.Fatalf("SSH landed in a different shell than aerolvm shell:\n%s", out.String())
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// UC-223 — `exec -it` behaves like `docker exec -it`: TERM and size reach
// the command, a resize follows it, and Ctrl-C goes to it, not to aerolvm.
func TestAerolvmExecInteractiveTerminal(t *testing.T) {
	harness.Require(t, sc, "UC-223")
	name := createCLISandbox(t, harness.DefaultImage)

	script := `echo "T=$TERM S=$(stty size)"; read _; echo "S2=$(stty size)"; ` +
		`trap 'echo got-int; exit 7' INT; echo armed-$((6*6)); while :; do sleep 1; done`
	// One word after "--" is run as a shell command line (/bin/sh -c).
	ex := startTermCLI(t, tokenEnv(t, "TERM=xterm-ghostty"), 33, 111, "exec", name, "-it", "--", script)
	ex.expect(`T=xterm-256color S=33 111`)
	ex.resize(44, 132)
	time.Sleep(time.Second)
	ex.send("\r")
	ex.expect(`S2=44 132`)
	ex.expect(`armed-36`)
	ex.send("\x03") // Ctrl-C: a byte for the remote terminal in raw mode
	ex.expect(`got-int`)
	if code := ex.wait(); code != 7 {
		t.Fatalf("exec -it exit = %d, want the trap's 7\n%s", code, ex.text())
	}

	// After "--", -it belongs to the command, not to aerolvm.
	r := runCLI(t, tokenEnv(t), nil, "exec", name, "--no-stdin", "--", "echo", "-it")
	if r.code != 0 || r.stdout != "-it\n" {
		t.Fatalf("exec -- echo -it = %d %q %q", r.code, r.stdout, r.stderr)
	}
}

// loginEnv is cliEnv with a private config directory and no SB_* at all:
// only `aerolvm login` can supply a server and token.
func loginEnv(t *testing.T, extra ...string) ([]string, string) {
	dir := t.TempDir()
	return cliEnv(append([]string{"XDG_CONFIG_HOME=" + dir}, extra...)...), filepath.Join(dir, "aerolvm", "config.json")
}

// UC-224 — `login --token-stdin` checks the token against the live API and
// saves it 0600; every command then works with no SB_* variables; a wrong
// token is refused and doesn't replace the login.
func TestAerolvmLoginFromScript(t *testing.T) {
	harness.Require(t, sc, "UC-224")
	env, path := loginEnv(t)

	r := runCLI(t, env, strings.NewReader("garbage-token\n"), "login", sc.BaseURL, "--token-stdin")
	if r.code != 1 || !strings.Contains(r.stderr, "refused the token") {
		t.Fatalf("login with a wrong token = %d %q", r.code, r.stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a token sandboxd refused was saved")
	}

	r = runCLI(t, env, strings.NewReader(sc.PAT+"\n"), "login", sc.BaseURL, "--token-stdin", "--json")
	if r.code != 0 {
		t.Fatalf("login = %d %q", r.code, r.stderr)
	}
	var out map[string]string
	r.json(t, &out)
	if !strings.EqualFold(out["api_url"], strings.TrimRight(sc.BaseURL, "/")) || out["config_path"] != path || out["server_version"] == "" {
		t.Fatalf("login --json = %v", out)
	}
	if strings.Contains(r.stdout+r.stderr, sc.PAT) {
		t.Fatal("login printed the token")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved login mode = %v, %v; want 0600", info, err)
	}

	name := harness.UniqueName(sc, t)
	destroyByNameOnCleanup(t, client(t), name)
	mustCLI(t, env, "create", "--name", name, "--image", harness.DefaultImage, "--destroy-if-idle", "1h")
	if r := mustCLI(t, env, "list"); !strings.Contains(r.stdout, name) {
		t.Fatalf("list on the login misses %s:\n%s", name, r.stdout)
	}
	var got struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	mustCLI(t, env, "get", name, "--json").json(t, &got)
	if got.Name != name {
		t.Fatalf("get = %+v", got)
	}
	if r := mustCLI(t, env, "exec", name, "--no-stdin", "--", "echo on-the-login-$((2*3))"); r.stdout != "on-the-login-6\n" {
		t.Fatalf("exec on the login = %q", r.stdout)
	}
	if r := mustCLI(t, env, "ls", name+":/etc"); !strings.Contains(r.stdout, "passwd") {
		t.Fatalf("ls on the login = %q", r.stdout)
	}
	if r := mustCLI(t, env, "health"); !strings.HasPrefix(r.stdout, "ok (sandboxd ") || !strings.Contains(r.stderr, "with the token from "+path) {
		t.Fatalf("health on the login = %q %q", r.stdout, r.stderr)
	}

	// A wrong token later must not replace the good login.
	if r := runCLI(t, env, strings.NewReader("garbage-token"), "login", sc.BaseURL, "--token-stdin"); r.code != 1 {
		t.Fatalf("second login with a wrong token = %d", r.code)
	}
	mustCLI(t, env, "destroy", name)
}

// UC-225 — interactive `aerolvm login` in a real terminal: the token is
// typed with echo off and never shown; `logout` forgets it.
func TestAerolvmLoginInteractiveAndLogout(t *testing.T) {
	harness.Require(t, sc, "UC-225")
	env, path := loginEnv(t, "TERM=xterm-256color")

	lg := startTermCLI(t, env, 30, 100, "login")
	lg.expect(`sandboxd URL \[http://127\.0\.0\.1:21212\]: `)
	lg.send(sc.BaseURL + "\r")
	lg.expect(`API token \(typing is hidden\): `)
	// ReadPassword turns echo off just after the prompt is printed; a person
	// pastes after seeing it, and so does this.
	time.Sleep(500 * time.Millisecond)
	lg.send(sc.PAT + "\r")
	lg.expect(`logged in to \S+ \(sandboxd `)
	if code := lg.wait(); code != 0 {
		t.Fatalf("login = %d\n%s", code, lg.text())
	}
	if strings.Contains(lg.text(), sc.PAT) {
		t.Fatalf("the token was echoed to the terminal:\n%s", lg.text())
	}
	mustCLI(t, env, "list")

	r := mustCLI(t, env, "logout")
	if !strings.Contains(r.stderr, "logged out of") || !strings.Contains(r.stderr, "it still works on sandboxd") {
		t.Fatalf("logout = %q", r.stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("logout left the login file")
	}
	if r := runCLI(t, env, nil, "list"); r.code != 1 || !strings.Contains(r.stderr, "not logged in") {
		t.Fatalf("list after logout = %d %q", r.code, r.stderr)
	}
	if r := mustCLI(t, env, "logout"); !strings.Contains(r.stderr, "nothing to do") {
		t.Fatalf("second logout = %q", r.stderr)
	}
}

// UC-226 — the saved token only goes to the server it was saved for;
// `health` proves the token (sandboxd's /health needs none); `version`.
func TestAerolvmTokenScopeHealthVersion(t *testing.T) {
	harness.Require(t, sc, "UC-226")
	env, _ := loginEnv(t)
	if r := runCLI(t, env, strings.NewReader(sc.PAT), "login", sc.BaseURL, "--token-stdin"); r.code != 0 {
		t.Fatalf("login = %d %q", r.code, r.stderr)
	}

	var hits atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer elsewhere.Close()
	r := runCLI(t, append(env, "SB_API_URL="+elsewhere.URL), nil, "list")
	if r.code != 1 || !strings.Contains(r.stderr, "SB_API_URL points elsewhere") {
		t.Fatalf("list with SB_API_URL at another server = %d %q", r.code, r.stderr)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the other server received %d request(s); the saved token must never go there", n)
	}

	// The premise: /health answers without a token.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, sc.BaseURL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health without a token = %d, want 200", resp.StatusCode)
	}
	bad := cliEnv("SB_API_URL="+sc.BaseURL, "SB_PAT_TOKEN=garbage-token", "XDG_CONFIG_HOME="+t.TempDir())
	if r := runCLI(t, bad, nil, "health"); r.code != 1 || !strings.Contains(r.stderr, "refused the token") {
		t.Fatalf("health with a wrong token = %d %q (it must not pass on /health alone)", r.code, r.stderr)
	}
	if r := mustCLI(t, tokenEnv(t), "health"); !strings.Contains(r.stderr, "with the token from SB_PAT_TOKEN") {
		t.Fatalf("health = %q", r.stderr)
	}

	var v struct {
		Version string `json:"version"`
	}
	mustCLI(t, cliEnv(), "version", "--json").json(t, &v)
	if v.Version == "" {
		t.Fatal("version --json printed no version")
	}
	if r := mustCLI(t, cliEnv(), "--help"); !strings.Contains(r.stdout, "Work in a sandbox:") || !strings.Contains(r.stdout, "aerolvm login") {
		t.Fatalf("--help overview = %q", r.stdout)
	}
}

// UC-227 — stop keeps the files, start resumes, a command on a stopped
// sandbox starts it; list --tag and get follow the state.
func TestAerolvmLifecycleVerbs(t *testing.T) {
	harness.Require(t, sc, "UC-227")
	env := tokenEnv(t)
	name := createCLISandbox(t, harness.DefaultImage)

	local := filepath.Join(t.TempDir(), "kept.txt")
	if err := os.WriteFile(local, []byte("kept across stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustCLI(t, env, "cp", local, name+":/root/kept.txt")

	status := func() string {
		var sb struct {
			Status string `json:"status"`
		}
		mustCLI(t, env, "get", name, "--json").json(t, &sb)
		return sb.Status
	}
	mustCLI(t, env, "stop", name)
	if s := status(); s != "stopped" {
		t.Fatalf("status after stop = %q", s)
	}
	mustCLI(t, env, "start", name)
	if s := status(); s != "started" {
		t.Fatalf("status after start = %q", s)
	}
	if r := mustCLI(t, env, "cp", name+":/root/kept.txt", "-"); r.stdout != "kept across stop\n" {
		t.Fatalf("file after stop/start = %q", r.stdout)
	}

	mustCLI(t, env, "stop", name)
	if r := mustCLI(t, env, "exec", name, "--no-stdin", "--", "cat /root/kept.txt"); r.stdout != "kept across stop\n" {
		t.Fatalf("exec on a stopped sandbox = %q", r.stdout)
	}
	if s := status(); s != "started" {
		t.Fatalf("exec didn't start the stopped sandbox: %q", s)
	}

	var page struct {
		Sandboxes []struct {
			Name string `json:"name"`
		} `json:"sandboxes"`
	}
	mustCLI(t, env, "list", "--tag", "aerolvm.created_by=cli", "--json").json(t, &page)
	found := false
	for _, s := range page.Sandboxes {
		found = found || s.Name == name
	}
	if !found {
		t.Fatalf("list --tag aerolvm.created_by=cli misses %s", name)
	}
	mustCLI(t, env, "list", "--limit", "1", "--json").json(t, &page)
	if len(page.Sandboxes) > 1 {
		t.Fatalf("list --limit 1 returned %d rows", len(page.Sandboxes))
	}
}

// UC-228 — snapshot a sandbox and start another from it by name, as the
// snapshot help says.
func TestAerolvmSnapshotAndCreateFromIt(t *testing.T) {
	harness.Require(t, sc, "UC-228")
	env := tokenEnv(t)
	src := createCLISandbox(t, harness.DefaultImage)
	mustCLI(t, env, "exec", src, "--no-stdin", "--", "echo baked-in > /root/snap.txt")

	// Snapshot images stay on the node, like UC-21's; the run's teardown
	// removes them with it.
	snap := harness.UniqueName(sc, t) + "-snap"
	if r := mustCLI(t, env, "snapshot", src, snap); strings.TrimSpace(r.stdout) != snap {
		t.Fatalf("snapshot printed %q, want %q", r.stdout, snap)
	}
	derived := harness.UniqueName(sc, t) + "-from"
	destroyByNameOnCleanup(t, client(t), derived)
	// On a cluster the snapshot reaches other nodes in the background
	// (UC-21); single-node has it locally at once.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		r := runCLI(t, env, nil, "create", "--name", derived, "--image", snap, "--destroy-if-idle", "1h")
		if r.code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("create --image %s never succeeded: %s", snap, r.stderr)
		}
		time.Sleep(5 * time.Second)
	}
	if r := mustCLI(t, env, "exec", derived, "--no-stdin", "--", "cat /root/snap.txt"); r.stdout != "baked-in\n" {
		t.Fatalf("file in the sandbox made from the snapshot = %q", r.stdout)
	}
}

// UC-229 — a background command: `exec --background` returns a session,
// `logs` prints it, `logs --follow` streams to its exit; `ls --json`; and
// a background server is reached through `expose`.
func TestAerolvmBackgroundLogsLsExpose(t *testing.T) {
	harness.Require(t, sc, "UC-229")
	env := tokenEnv(t)
	name := createCLISandbox(t, agentImage)

	r := mustCLI(t, env, "exec", name, "--background", "--", "for i in 1 2 3; do echo tick-$i > /tmp/tick-$i; echo tick-$i; sleep 1; done; exit 4")
	session := strings.TrimSpace(r.stdout)
	if session == "" || !strings.Contains(r.stderr, "aerolvm logs "+name+" "+session+" --follow") {
		t.Fatalf("exec --background = %q %q", r.stdout, r.stderr)
	}
	r = mustCLI(t, env, "logs", name, session, "--follow")
	if !strings.Contains(r.stdout, "tick-1") || !strings.Contains(r.stdout, "tick-3") || !strings.Contains(r.stderr, "exited with code 4") {
		t.Fatalf("logs --follow = %q %q", r.stdout, r.stderr)
	}
	if r = mustCLI(t, env, "logs", name, session); !strings.Contains(r.stdout, "tick-2") {
		t.Fatalf("logs = %q", r.stdout)
	}
	var listing struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	mustCLI(t, env, "ls", name+":/tmp", "--json").json(t, &listing)
	ticks := 0
	for _, e := range listing.Entries {
		if strings.HasPrefix(e.Name, "tick-") {
			ticks++
		}
	}
	if ticks != 3 {
		t.Fatalf("ls --json /tmp found %d tick files, want 3: %+v", ticks, listing.Entries)
	}

	mustCLI(t, env, "exec", name, "--background", "--", "cd /tmp && python3 -m http.server 8080")
	url := strings.TrimSpace(mustCLI(t, env, "expose", name, "8080").stdout)
	if url == "" {
		t.Fatal("expose printed no URL")
	}
	if sc.Has(harness.CapDomain) {
		fetchEventually(t, url+"/tick-1")
	}
}

// UC-230 — after `aerolvm login`, `mcp config` prints a setup with no
// credentials in it, and the stdio MCP server runs on the login alone.
func TestAerolvmMCPOnLogin(t *testing.T) {
	harness.Require(t, sc, "UC-230")
	env, path := loginEnv(t)
	if r := runCLI(t, env, strings.NewReader(sc.PAT), "login", sc.BaseURL, "--token-stdin"); r.code != 0 {
		t.Fatalf("login = %d %q", r.code, r.stderr)
	}
	name := harness.UniqueName(sc, t)
	destroyByNameOnCleanup(t, client(t), name)

	r := mustCLI(t, env, "mcp", "config", "claude-code", "--sandbox", name)
	if r.stdout != "claude mcp add aerolvm -- aerolvm mcp --sandbox "+name+"\n" || !strings.Contains(r.stderr, path) {
		t.Fatalf("mcp config claude-code = %q %q", r.stdout, r.stderr)
	}
	for _, mcpClient := range []string{"claude-desktop", "cursor", "vscode"} {
		r := mustCLI(t, env, "mcp", "config", mcpClient)
		if strings.Contains(r.stdout, "SB_PAT_TOKEN") || strings.Contains(r.stdout, sc.PAT) {
			t.Fatalf("mcp config %s after login wires credentials:\n%s", mcpClient, r.stdout)
		}
	}

	cmd := exec.Command(aerolvmBinary(t), "mcp", "--sandbox", name, "--create-if-missing", "--image", harness.DefaultImage, "--ephemeral")
	cmd.Env = env
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "aerolvm-itest"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to aerolvm mcp on the login: %v", err)
	}
	var ex execOut
	mcpCall(t, cs, "exec", map[string]any{"command": "echo via-mcp-$((40+2))"}, &ex)
	if ex.ExitCode != 0 || ex.Stdout != "via-mcp-42\n" {
		_ = cs.Close()
		t.Fatalf("mcp exec on the login = %+v", ex)
	}
	if err := cs.Close(); err != nil {
		t.Logf("close: %v", err)
	}
	// --ephemeral: the server destroys the sandbox it created when it ends.
	deadline := time.Now().Add(2 * time.Minute)
	for {
		gctx, gcancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := client(t).SDK().GetByName(gctx, name)
		gcancel()
		if errors.Is(err, microvm.ErrNotFound) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ephemeral sandbox outlived the MCP server: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
}
