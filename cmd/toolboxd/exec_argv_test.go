package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

// hostileArgs reach a program unchanged only if no shell parses them.
var hostileArgs = []string{"a b", "'single'", `"double"`, "$HOME", "; echo pwned", "`id`", "$(id)", "*", "back\\slash", ""}

// printfArgv prints each argument followed by "|".
func printfArgv() []string { return append([]string{"printf", "%s|"}, hostileArgs...) }

func wantPrinted() string { return strings.Join(hostileArgs, "|") + "|" }

// noShell makes detectShell fail, as in an image without /bin/sh.
func noShell(t *testing.T) {
	t.Helper()
	oldStat, oldLook := statFn, lookPathFn
	t.Cleanup(func() { statFn, lookPathFn = oldStat, oldLook })
	statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	lookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
}

// writeProgram writes an executable shell script named name into dir.
func writeProgram(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateArgvRequest(t *testing.T) {
	for _, tc := range []struct {
		hasCommand bool
		argv       []string
		want       string
	}{
		{true, nil, ""},
		{false, []string{"ls", "-l"}, ""},
		{true, []string{"ls"}, "set command or argv, not both"},
		{false, nil, "command is required"},
		{false, []string{}, "command is required"},
		{false, []string{""}, "argv[0] must name the program to run"},
		{false, []string{"  ", "x"}, "argv[0] must name the program to run"},
		{false, []string{"-c", "id"}, "argv[0] must name the program to run, not an option"},
		{false, []string{"./-odd"}, ""},
	} {
		if got := validateArgvRequest(tc.hasCommand, tc.argv); got != tc.want {
			t.Errorf("validateArgvRequest(%v, %q) = %q, want %q", tc.hasCommand, tc.argv, got, tc.want)
		}
	}
}

func TestShellArgv(t *testing.T) {
	got := shellArgv("/bin/sh", false, []string{"ls", "a b"})
	if !slices.Equal(got, []string{"/bin/sh", "-c", `exec "$@"`, "sh", "ls", "a b"}) {
		t.Fatalf("stream argv = %q", got)
	}
	got = shellArgv("/bin/bash", true, []string{"ls"})
	if !slices.Equal(got, []string{"/bin/bash", "-lc", loginshell.Prefix(`exec "$@"`), "sh", "ls"}) {
		t.Fatalf("login argv = %q", got)
	}
}

func TestArgvSearchPath(t *testing.T) {
	env := []string{"PATH=/toolboxd/bin", loginshell.Env + "=/image/old", "X=1", loginshell.Env + "=/image/bin"}
	if got := argvSearchPath(env, map[string]string{"PATH": "/req/bin"}); got != "/req/bin" {
		t.Fatalf("request PATH not first: %q", got)
	}
	if got := argvSearchPath(env, nil); got != "/image/bin" {
		t.Fatalf("image PATH (last entry) not used: %q", got)
	}
	if got := argvSearchPath([]string{"PATH=/a", "PATH=/b"}, map[string]string{"PATH": ""}); got != "/b" {
		t.Fatalf("fallback PATH = %q", got)
	}
	if got := lastEnv([]string{"NOEQUALS", "K=v=w"}, "K"); got != "v=w" {
		t.Fatalf("lastEnv = %q", got)
	}
}

func TestResolveArgvProgram(t *testing.T) {
	bin := t.TempDir()
	prog := writeProgram(t, bin, "prog", "exit 0")
	if err := os.WriteFile(filepath.Join(bin, "plain"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(bin, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	writeProgram(t, other, "prog", "exit 1")
	for _, tc := range []struct {
		name, path, workdir string
		want                string
		code                int
		stderr              string
	}{
		{name: "prog", path: bin, want: prog},
		{name: "prog", path: "::relative:" + bin + ":" + other, want: prog},
		{name: "prog", path: other + ":" + bin, want: filepath.Join(other, "prog")},
		{name: "missing", path: bin, code: 127, stderr: "missing: not found\n"},
		{name: "plain", path: bin, code: 127, stderr: "plain: not found\n"},
		{name: "folder", path: bin, code: 127, stderr: "folder: not found\n"},
		{name: prog, want: prog},
		{name: "./prog", workdir: bin, want: "./prog"},
		{name: bin + "/missing", code: 127, stderr: bin + "/missing: not found\n"},
		{name: bin + "/plain", code: 126, stderr: bin + "/plain: permission denied\n"},
		{name: bin + "/folder", code: 126, stderr: bin + "/folder: is a directory\n"},
	} {
		t.Run(tc.name+" in "+tc.path, func(t *testing.T) {
			path, code, stderr := resolveArgvProgram(tc.name, tc.path, tc.workdir)
			if path != tc.want || code != tc.code || stderr != tc.stderr {
				t.Fatalf("got %q %d %q, want %q %d %q", path, code, stderr, tc.want, tc.code, tc.stderr)
			}
		})
	}
}

func TestArgvStartFailure(t *testing.T) {
	enoent := &fs.PathError{Op: "fork/exec", Path: "/x", Err: syscall.ENOENT}
	eacces := &fs.PathError{Op: "fork/exec", Path: "/x", Err: syscall.EACCES}
	if _, _, ok := argvStartFailure("x", "/definitely/missing/workdir", enoent); ok {
		t.Fatal("a missing workdir must keep its own error")
	}
	if code, stderr, ok := argvStartFailure("x", t.TempDir(), enoent); !ok || code != 127 || stderr != "x: not found\n" {
		t.Fatalf("ENOENT = %d %q %v", code, stderr, ok)
	}
	if code, stderr, ok := argvStartFailure("x", "", eacces); !ok || code != 126 || stderr != "x: permission denied\n" {
		t.Fatalf("EACCES = %d %q %v", code, stderr, ok)
	}
	if code, stderr, ok := argvStartFailure("x", "", errors.New("odd")); !ok || code != 126 || stderr != "x: odd\n" {
		t.Fatalf("other = %d %q %v", code, stderr, ok)
	}
}

// E2: argv reaches the program without shell parsing, on an image with a
// shell (the login shell runs only `exec "$@"`).
func TestExecArgvSkipsShellParsing(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	code, res, body := execRequestWith(t, newExecTestServer(), models.ExecRequest{Argv: printfArgv(), TimeoutSeconds: 10})
	if code != http.StatusOK || res.Stdout != wantPrinted() || res.ExitCode != 0 {
		t.Fatalf("exec = %d stdout %q exit %d (%s), want %q", code, res.Stdout, res.ExitCode, body, wantPrinted())
	}
	// The program's own exit status comes back (exec replaced the shell).
	if _, res, _ := execRequestWith(t, newExecTestServer(), models.ExecRequest{Argv: []string{"sh", "-c", "exit 5"}}); res.ExitCode != 5 {
		t.Fatalf("exit = %d, want 5", res.ExitCode)
	}
	// Output caps apply to argv like to a command.
	if _, res, _ := execRequestWith(t, newExecTestServer(), models.ExecRequest{Argv: []string{"printf", "abcdef"}, MaxStdoutBytes: 3}); res.Stdout != "abc" || !res.StdoutTruncated {
		t.Fatalf("capped argv = %q truncated %v", res.Stdout, res.StdoutTruncated)
	}
}

// E2: argv finds the same programs a command does, including the PATH the
// login profile resets and toolboxd puts back (the image's, or the
// request's), not only toolboxd's own.
func TestExecArgvFindsTheSameProgramsAsACommand(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	imageBin := t.TempDir()
	writeProgram(t, imageBin, "uc382tool", `printf 'tool:%s' "$1"`)
	t.Setenv(loginshell.Env, imageBin+":/usr/bin:/bin")
	s := newExecTestServer()
	for _, req := range []models.ExecRequest{
		{Command: "uc382tool 'a b'"},
		{Argv: []string{"uc382tool", "a b"}},
	} {
		_, res, body := execRequestWith(t, s, req)
		if res.Stdout != "tool:a b" || res.ExitCode != 0 {
			t.Fatalf("%+v: stdout %q exit %d (%s)", req, res.Stdout, res.ExitCode, body)
		}
	}
	reqBin := t.TempDir()
	writeProgram(t, reqBin, "uc382req", `printf req`)
	_, res, _ := execRequestWith(t, s, models.ExecRequest{Argv: []string{"uc382req"}, Env: map[string]string{"PATH": reqBin + ":/usr/bin:/bin"}})
	if res.Stdout != "req" {
		t.Fatalf("request PATH not used: %+v", res)
	}
}

func TestExecArgvMissingProgramWithAShell(t *testing.T) {
	_, res, _ := execRequestWith(t, newExecTestServer(), models.ExecRequest{Argv: []string{"uc383-no-such-program", "x"}})
	if res.ExitCode != 127 || !strings.Contains(res.Stderr, "not found") {
		t.Fatalf("missing program = exit %d stderr %q, want 127 and not found", res.ExitCode, res.Stderr)
	}
}

func TestExecArgvBadRequests(t *testing.T) {
	for _, tc := range []struct {
		req  models.ExecRequest
		want string
	}{
		{models.ExecRequest{Command: "ls", Argv: []string{"ls"}}, "set command or argv, not both"},
		{models.ExecRequest{}, "command is required"},
		{models.ExecRequest{Argv: []string{""}}, "argv[0] must name the program to run"},
		{models.ExecRequest{Argv: []string{"-l"}}, "not an option"},
	} {
		code, _, body := execRequestWith(t, newExecTestServer(), tc.req)
		if code != http.StatusBadRequest || !strings.Contains(body, tc.want) {
			t.Fatalf("%+v = %d %s, want 400 %q", tc.req, code, body, tc.want)
		}
	}
}

// E2 with no shell in the image: argv[0] is looked up on the image's PATH
// (never toolboxd's own) and run directly; a missing program answers like a
// shell would.
func TestExecArgvWithoutAShell(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	imageBin := t.TempDir()
	writeProgram(t, imageBin, "uc382direct", `printf 'direct:%s' "$1"`)
	if err := os.WriteFile(filepath.Join(imageBin, "noexec"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badInterp := filepath.Join(imageBin, "badinterp")
	if err := os.WriteFile(badInterp, []byte("#!/definitely/missing/interpreter\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(loginshell.Env, imageBin)
	noShell(t)
	s := newExecTestServer()

	// The image PATH, not toolboxd's: imageBin is not on toolboxd's PATH.
	_, res, body := execRequestWith(t, s, models.ExecRequest{Argv: []string{"uc382direct", "a b; $X"}})
	if res.Stdout != "direct:a b; $X" || res.ExitCode != 0 {
		t.Fatalf("direct = %+v (%s)", res, body)
	}
	_, res, _ = execRequestWith(t, s, models.ExecRequest{Argv: printfArgv(), Env: map[string]string{"PATH": "/usr/bin:/bin"}})
	if res.Stdout != wantPrinted() {
		t.Fatalf("direct printf = %q, want %q", res.Stdout, wantPrinted())
	}

	for _, tc := range []struct {
		name   string
		argv   []string
		code   int
		stderr string
	}{
		{"missing", []string{"uc383-missing"}, 127, "uc383-missing: not found\n"},
		{"not executable", []string{filepath.Join(imageBin, "noexec")}, 126, filepath.Join(imageBin, "noexec") + ": permission denied\n"},
		{"interpreter missing", []string{badInterp}, 127, badInterp + ": not found\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, res, body := execRequestWith(t, s, models.ExecRequest{Argv: tc.argv})
			if code != http.StatusOK || res.ExitCode != tc.code || res.Stderr != tc.stderr {
				t.Fatalf("got %d exit %d stderr %q (%s), want exit %d %q", code, res.ExitCode, res.Stderr, body, tc.code, tc.stderr)
			}
		})
	}

	// A missing working folder keeps the error a command gets (ER2).
	if code, _, body := execRequestWith(t, s, models.ExecRequest{Argv: []string{"uc382direct"}, WorkDir: "/definitely/missing/workdir"}); code != http.StatusInternalServerError {
		t.Fatalf("missing workdir = %d %s, want 500", code, body)
	}
	// A command string still needs a shell, as before.
	if code, _, body := execRequestWith(t, s, models.ExecRequest{Command: "true"}); code != http.StatusInternalServerError {
		t.Fatalf("command without a shell = %d %s, want 500", code, body)
	}
}

// streamRun sends a start message and collects output until the exit (or
// an error control message).
func streamRun(t *testing.T, start map[string]any) (stdout, stderr string, exit execStreamControlOut) {
	t.Helper()
	conn := dialExecStream(t, newExecStreamTestServer(t))
	if err := conn.WriteJSON(start); err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var out, errOut strings.Builder
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (stdout %q stderr %q)", err, out.String(), errOut.String())
		}
		if msgType == websocket.BinaryMessage && len(payload) > 0 {
			if payload[0] == streamFramePrefixStderr {
				errOut.Write(payload[1:])
			} else {
				out.Write(payload[1:])
			}
			continue
		}
		var ctrl execStreamControlOut
		if err := json.Unmarshal(payload, &ctrl); err == nil && (ctrl.Type == "exit" || ctrl.Type == "error") {
			return out.String(), errOut.String(), ctrl
		}
	}
}

// E2 on the exec stream: argv runs through a plain `sh -c 'exec "$@"'`,
// or directly without a shell, in pipe and terminal mode.
func TestExecStreamArgv(t *testing.T) {
	stdout, _, exit := streamRun(t, map[string]any{"argv": printfArgv()})
	if stdout != wantPrinted() || exit.Type != "exit" || exit.Code != 0 {
		t.Fatalf("pipes = %q %+v, want %q", stdout, exit, wantPrinted())
	}
	stdout, _, exit = streamRun(t, map[string]any{"argv": []string{"printf", "%s", "a b"}, "tty": true})
	if !strings.Contains(stdout, "a b") || exit.Code != 0 {
		t.Fatalf("tty = %q %+v", stdout, exit)
	}
	_, stderr, exit := streamRun(t, map[string]any{"argv": []string{"uc383-no-such-program"}})
	if exit.Code != 127 || !strings.Contains(stderr, "not found") {
		t.Fatalf("missing with a shell = %+v stderr %q", exit, stderr)
	}
	for _, tc := range []struct {
		start map[string]any
		want  string
	}{
		{map[string]any{"command": "ls", "argv": []string{"ls"}}, "set command or argv, not both"},
		{map[string]any{}, "command is required"},
		{map[string]any{"argv": []string{"-c"}}, "not an option"},
	} {
		_, _, ctrl := streamRun(t, tc.start)
		if ctrl.Type != "error" || !strings.Contains(ctrl.Message, tc.want) {
			t.Fatalf("%v = %+v, want error %q", tc.start, ctrl, tc.want)
		}
	}
}

func TestExecStreamArgvWithoutAShell(t *testing.T) {
	imageBin := t.TempDir()
	writeProgram(t, imageBin, "uc382stream", `printf 'stream:%s' "$1"`)
	t.Setenv(loginshell.Env, imageBin)
	noShell(t)

	stdout, _, exit := streamRun(t, map[string]any{"argv": []string{"uc382stream", "a b"}})
	if stdout != "stream:a b" || exit.Code != 0 {
		t.Fatalf("direct = %q %+v", stdout, exit)
	}
	_, stderr, exit := streamRun(t, map[string]any{"argv": []string{"uc383-missing"}})
	if exit.Type != "exit" || exit.Code != 127 || stderr != "uc383-missing: not found\n" {
		t.Fatalf("missing = %+v stderr %q", exit, stderr)
	}
	stdout, _, exit = streamRun(t, map[string]any{"argv": []string{"uc383-missing"}, "tty": true})
	if exit.Code != 127 || stdout != "uc383-missing: not found\n" {
		t.Fatalf("missing in a terminal = %+v stdout %q", exit, stdout)
	}
	// A command string still reports the missing shell.
	_, _, ctrl := streamRun(t, map[string]any{"command": "true"})
	if ctrl.Type != "error" {
		t.Fatalf("command without a shell = %+v", ctrl)
	}
}

func TestVersionListsExecArgv(t *testing.T) {
	if _, ok := toolboxFeatures["exec.argv"]; !ok || !slices.Contains(featureList(), "exec.argv") {
		t.Fatalf("features = %v, want exec.argv", featureList())
	}
}
