package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestHandleExecKeepsTheImagePath: /process/execute runs a login shell,
// whose /etc/profile resets PATH on Alpine and Debian; the image's PATH
// still leads, or the request's when it sets one.
func TestHandleExecKeepsTheImagePath(t *testing.T) {
	t.Setenv(loginshell.Env, "/aerolvm-image/bin:/usr/bin:/bin")
	s := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), allowedPorts: map[int]struct{}{}}
	run := func(env map[string]string) string {
		t.Helper()
		body, _ := json.Marshal(models.ExecRequest{Command: `printf '%s' "$PATH"`, Env: env, TimeoutSeconds: 10})
		rr := httptest.NewRecorder()
		s.handleExec(rr, httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		var res models.ExecResult
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res.Stdout
	}
	if got := run(nil); !strings.HasPrefix(got, "/aerolvm-image/bin:") {
		t.Fatalf("PATH = %q, want the image's first", got)
	}
	if got := run(map[string]string{"PATH": "/req/bin:/usr/bin:/bin"}); !strings.HasPrefix(got, "/req/bin:") {
		t.Fatalf("PATH = %q, want the request's first", got)
	}
}

// TestPrepareLoginShells: startup records the PATH for children and
// installs the profile hook, and an unwritable profile.d is logged, not
// fatal.
func TestPrepareLoginShells(t *testing.T) {
	t.Setenv("PATH", os.Getenv("PATH"))
	t.Setenv(loginshell.Env, "")
	os.Unsetenv(loginshell.Env)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	dir := t.TempDir()
	prepareLoginShells(logger, dir)
	if os.Getenv(loginshell.Env) != os.Getenv("PATH") {
		t.Fatalf("%s = %q", loginshell.Env, os.Getenv(loginshell.Env))
	}
	if _, err := os.Stat(filepath.Join(dir, "00-aerolvm-image-path.sh")); err != nil {
		t.Fatalf("hook: %v", err)
	}
	// No profile.d at all (a distroless image) is not a failure: there is
	// nothing to install, and commands still get the restore themselves.
	prepareLoginShells(logger, filepath.Join(dir, "missing"))
	if strings.Contains(logs.String(), "hook not installed") {
		t.Fatalf("a missing profile.d was logged as a failure: %s", logs.String())
	}
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		prepareLoginShells(logger, ro)
		if !strings.Contains(logs.String(), "hook not installed") {
			t.Fatalf("an unwritable profile.d must be logged: %s", logs.String())
		}
	}
}
