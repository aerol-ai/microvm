package wasm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The WASM toolbox runs in sandboxd, on the host. Its session routes used to
// hand the caller's command to a toolboxd sessions Manager, which started it
// with a host shell as the daemon user. Driven through ServeToolbox (the path
// the v1, SSH, Daytona and Runloop surfaces reach), every session route must
// now answer 501, build no Manager, and run nothing: the command each request
// carries would touch a marker file on the host.
func TestServeToolboxRefusesSessionRoutes(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	workDir := filepath.Join(runDir, "sb-sess")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.mu.Lock()
	d.byID["sb-sess"] = &sandboxInstance{
		sandboxID: "sb-sess",
		workDir:   workDir,
		status:    models.SandboxStatusStarted,
	}
	d.mu.Unlock()

	marker := filepath.Join(dir, "host-marker")
	touch := "touch " + marker
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/sessions", `{"name":"s1","command":"` + touch + `"}`},
		{http.MethodPost, "/process/session", `{"sessionId":"s1"}`},
		{http.MethodPost, "/process/session/s1/exec", `{"command":"` + touch + `"}`},
		{http.MethodPost, "/process/session/s1/exec", `{"command":"` + touch + `","runAsync":true}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		d.ServeToolbox(req.Context(), "sb-sess", "tok", rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501 (body %q)", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	// The Manager made its recording dir on construction, so its absence
	// shows no Manager was ever built for this sandbox.
	if _, err := os.Stat(filepath.Join(workDir, ".aerol-sessions")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("session recording dir exists (stat err %v): a session manager was built", err)
	}
	// A started command would have written the marker within milliseconds;
	// give a background (runAsync) one a short window before calling it.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("a session command ran on the host and wrote the marker file")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
