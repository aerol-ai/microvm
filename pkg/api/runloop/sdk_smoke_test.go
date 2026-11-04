//go:build runloop_sdk

package runloop

// The real-SDK check: installs the official Runloop SDKs and drives the
// facade with them. It needs node, python3 and network access, so it is
// tag-gated out of `make test`:
//
//	go test -tags runloop_sdk -run TestRealSDKSmoke -v ./pkg/api/runloop/
//
// RUNLOOP_TS_SDK_VERSION / RUNLOOP_PY_SDK_VERSION test a newer SDK release
// before claiming compatibility with it.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRealSDKSmoke(t *testing.T) {
	tsVersion := envOr("RUNLOOP_TS_SDK_VERSION", "2.0.0")
	pyVersion := envOr("RUNLOOP_PY_SDK_VERSION", "2.0.0")
	scripts, err := filepath.Abs(filepath.Join("testdata", "sdk-smoke"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	runIn := func(dir string, env []string, argv ...string) {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		t.Logf("%s:\n%s", strings.Join(argv, " "), out)
		if err != nil {
			t.Fatalf("%s: %v", strings.Join(argv, " "), err)
		}
	}
	runIn(work, nil, "npm", "init", "-y")
	runIn(work, nil, "npm", "install", "--silent", "@runloop/api-client@"+tsVersion)
	runIn(work, nil, "python3", "-m", "venv", "venv")
	runIn(work, nil, filepath.Join(work, "venv", "bin", "pip"), "install", "-q", "runloop_api_client=="+pyVersion)
	for _, name := range []string{"smoke.mjs", "smoke.py"} {
		raw, err := os.ReadFile(filepath.Join(scripts, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	env := newTestEnv(t)
	var mu sync.Mutex
	protos := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos[r.Proto]++
		mu.Unlock()
		env.handler.ServeHTTP(w, r)
	}))
	// The daemon's listener protocols: the TS SDK on Node speaks h2c to an
	// http:// base URL and fails outright against HTTP/1.1 only.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &protocols
	srv.Start()
	t.Cleanup(srv.Close)

	sdkEnv := []string{"RUNLOOP_BASE_URL=" + srv.URL + PathPrefix, "RUNLOOP_API_KEY=smoke"}
	runIn(work, sdkEnv, "node", "smoke.mjs")
	runIn(work, sdkEnv, filepath.Join(work, "venv", "bin", "python"), "smoke.py")
	if protos["HTTP/2.0"] == 0 {
		t.Fatalf("no HTTP/2 requests seen (%v): the TS SDK fell back or the h2c path went untested", protos)
	}
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
