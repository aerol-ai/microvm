package e2b

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestE2BPythonSDKSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping python smoke test in short mode")
	}
	if strings.TrimSpace(os.Getenv("SB_E2B_PYTHON_SMOKE")) != "1" {
		t.Skip("set SB_E2B_PYTHON_SMOKE=1 to run the real Python SDK smoke test")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	sdkPath := strings.TrimSpace(os.Getenv("SB_E2B_PYTHON_SDK_PATH"))
	sdkSpec := strings.TrimSpace(os.Getenv("SB_E2B_PYTHON_SDK_SPEC"))
	if sdkPath == "" && sdkSpec == "" {
		sdkSpec = "e2b==2.21.0"
	}

	venvDir := filepath.Join(t.TempDir(), "venv")
	venvPython := filepath.Join(venvDir, "bin", "python")
	venvPip := filepath.Join(venvDir, "bin", "pip")
	venvCmd := exec.Command(python, "-m", "venv", venvDir)
	if output, err := venvCmd.CombinedOutput(); err != nil {
		t.Fatalf("create python venv error = %v\n%s", err, output)
	}
	installTarget := sdkSpec
	if sdkPath != "" {
		installTarget = sdkPath
	}
	installCmd := exec.Command(venvPip, "install", installTarget)
	if output, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("install python sdk error = %v\n%s", err, output)
	}

	repoRoot := repoRootFromCaller(t)
	toolboxPort := freeTCPPort(t)
	toolboxBin := filepath.Join(t.TempDir(), "toolboxd")
	buildCmd := exec.Command("go", "build", "-o", toolboxBin, "./cmd/toolboxd")
	buildCmd.Dir = repoRoot
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build toolboxd error = %v\n%s", err, output)
	}

	toolboxCtx, toolboxCancel := context.WithCancel(context.Background())
	defer toolboxCancel()
	toolboxCmd := exec.CommandContext(toolboxCtx, toolboxBin)
	toolboxCmd.Env = append(os.Environ(),
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", toolboxPort),
		"SB_RECORDING_DIR="+filepath.Join(t.TempDir(), "recordings"),
	)
	toolboxCmd.Stdout = io.Discard
	toolboxCmd.Stderr = io.Discard
	if err := toolboxCmd.Start(); err != nil {
		t.Fatalf("start toolboxd error = %v", err)
	}
	t.Cleanup(func() {
		toolboxCancel()
		_ = toolboxCmd.Wait()
	})
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/health", toolboxPort), 5*time.Second)

	fakeRuntime := newFakeE2BRuntime()
	fakeRuntime.containerIP = "127.0.0.1"
	svc, _, _ := newE2BHandlerTestEnvWithRuntime(t, fakeRuntime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: toolboxPort})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.TrimSpace(r.Header.Get("X-API-KEY")) != "test-pat" {
					WriteError(w, http.StatusUnauthorized, "Unauthorized")
					return
				}
				next.ServeHTTP(w, r)
			})
		},
	})
	apiServer := httptest.NewServer(mux)
	defer apiServer.Close()

	scriptPath := filepath.Join(repoRoot, "scripts", "e2b_sdk_smoke.py")
	smokeCtx, smokeCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer smokeCancel()
	smokeCmd := exec.CommandContext(smokeCtx, venvPython, scriptPath)
	smokeEnv := append(os.Environ(),
		"E2B_API_URL="+apiServer.URL+PathPrefix,
		"E2B_SANDBOX_URL="+apiServer.URL+PathPrefix+"/runtime",
		"E2B_API_KEY=test-pat",
	)
	smokeCmd.Env = smokeEnv
	output, err := smokeCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python smoke harness failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "E2B SDK smoke passed") {
		t.Fatalf("unexpected python smoke output: %s", output)
	}
}

func repoRootFromCaller(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on ephemeral port error = %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHTTP(t *testing.T, endpoint string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", endpoint)
		}
		resp, err := http.Get(endpoint)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}
