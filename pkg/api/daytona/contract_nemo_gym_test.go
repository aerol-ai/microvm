package daytona

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/options"

	"github.com/aerol-ai/microvm/pkg/models"
)

// NVIDIA NeMo Gym's Daytona provider (plan G5) makes these Daytona SDK calls:
// create, get, refresh, process.exec with a working folder, environment and
// timeout, fs.upload_file, fs.download_file and delete. Create, get and
// delete have cases in contract_test.go. These cases cover the command,
// upload and download calls, end to end through the facade to a toolboxd.

// nemoGymToolbox is a toolboxd that runs each command for real (so the
// working folder and environment are checked however the SDK sends them)
// and keeps uploads in memory.
type nemoGymToolbox struct {
	t       *testing.T
	mu      sync.Mutex
	execs   []models.ExecRequest
	uploads map[string][]byte
}

func newNemoGymToolbox(t *testing.T) *nemoGymToolbox {
	return &nemoGymToolbox{t: t, uploads: map[string][]byte{}}
}

func (b *nemoGymToolbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/process/execute":
		var req models.ExecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.execs = append(b.execs, req)
		b.mu.Unlock()
		cmd := exec.Command("/bin/sh", "-c", req.Command)
		cmd.Dir = req.WorkDir
		cmd.Env = os.Environ()
		for k, v := range req.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			code = -1
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			}
		}
		_ = json.NewEncoder(w).Encode(models.ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code})
	case "/files/upload":
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(file)
		b.mu.Lock()
		b.uploads[r.URL.Query().Get("path")] = data
		b.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case "/files/download":
		b.mu.Lock()
		data, ok := b.uploads[r.URL.Query().Get("path")]
		b.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	default:
		b.t.Errorf("unexpected toolbox call %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func TestDaytonaSDKContractsNeMoGym(t *testing.T) {
	var toolbox *nemoGymToolbox
	newToolbox := func(t *testing.T) http.Handler {
		toolbox = newNemoGymToolbox(t)
		return toolbox
	}
	cases := []contractCase{
		{
			name:    "process_exec_with_cwd_env_and_timeout",
			toolbox: newToolbox,
			run: func(t *testing.T, env *daytonaContractEnv) {
				workDir := t.TempDir()
				sandbox := nemoGymContractSandbox(t, env, "nemo-exec")
				result, err := sandbox.Process.ExecuteCommand(env.ctx, `printf '%s|%s' "$FOO" "$(pwd)"; exit 3`,
					options.WithCwd(workDir),
					options.WithCommandEnv(map[string]string{"FOO": "bar"}),
					options.WithExecuteTimeout(7*time.Second),
				)
				if err != nil {
					t.Fatalf("ExecuteCommand error = %v", err)
				}
				// The exit code and output come back, and the command ran in
				// the folder and with the variable NeMo Gym asked for. pwd
				// prints the folder with its symlinks resolved.
				resolved, err := filepath.EvalSymlinks(workDir)
				if err != nil {
					t.Fatal(err)
				}
				if result.ExitCode != 3 || result.Result != "bar|"+resolved {
					t.Fatalf("ExecuteCommand = exit %d result %q, want exit 3 and %q", result.ExitCode, result.Result, "bar|"+resolved)
				}
				if got := toolbox.execs[len(toolbox.execs)-1].TimeoutSeconds; got != 7 {
					t.Fatalf("toolboxd got timeout_seconds %d, want 7", got)
				}
			},
		},
		{
			name:    "fs_upload_file_to_an_absolute_path",
			toolbox: newToolbox,
			run: func(t *testing.T, env *daytonaContractEnv) {
				sandbox := nemoGymContractSandbox(t, env, "nemo-upload")
				if err := sandbox.FileSystem.UploadFile(env.ctx, []byte("task data"), "/workspace/task/input.txt"); err != nil {
					t.Fatalf("UploadFile error = %v", err)
				}
				if got := string(toolbox.uploads["/workspace/task/input.txt"]); got != "task data" {
					t.Fatalf("toolboxd got uploads %v, want /workspace/task/input.txt = %q", toolbox.uploads, "task data")
				}
			},
		},
		{
			// The SDK sends one path to bulk-download and reads the answer
			// part back; the bytes must survive the round trip.
			name:    "fs_download_file_from_an_absolute_path",
			toolbox: newToolbox,
			run: func(t *testing.T, env *daytonaContractEnv) {
				sandbox := nemoGymContractSandbox(t, env, "nemo-download")
				toolbox.uploads["/workspace/task/output.txt"] = []byte("reward=1")
				got, err := sandbox.FileSystem.DownloadFile(env.ctx, "/workspace/task/output.txt", nil)
				if err != nil {
					t.Fatalf("DownloadFile error = %v", err)
				}
				if string(got) != "reward=1" {
					t.Fatalf("DownloadFile = %q, want %q", got, "reward=1")
				}
			},
		},
		{
			// A missing file comes back as the error part, which the SDK
			// turns into an error rather than empty bytes.
			name:    "fs_download_file_that_does_not_exist",
			toolbox: newToolbox,
			run: func(t *testing.T, env *daytonaContractEnv) {
				sandbox := nemoGymContractSandbox(t, env, "nemo-download-missing")
				got, err := sandbox.FileSystem.DownloadFile(env.ctx, "/workspace/task/none.txt", nil)
				if err == nil {
					t.Fatalf("DownloadFile = %q, want an error", got)
				}
				if !strings.Contains(err.Error(), "not found") {
					t.Fatalf("DownloadFile error = %v, want it to say not found", err)
				}
			},
		},
	}
	runContractCases(t, cases)
}

// nemoGymContractSandbox seeds a sandbox whose toolbox is the case's fake and
// opens it with the Daytona SDK.
func nemoGymContractSandbox(t *testing.T, env *daytonaContractEnv, id string) *daytonasdk.Sandbox {
	t.Helper()
	seed := env.seedSandbox(contractSandboxSeed{ID: id, Name: id, ContainerIP: env.toolboxHost})
	sandbox, err := env.sdk.Get(env.ctx, seed.ID)
	if err != nil {
		t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
	}
	return sandbox
}
