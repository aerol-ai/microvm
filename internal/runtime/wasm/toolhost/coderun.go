package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type codeRunRequest struct {
	Code     string            `json:"code"`
	Language string            `json:"language"`
	Argv     []string          `json:"argv,omitempty"`
	Envs     map[string]string `json:"envs,omitempty"`
	Timeout  int               `json:"timeout,omitempty"`
}

type codeRunResponse struct {
	ExitCode int    `json:"exitCode"`
	Result   string `json:"result"`
}

type codeRunSpec struct {
	suffix string
	cmd    string
	args   []string
}

var codeRunSpecs = map[string]codeRunSpec{
	"python":     {suffix: ".py", cmd: "python3"},
	"python3":    {suffix: ".py", cmd: "python3"},
	"javascript": {suffix: ".js", cmd: "node"},
	"js":         {suffix: ".js", cmd: "node"},
	"node":       {suffix: ".js", cmd: "node"},
	"typescript": {suffix: ".ts", cmd: "ts-node"},
	"ts":         {suffix: ".ts", cmd: "ts-node"},
	"bash":       {suffix: ".sh", cmd: "bash"},
	"sh":         {suffix: ".sh", cmd: "sh"},
	"shell":      {suffix: ".sh", cmd: "sh"},
}

func (h *Host) handleCodeRun(w http.ResponseWriter, r *http.Request) {
	var req codeRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	spec, ok := codeRunSpecs[strings.ToLower(strings.TrimSpace(req.Language))]
	if !ok {
		writeError(w, http.StatusBadRequest, "language not supported: "+req.Language)
		return
	}
	interp, err := exec.LookPath(spec.cmd)
	if err != nil {
		writeError(w, http.StatusBadRequest, "interpreter not installed on host: "+spec.cmd)
		return
	}

	scriptPath, cleanup, err := writeCodeRunScript(h.workDir, req.Code, spec.suffix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer cleanup()

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	args := append([]string{}, spec.args...)
	args = append(args, scriptPath)
	args = append(args, req.Argv...)
	cmd := exec.CommandContext(ctx, interp, args...)
	cmd.Dir = h.workDir
	cmd.Env = append(os.Environ(), envMapToSlice(req.Envs)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var stdoutBytes, stderrBytes []byte
	var readWG sync.WaitGroup
	readWG.Add(2)
	go func() {
		defer readWG.Done()
		stdoutBytes, _ = io.ReadAll(stdout)
	}()
	go func() {
		defer readWG.Done()
		stderrBytes, _ = io.ReadAll(stderr)
	}()
	readWG.Wait()
	waitErr := cmd.Wait()

	exitCode, _ := interpretWaitResult(waitErr)
	stdoutStr := string(stdoutBytes)
	stderrStr := string(stderrBytes)
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) && !errors.Is(waitErr, syscall.ECHILD) {
			stderrStr = strings.TrimSpace(stderrStr + "\n" + waitErr.Error())
		}
	}
	result := stdoutStr
	if result == "" {
		result = stderrStr
	}
	writeJSON(w, http.StatusOK, codeRunResponse{ExitCode: exitCode, Result: result})
}

func writeCodeRunScript(workDir, code, suffix string) (string, func(), error) {
	base := filepath.Join(workDir, ".coderun")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(base, "run-*")
	if err != nil {
		return "", nil, err
	}
	scriptPath := filepath.Join(dir, "script"+suffix)
	if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	return scriptPath, func() { _ = os.RemoveAll(dir) }, nil
}

func envMapToSlice(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func interpretWaitResult(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return 1, err
}
