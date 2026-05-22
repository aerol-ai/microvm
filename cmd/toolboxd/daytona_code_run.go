package main

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

// daytonaCodeRunRequest mirrors the @daytona/sdk Process.codeRun payload
// (node_modules/@daytona/sdk/esm/Process.js:147-153). The Daytona SDK calls
// POST /process/code-run on the toolbox proxy expecting a temp-file + interpreter
// execution against the language label set at sandbox creation.
type daytonaCodeRunRequest struct {
	Code     string            `json:"code"`
	Language string            `json:"language"`
	Argv     []string          `json:"argv,omitempty"`
	Envs     map[string]string `json:"envs,omitempty"`
	Timeout  int               `json:"timeout,omitempty"`
}

// daytonaCodeRunResponse matches the fields Process.codeRun consumes
// (Process.js:155-164): exitCode + result (stdout). Charts are an
// E2B/Jupyter-only feature; we omit the artifacts envelope and let the SDK
// default it to an empty array client-side.
type daytonaCodeRunResponse struct {
	ExitCode int    `json:"exitCode"`
	Result   string `json:"result"`
}

// codeRunSpec describes how to materialize and execute a code snippet for a
// given language. Cmd is looked up via exec.LookPath at request time so we
// can give a useful error if the interpreter is missing from the image.
type codeRunSpec struct {
	// suffix is the temp-file extension. Some interpreters (notably ts-node)
	// dispatch on file extension, so .ts must be .ts — not .txt.
	suffix string
	// cmd is the interpreter binary name as it appears on PATH.
	cmd string
	// args are flags prepended before the script path. Keep these minimal —
	// users can set their own flags via shebang/env if they need more.
	args []string
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

func (s *server) handleDaytonaCodeRun(w http.ResponseWriter, r *http.Request) {
	var req daytonaCodeRunRequest
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

	// Interpreter must actually be on PATH. ts-node / node / python3 are
	// image-dependent — we surface a 400 instead of letting exec fail
	// opaquely with "no such file or directory".
	interp, err := exec.LookPath(spec.cmd)
	if err != nil {
		writeError(w, http.StatusBadRequest, "interpreter not installed in sandbox: "+spec.cmd)
		return
	}

	scriptPath, cleanup, err := writeCodeRunScript(req.Code, spec.suffix)
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
	// The SDK exposes only `result` (stdout) and `exitCode`. Merge stderr in
	// when stdout is empty so users on a non-zero exit aren't staring at a
	// blank string; otherwise mirror handleExec and discard it. This also
	// preserves the spawn-failure message we appended below.
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
	writeJSON(w, http.StatusOK, daytonaCodeRunResponse{ExitCode: exitCode, Result: result})
}

// writeCodeRunScript drops the snippet into an isolated temp dir so cleanup
// removes both the script and any sibling files the interpreter may write
// (ts-node's .tsbuildinfo, __pycache__, etc.) without us having to enumerate
// them.
func writeCodeRunScript(code, suffix string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "sb-coderun-*")
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
