package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Code-run on WASM (issue #535): POST /process/code-run runs the snippet
// with the language's standard module (python.wasm, QuickJS, ruby.wasm) as
// a confined run in the sandbox's worker, on the sandbox's /work. Request
// and response match toolboxd's (cmd/toolboxd/daytona_code_run.go), so the
// Daytona SDK's process.codeRun works the same on every runtime. The code is
// handed to the interpreter as an argument (python -c, qjs -e, ruby -e), so
// nothing is written to /work and nothing runs on the host.

// codeRunRequest is toolboxd's daytonaCodeRunRequest.
type codeRunRequest struct {
	Code     string            `json:"code"`
	Language string            `json:"language"`
	Argv     []string          `json:"argv,omitempty"`
	Envs     map[string]string `json:"envs,omitempty"`
	// Timeout is in seconds; 0 uses the node's wasm wall timeout.
	Timeout int `json:"timeout,omitempty"`
}

// codeRunResponse is toolboxd's daytonaCodeRunResponse: the SDK reads
// exitCode and result (stdout, or stderr when stdout is empty).
type codeRunResponse struct {
	ExitCode int    `json:"exitCode"`
	Result   string `json:"result"`
}

var (
	// codeRunMaxBody bounds the request; the code travels inside the run's
	// arguments, which the worker protocol caps at 16 MiB per frame.
	codeRunMaxBody int64 = 8 << 20
	// codeRunMaxOutput caps each of stdout and stderr: sandboxd, not the
	// sandbox, holds the output until the run ends.
	codeRunMaxOutput int64 = 10 << 20
)

func (h *Host) handleCodeRun(w http.ResponseWriter, r *http.Request) {
	if h.procs == nil {
		writeError(w, http.StatusNotImplemented, "code-run is not available for this wasm sandbox")
		return
	}
	var req codeRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, codeRunMaxBody)).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("code-run request is larger than %d bytes", codeRunMaxBody))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	timeout := time.Duration(req.Timeout) * time.Second
	st, err := h.procs.StartCodeRun(r.Context(), CodeRunSpec{
		Language:       req.Language,
		Code:           req.Code,
		Argv:           req.Argv,
		Env:            req.Envs,
		Timeout:        timeout,
		MaxOutputBytes: codeRunMaxOutput,
	})
	if err != nil {
		writeError(w, processErrorStatus(err), err.Error())
		return
	}
	defer st.Close()
	// A client that goes away takes its run with it.
	stop := context.AfterFunc(r.Context(), func() { _ = st.Kill(); _ = st.Close() })
	defer stop()

	var stdout, stderr strings.Builder
	for {
		ev, err := st.Recv()
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			writeError(w, http.StatusInternalServerError, "code-run ended without an exit: "+err.Error())
			return
		}
		if ev.Exit == nil {
			stdout.Write(ev.Stdout)
			stderr.Write(ev.Stderr)
			continue
		}
		errText := stderr.String()
		switch {
		case ev.Exit.TimedOut:
			errText = joinLines(errText, fmt.Sprintf("code-run timed out after %s", timeoutText(timeout)))
		case ev.Exit.Killed:
			errText = joinLines(errText, "code-run was killed")
		case ev.Exit.Error != "":
			errText = joinLines(errText, ev.Exit.Error)
		}
		// Same rule as toolboxd: the SDK shows only result, so a run with
		// no stdout reports its stderr there instead of an empty string.
		result := stdout.String()
		if result == "" {
			result = errText
		}
		writeJSON(w, http.StatusOK, codeRunResponse{ExitCode: ev.Exit.ExitCode, Result: result})
		return
	}
}

func timeoutText(d time.Duration) string {
	if d <= 0 {
		return "the wasm wall timeout"
	}
	return d.String()
}

func joinLines(a, b string) string {
	if a == "" {
		return b
	}
	if !strings.HasSuffix(a, "\n") {
		a += "\n"
	}
	return a + b
}
