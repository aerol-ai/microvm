package toolhost

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Executor runs a WASM invocation for toolbox /process/execute.
type Executor interface {
	Exec(r *http.Request, req models.ExecRequest) (models.ExecResult, error)
}

func (h *Host) handleExec(w http.ResponseWriter, r *http.Request) {
	var req models.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	if h.exec == nil {
		writeError(w, http.StatusServiceUnavailable, "exec not configured")
		return
	}
	start := time.Now()
	result, err := h.exec.Exec(r, req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
