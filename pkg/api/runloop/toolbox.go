package runloop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// maxToolboxResponse caps a decoded toolbox JSON answer. Command logs are
// the large ones; output past this fails the read rather than sandboxd.
const maxToolboxResponse = 64 << 20

// toolboxError is a non-2xx answer from the in-sandbox toolbox.
type toolboxError struct {
	status  int
	message string
}

func (e *toolboxError) Error() string {
	return fmt.Sprintf("toolbox returned %d: %s", e.status, e.message)
}

func isToolboxNotFound(err error) bool {
	var tbErr *toolboxError
	return errors.As(err, &tbErr) && tbErr.status == http.StatusNotFound
}

// Wire shapes of toolboxd's session API (cmd/toolboxd/daytona_process.go).
type toolboxCommand struct {
	Command  string `json:"command"`
	ExitCode *int32 `json:"exitCode,omitempty"`
	ID       string `json:"id"`
}

type toolboxSession struct {
	SessionID string           `json:"sessionId"`
	Commands  []toolboxCommand `json:"commands"`
}

type toolboxCommandLogs struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

func (h *handlers) toolboxCall(ctx context.Context, devboxID, method, path string, query url.Values, body any, out any) (int, error) {
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(payload)
		headers.Set("Content-Type", "application/json")
	}
	resp, err := h.deps.Service.RoundTripToolbox(ctx, devboxID, method, path, query, reader, headers)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return resp.StatusCode, readToolboxError(resp)
	}
	if out != nil {
		// The toolbox runs inside the sandbox, so its answers are guest
		// controlled: bound what sandboxd will decode into memory.
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxToolboxResponse)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode toolbox response: %w", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode, nil
}

func readToolboxError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(raw))
	var body models.ErrorResponse
	if json.Unmarshal(raw, &body) == nil && body.Error != "" {
		message = body.Error
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	return &toolboxError{status: resp.StatusCode, message: message}
}

// createSession opens toolbox session sid, reporting whether this call
// created it. The 201-vs-200 split is atomic inside toolboxd, which is what
// makes it a claim: of several requests racing to start the same
// execution, exactly one sees created=true and runs the command.
func (h *handlers) createSession(ctx context.Context, devboxID, sid string) (bool, error) {
	status, err := h.toolboxCall(ctx, devboxID, http.MethodPost, "/process/session", nil, map[string]string{"sessionId": sid}, nil)
	if err != nil {
		return false, err
	}
	return status == http.StatusCreated, nil
}

func (h *handlers) sessionExec(ctx context.Context, devboxID, sid, command string) (string, error) {
	var out struct {
		CmdID string `json:"cmdId"`
	}
	if _, err := h.toolboxCall(ctx, devboxID, http.MethodPost, "/process/session/"+sid+"/exec", nil, map[string]any{"command": command, "runAsync": true}, &out); err != nil {
		return "", err
	}
	if out.CmdID == "" {
		return "", errors.New("toolbox did not return a command id")
	}
	return out.CmdID, nil
}

func (h *handlers) getSession(ctx context.Context, devboxID, sid string) (*toolboxSession, error) {
	var out toolboxSession
	if _, err := h.toolboxCall(ctx, devboxID, http.MethodGet, "/process/session/"+sid, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (h *handlers) getCommand(ctx context.Context, devboxID, sid, cid string) (*toolboxCommand, error) {
	var out toolboxCommand
	if _, err := h.toolboxCall(ctx, devboxID, http.MethodGet, "/process/session/"+sid+"/command/"+cid, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (h *handlers) commandLogs(ctx context.Context, devboxID, sid, cid string) (*toolboxCommandLogs, error) {
	var out toolboxCommandLogs
	if _, err := h.toolboxCall(ctx, devboxID, http.MethodGet, "/process/session/"+sid+"/command/"+cid+"/logs", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (h *handlers) deleteSession(ctx context.Context, devboxID, sid string) error {
	_, err := h.toolboxCall(ctx, devboxID, http.MethodDelete, "/process/session/"+sid, nil, nil, nil)
	if isToolboxNotFound(err) {
		return nil
	}
	return err
}

func (h *handlers) sendSessionInput(ctx context.Context, devboxID, sid, cid, data string) error {
	_, err := h.toolboxCall(ctx, devboxID, http.MethodPost, "/process/session/"+sid+"/command/"+cid+"/input", nil, map[string]string{"data": data}, nil)
	return err
}

// runOneShot runs a short command through /process/execute.
func (h *handlers) runOneShot(ctx context.Context, devboxID, command string) (*models.ExecResult, error) {
	var out models.ExecResult
	if _, err := h.toolboxCall(ctx, devboxID, http.MethodPost, "/process/execute", nil, models.ExecRequest{Command: command, TimeoutSeconds: 10}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// writeToolboxError maps a toolbox failure onto the response. A toolbox
// 4xx is the caller's problem and passes through. Service sentinels (an
// unknown or stopped devbox) keep their usual mapping. Anything else means
// the toolbox could not be reached or failed: 502, which the SDK retries.
func (h *handlers) writeToolboxError(w http.ResponseWriter, err error) {
	var tbErr *toolboxError
	switch {
	case errors.As(err, &tbErr) && tbErr.status >= 400 && tbErr.status < 500:
		WriteError(w, tbErr.status, tbErr.message)
		return
	case errors.As(err, new(requestError)),
		errors.Is(err, store.ErrNotFound),
		errors.Is(err, service.ErrSandboxManuallyStopped),
		errors.Is(err, service.ErrWakeCircuitOpen):
		writeStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if h.deps.Logger != nil {
		h.deps.Logger.Warn("runloop toolbox request failed", "error", err)
	}
	WriteError(w, http.StatusBadGateway, "devbox toolbox unavailable")
}
