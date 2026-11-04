package agenttools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Process is a background command running in a session.
type Process struct {
	SessionID  string `json:"session_id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code,omitempty"`
	ExitSignal string `json:"exit_signal,omitempty"`
}

// ProcessLogs is the tail of a background command's output.
type ProcessLogs struct {
	Process
	Output       string `json:"output"`
	Truncated    bool   `json:"truncated,omitempty"`
	DroppedBytes int64  `json:"dropped_bytes,omitempty"`
}

// StartProcess runs command in a new session that outlives this call (a dev
// server, a watcher). Sessions are how work survives a dropped connection;
// exec streams are killed when their connection drops.
//
// Each call gets its own session name: sessions with the same name are the
// same session, so a fixed name would make a second start return the first
// process.
func (t *Tools) StartProcess(ctx context.Context, sb *microvm.Sandbox, command, cwd string, env map[string]string) (Process, error) {
	if strings.TrimSpace(command) == "" {
		return Process{}, newError(CodeInvalidArgument, "command is required")
	}
	if err := RequireShell(sb); err != nil {
		return Process{}, err
	}
	name, err := processName()
	if err != nil {
		return Process{}, Classify(err)
	}
	session, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{Name: name, Command: command, WorkDir: cwd, Env: env})
	if err != nil {
		return Process{}, Classify(err)
	}
	return processFromSession(session), nil
}

// ProcessLogs returns a background command's status and the head/tail of
// its recorded output, within maxBytes (0 means DefaultMaxOutputBytes). The
// session keeps at most its replay buffer (1 MiB by default) on the server.
func (t *Tools) ProcessLogs(ctx context.Context, sb *microvm.Sandbox, sessionID string, maxBytes int) (ProcessLogs, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ProcessLogs{}, newError(CodeInvalidArgument, "session_id is required")
	}
	session, err := sb.GetSession(ctx, sessionID)
	if err != nil {
		return ProcessLogs{}, sessionError(err, sessionID)
	}
	raw, err := sb.SessionLog(ctx, sessionID)
	if err != nil {
		return ProcessLogs{}, sessionError(err, sessionID)
	}
	out := ProcessLogs{Process: processFromSession(session)}
	out.Output, out.Truncated, out.DroppedBytes = boundText(string(raw), maxBytes)
	return out, nil
}

// StopProcess kills a background command and removes its session. Stopping
// one that is already gone succeeds, so a retry is harmless.
func (t *Tools) StopProcess(ctx context.Context, sb *microvm.Sandbox, sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return newError(CodeInvalidArgument, "session_id is required")
	}
	if err := sb.DeleteSession(ctx, sessionID); err != nil && !errors.Is(err, microvm.ErrNotFound) {
		return sessionError(err, sessionID)
	}
	return nil
}

func processFromSession(s models.Session) Process {
	return Process{
		SessionID:  s.ID,
		Name:       s.Name,
		Status:     string(s.Status),
		ExitCode:   s.ExitCode,
		ExitSignal: s.ExitSignal,
	}
}

func processName() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "proc-" + hex.EncodeToString(buf), nil
}

func sessionError(err error, sessionID string) *Error {
	e := Classify(err)
	if e.Code == CodeNotFound {
		cp := *e
		cp.Message = "no background process with session_id " + quote(sessionID)
		return &cp
	}
	return e
}
