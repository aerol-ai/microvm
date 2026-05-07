package models

import "time"

// SessionStatus is the lifecycle stage of a long-running command session
// inside a sandbox container.
type SessionStatus string

const (
	SessionStatusRunning  SessionStatus = "running"
	SessionStatusExited   SessionStatus = "exited"
	SessionStatusKilled   SessionStatus = "killed"
	SessionStatusFailed   SessionStatus = "failed" // could not start
)

// CreateSessionRequest is the body of POST /sessions on toolboxd (and the
// shape the sandboxd proxy forwards). Either Argv or Command may be supplied;
// Command is run via `sh -c` for convenience.
type CreateSessionRequest struct {
	// Name is the human-friendly session label. Two callers asking for the
	// same Name see the same session (idempotent attach). Default "default".
	Name    string            `json:"name,omitempty"`
	Argv    []string          `json:"argv,omitempty"`
	Command string            `json:"command,omitempty"`
	WorkDir string            `json:"workdir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	PTY     bool              `json:"pty,omitempty"`
	Cols    int               `json:"cols,omitempty"`
	Rows    int               `json:"rows,omitempty"`
}

// Session is the metadata view of a session — never includes its output.
type Session struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Argv       []string      `json:"argv"`
	WorkDir    string        `json:"workdir,omitempty"`
	PTY        bool          `json:"pty"`
	Status     SessionStatus `json:"status"`
	ExitCode   int           `json:"exit_code"`
	ExitSignal string        `json:"exit_signal,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	StartedAt  time.Time     `json:"started_at"`
	ExitedAt   time.Time     `json:"exited_at,omitempty"`
	Recording  bool          `json:"recording"`
	Bytes      int64         `json:"bytes"`     // total stdout+stderr bytes produced
	Attached   int           `json:"attached"`  // current number of attached clients
}

// SessionList is the GET /sessions response shape.
type SessionList struct {
	Sessions []Session `json:"sessions"`
}

// SessionSignalRequest is the POST /sessions/{id}/signal body. Signal is one
// of INT, TERM, KILL, HUP, QUIT (or the SIG*-prefixed forms).
type SessionSignalRequest struct {
	Signal string `json:"signal"`
}

// SessionResizeRequest is the POST /sessions/{id}/resize body.
type SessionResizeRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}
