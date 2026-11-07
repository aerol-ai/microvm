package types

type StreamCallback func([]byte)
type StreamErrorCallback func(string)

type ExecStreamOptions struct {
	Command string `json:"command"`
	// Argv runs a program with these arguments instead of Command, with no
	// shell parsing: spaces, quotes, $ and ; reach the program as written.
	// Set Command or Argv, not both. The sandbox's agent must list
	// exec.argv on /version; an older one fails with
	// ErrUnsupportedFeature before anything runs.
	Argv     []string            `json:"argv,omitempty"`
	Workdir  string              `json:"workdir,omitempty"`
	Env      map[string]string   `json:"env,omitempty"`
	TTY      bool                `json:"tty,omitempty"`
	Cols     int                 `json:"cols,omitempty"`
	Rows     int                 `json:"rows,omitempty"`
	OnStdout StreamCallback      `json:"-"`
	OnStderr StreamCallback      `json:"-"`
	OnError  StreamErrorCallback `json:"-"`
}

type ExecExitInfo struct {
	Code   int    `json:"code"`
	Signal string `json:"signal,omitempty"`
}
