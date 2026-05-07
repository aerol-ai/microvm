package types

type StreamCallback func([]byte)
type StreamErrorCallback func(string)

type ExecStreamOptions struct {
	Command  string              `json:"command"`
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
