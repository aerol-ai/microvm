// Package toolboxwire holds the wire formats of the toolbox exec stream
// (GET /process/exec/stream) and of the Daytona-compatible process sessions
// (/process/session, session.go), shared by toolboxd (cmd/toolboxd), which
// runs inside container and VM sandboxes, and the WASM toolhost
// (internal/runtime/wasm/toolhost), which runs in sandboxd. Clients see one
// protocol whichever runtime a sandbox uses; keeping its types in one place
// is what keeps the two servers from drifting apart.
//
// The exec stream: the client offers the sandbox.bearer subprotocol, which the
// server echoes. Its first text frame, within StartTimeout, is an
// ExecStreamStart. The server then sends binary frames whose first byte is
// FramePrefixStdout or FramePrefixStderr, and ends with a JSON
// ExecStreamControlOut of type "exit" (or "error"). Client binary frames are
// stdin; client text frames are ExecStreamControlIn ("signal", "resize",
// "close" for end of stdin). Pings and pong deadlines (Liveness) tell a
// silent stream from a dropped one, and a dropped stream kills its command.
package toolboxwire

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// First byte of every server-to-client binary frame. One byte instead of a
// JSON envelope keeps large output cheap.
const (
	FramePrefixStdout byte = 0x01
	FramePrefixStderr byte = 0x02
)

// BearerSubprotocol is echoed when offered: browsers cannot set
// Authorization on a WebSocket, so they smuggle the token as a subprotocol.
const BearerSubprotocol = "sandbox.bearer"

// StartTimeout bounds the wait for the start message, so a stalled client
// cannot hold a connection open.
const StartTimeout = 10 * time.Second

// ExecStreamStart is the client's first message.
type ExecStreamStart struct {
	Command string `json:"command"`
	// Argv runs a program with these arguments instead of Command, with no
	// shell parsing.
	Argv    []string          `json:"argv,omitempty"`
	Workdir string            `json:"workdir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	TTY     bool              `json:"tty,omitempty"`
	Cols    int               `json:"cols,omitempty"`
	Rows    int               `json:"rows,omitempty"`
}

// ExecStreamControlIn is a client text frame.
type ExecStreamControlIn struct {
	Type   string `json:"type"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Signal string `json:"signal,omitempty"`
}

// ExecStreamControlOut is a server text frame: the exit, or an error.
type ExecStreamControlOut struct {
	Type    string `json:"type"`
	Code    int    `json:"code,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Message string `json:"message,omitempty"`
}

// NewExecStreamUpgrader returns the exec stream's upgrader. Auth happens in
// the HTTP handler before the upgrade, and the connection is private to the
// authenticated caller from then on, so origins are not checked (SDK and CLI
// clients send no Origin).
func NewExecStreamUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin:     func(*http.Request) bool { return true },
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
		Subprotocols:    []string{BearerSubprotocol},
	}
}

// Liveness is the keepalive (plans/mcp-server-and-agent-cli.md, RR1). A
// dropped stream kills its command, so a healthy stream that is merely
// silent must not read as dropped: the server pings every PingInterval, and
// the read deadline is PongWait, extended by every pong and every client
// message. Proxies that close idle WebSockets after about a minute see
// traffic every 30s, and a real drop is noticed within 90s. Clients need no
// change: gorilla and browser WebSockets answer pings on their own.
type Liveness struct {
	PingInterval  time.Duration
	PongWait      time.Duration
	PingWriteWait time.Duration
}

// DefaultLiveness is the production keepalive.
var DefaultLiveness = Liveness{
	PingInterval:  30 * time.Second,
	PongWait:      90 * time.Second,
	PingWriteWait: 10 * time.Second,
}

// ArmLiveness starts the pinger and the pong-extended read deadline. extend
// must be called after every client message (on the reader goroutine, where
// the pong handler also runs). stop ends the pinger; it is safe to call more
// than once.
func ArmLiveness(conn *websocket.Conn, cfg Liveness) (extend func(), stop func()) {
	extend = func() { _ = conn.SetReadDeadline(time.Now().Add(cfg.PongWait)) }
	extend()
	conn.SetPongHandler(func(string) error {
		extend()
		return nil
	})
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(cfg.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// WriteControl is safe alongside the output pumps' writes.
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(cfg.PingWriteWait)); err != nil {
					return
				}
			}
		}
	}()
	var once sync.Once
	return extend, func() { once.Do(func() { close(done) }) }
}
