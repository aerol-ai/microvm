package toolboxwire

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

// Daytona-compatible process sessions (/process/session/...): the request and
// response bodies, the log window a poller reads, and the follow WebSocket's
// framing. toolboxd serves them from a shell in the guest; the WASM toolhost
// serves them from runs inside the wasm engine. The Daytona SDKs decode these
// shapes strictly (required fields), so both servers take them from here.

// Session ids the Daytona SDK uses for the sandbox's entrypoint: its process
// is the one command of a session it never created.
const (
	EntrypointSessionID = "entrypoint"
	EntrypointCommandID = "entrypoint_command"
)

// Daytona SDK ≥0.175 streams session command logs over WebSocket on
// /process/session/{sid}/command/{cid}/logs?follow=true. Frames are binary;
// the client (stdDemuxStream in @daytona/sdk's utils/Stream.js) demultiplexes
// stdout and stderr by these three-byte markers preceding each chunk.
var (
	LogStdoutMarker = []byte{0x01, 0x01, 0x01}
	LogStderrMarker = []byte{0x02, 0x02, 0x02}
)

// FrameLog is one follow frame: the stream's marker, then chunk.
func FrameLog(stderr bool, chunk []byte) []byte {
	marker := LogStdoutMarker
	if stderr {
		marker = LogStderrMarker
	}
	frame := make([]byte, 0, len(marker)+len(chunk))
	frame = append(frame, marker...)
	return append(frame, chunk...)
}

// LogReplay is the first follow frame: everything written so far, stdout
// then stderr, each behind its marker and left out when empty.
func LogReplay(stdout, stderr []byte) []byte {
	var replay []byte
	if len(stdout) > 0 {
		replay = append(replay, LogStdoutMarker...)
		replay = append(replay, stdout...)
	}
	if len(stderr) > 0 {
		replay = append(replay, LogStderrMarker...)
		replay = append(replay, stderr...)
	}
	return replay
}

// NewLogsUpgrader returns the follow WebSocket's upgrader. Auth happens in
// the HTTP handler before the upgrade, and SDK clients send no Origin.
func NewLogsUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin:     func(*http.Request) bool { return true },
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
	}
}

// FollowLogs sends replay, then every frame until frames is closed or the
// client goes away, and reports whether frames was closed (the command
// ended). The caller closes conn.
func FollowLogs(conn *websocket.Conn, replay []byte, frames <-chan []byte) (ended bool) {
	if len(replay) > 0 {
		if err := conn.WriteMessage(websocket.BinaryMessage, replay); err != nil {
			return false
		}
	}
	// Detect client disconnects so we don't block forever waiting on a
	// command that may run indefinitely. Reads here drain any frames the
	// client sends (none, per protocol) but unblock when the peer closes.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	for {
		select {
		case frame, ok := <-frames:
			if !ok {
				return true
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				return false
			}
		case <-done:
			return false
		}
	}
}

// CreateSessionRequest is POST /process/session.
type CreateSessionRequest struct {
	SessionID string `json:"sessionId"`
}

// SessionResponse is one session, as GET /process/session lists them.
type SessionResponse struct {
	Commands  []CommandResponse `json:"commands"`
	SessionID string            `json:"sessionId"`
}

// CommandResponse is one command of a session; ExitCode is absent while it
// runs.
type CommandResponse struct {
	Command  string `json:"command"`
	ExitCode *int32 `json:"exitCode,omitempty"`
	ID       string `json:"id"`
}

// SessionExecuteRequest is POST /process/session/{id}/exec. Older SDKs send
// async, newer ones runAsync.
type SessionExecuteRequest struct {
	Async             *bool  `json:"async,omitempty"`
	Command           string `json:"command"`
	RunAsync          *bool  `json:"runAsync,omitempty"`
	SuppressInputEcho *bool  `json:"suppressInputEcho,omitempty"`
}

// RunsAsync reports whether the caller asked for the command id at once
// instead of the command's result.
func (r SessionExecuteRequest) RunsAsync() bool {
	return (r.RunAsync != nil && *r.RunAsync) || (r.Async != nil && *r.Async)
}

// SessionExecuteResponse answers an exec: the id alone for an async one;
// the exit code and output (absent when empty) for a sync one.
type SessionExecuteResponse struct {
	CmdID    string  `json:"cmdId"`
	ExitCode *int32  `json:"exitCode,omitempty"`
	Output   *string `json:"output,omitempty"`
	Stderr   *string `json:"stderr,omitempty"`
	Stdout   *string `json:"stdout,omitempty"`
}

// NewSessionExecuteResponse is a finished command's result. Output is stdout
// then stderr.
func NewSessionExecuteResponse(cmdID string, exitCode int32, stdout, stderr string) *SessionExecuteResponse {
	return &SessionExecuteResponse{
		CmdID:    cmdID,
		ExitCode: &exitCode,
		Output:   stringOrNil(stdout + stderr),
		Stderr:   stringOrNil(stderr),
		Stdout:   stringOrNil(stdout),
	}
}

func stringOrNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// SessionLogsResponse is GET /process/session/{id}/command/{cid}/logs.
type SessionLogsResponse struct {
	Output string `json:"output"`
	Stderr string `json:"stderr"`
	Stdout string `json:"stdout"`
	// StdoutLength / StderrLength are each stream's full length so far, so a
	// caller that read from an offset knows how much is left. Their presence
	// also tells a caller this toolbox serves a running command's output and
	// honours the offset parameters.
	StdoutLength int64 `json:"stdoutLength"`
	StderrLength int64 `json:"stderrLength"`
	// StdoutEnd / StderrEnd are the offsets just past the returned text, in
	// the stream's bytes: where the caller's next read starts.
	StdoutEnd int64 `json:"stdoutEnd"`
	StderrEnd int64 `json:"stderrEnd"`
}

// NewSessionLogsResponse puts two windows into a logs response.
func NewSessionLogsResponse(stdout, stderr LogWindow) SessionLogsResponse {
	return SessionLogsResponse{
		Stdout: stdout.Text, StdoutEnd: stdout.End, StdoutLength: stdout.Length,
		Stderr: stderr.Text, StderrEnd: stderr.End, StderrLength: stderr.Length,
		Output: stdout.Text + stderr.Text,
	}
}

// SessionInputRequest is POST /process/session/{id}/command/{cid}/input.
type SessionInputRequest struct {
	Data string `json:"data"`
}

// Line is the bytes to write to the command's stdin. A trailing newline is
// added unless the payload already ends in one (\n or \r). Daytona's own SDK
// helper `sendSessionCommandInput(sid, cid, 'Alice')` ships line-oriented
// examples that omit the terminator, and a reader waiting for a line blocks
// forever without it, so verbatim forwarding silently hangs interactive
// commands. Callers that send several lines include their own \n bytes.
func (r SessionInputRequest) Line() string {
	if strings.HasSuffix(r.Data, "\n") || strings.HasSuffix(r.Data, "\r") {
		return r.Data
	}
	return r.Data + "\n"
}

// LogQuery is a logs request's window: where each stream's read starts and
// how many bytes of each to return at most (0: no limit).
type LogQuery struct {
	StdoutOffset, StderrOffset, Limit int64
}

// ParseLogQuery reads stdoutOffset, stderrOffset and limit. The error is the
// 400 message.
func ParseLogQuery(q url.Values) (LogQuery, error) {
	var bounds [3]int64
	for i, name := range []string{"stdoutOffset", "stderrOffset", "limit"} {
		raw := strings.TrimSpace(q.Get(name))
		if raw == "" {
			continue
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return LogQuery{}, errors.New(name + " must be a non-negative integer")
		}
		bounds[i] = n
	}
	return LogQuery{StdoutOffset: bounds[0], StderrOffset: bounds[1], Limit: bounds[2]}, nil
}

// LogWindow is one stream's bytes from an offset: Text, then End, the offset
// just past them, and Length, the stream's full length so far, all counted
// in the stream's own bytes. Text is valid UTF-8 of the same length as the
// bytes it stands for (see SameLengthUTF8), so a reader's offsets agree
// whether it counts End or the text it has been sent.
type LogWindow struct {
	Text        string
	End, Length int64
}

// CutLogWindow is text[from:], cut to limit bytes when limit is positive,
// and never ending partway through a UTF-8 character: a character the cut
// would split is left for the next window, so each one decodes whole.
// final says text will not grow; without it a character still being written
// at the end of text is held back too. A cut that would leave nothing (a
// limit shorter than one character) keeps the bytes, so a reader always
// moves forward.
func CutLogWindow[T ~string | ~[]byte](text T, from, limit int64, final bool) LogWindow {
	return CutLogWindowAt(text, 0, from, limit, final)
}

// CutLogWindowAt is CutLogWindow for a stream whose first base bytes are no
// longer kept: text holds the bytes from offset base on. Offsets stay the
// stream's own, and a read from before base starts at the oldest byte kept.
func CutLogWindowAt[T ~string | ~[]byte](text T, base, from, limit int64, final bool) LogWindow {
	from = min(max(from-base, 0), int64(len(text)))
	window := text[from:]
	cut := limit > 0 && int64(len(window)) > limit
	if cut {
		window = window[:limit]
	}
	if cut || !final {
		if whole := wholeRunesLen(window); whole > 0 || !cut {
			window = window[:whole]
		}
	}
	return LogWindow{Text: SameLengthUTF8(string(window)), End: base + from + int64(len(window)), Length: base + int64(len(text))}
}

// SameLengthUTF8 replaces each byte of text that is not part of a valid
// UTF-8 character with '?'. The text goes out as a JSON string, and JSON
// would replace each such byte with a three-byte character instead, so a
// reader counting the text it received would drift past the stream's real
// length and resume at the wrong place.
func SameLengthUTF8(text string) string {
	if utf8.ValidString(text) {
		return text
	}
	out := []byte(text)
	for i := 0; i < len(out); {
		r, size := utf8.DecodeRune(out[i:])
		if r == utf8.RuneError && size == 1 {
			out[i] = '?'
		}
		i += size
	}
	return string(out)
}

// wholeRunesLen is the length of text without a final UTF-8 character that
// is missing its last bytes. Invalid bytes count as whole: no later byte
// can complete them.
func wholeRunesLen[T ~string | ~[]byte](text T) int {
	for i := len(text) - 1; i >= 0 && i > len(text)-utf8.UTFMax; i-- {
		if utf8.RuneStart(text[i]) {
			if utf8.FullRune([]byte(text[i:])) {
				return len(text)
			}
			return i
		}
	}
	return len(text)
}
