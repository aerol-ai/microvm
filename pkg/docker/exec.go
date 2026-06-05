package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ExecSession is a hijacked Docker exec stream. With Tty=true the byte stream
// is unframed (raw); with Tty=false it follows Docker's stdin/stdout/stderr
// multiplexing. The SSH gateway only uses Tty=true for shells and Tty=false
// for one-shot exec, where stderr framing isn't decoded — stdout+stderr both
// reach the SSH client through the merged stream as the SSH side expects.
type ExecSession struct {
	ID     string
	Conn   net.Conn
	Reader *bufio.Reader
}

// Close releases the hijacked connection. Idempotent.
func (e *ExecSession) Close() error {
	if e == nil || e.Conn == nil {
		return nil
	}
	return e.Conn.Close()
}

// ExecCreate creates an exec instance attached to the given container. The
// returned exec ID must be passed to ExecStart to actually run the command.
func (c *Client) ExecCreate(ctx context.Context, containerID string, cmd []string, env []string, workdir string, tty bool) (string, error) {
	if containerID == "" {
		return "", errors.New("containerID is empty")
	}
	if len(cmd) == 0 {
		return "", errors.New("cmd is empty")
	}

	body := map[string]any{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          tty,
		"Cmd":          cmd,
	}
	if len(env) > 0 {
		body["Env"] = env
	}
	if workdir != "" {
		body["WorkingDir"] = workdir
	}

	var created struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/exec", nil, body, nil, &created); err != nil {
		return "", fmt.Errorf("create exec: %w", err)
	}
	if created.ID == "" {
		return "", errors.New("docker returned empty exec ID")
	}
	return created.ID, nil
}

// ExecStart starts a previously-created exec and hijacks the connection so the
// caller can pipe stdin/stdout directly. The returned ExecSession owns the
// underlying net.Conn — close it when done.
func (c *Client) ExecStart(ctx context.Context, execID string, tty bool) (*ExecSession, error) {
	if execID == "" {
		return nil, errors.New("execID is empty")
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial docker socket: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	payload, err := json.Marshal(map[string]any{
		"Detach": false,
		"Tty":    tty,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The payload rides as the request body so req.Write emits headers and
	// body in one well-formed write. Setting req.ContentLength on a nil-Body
	// request and writing the body separately is rejected by net/http's
	// transfer writer ("ContentLength=N with nil Body") before a single byte
	// reaches the socket, which would break every exec start.
	req, err := http.NewRequest(http.MethodPost, "http://docker/exec/"+url.PathEscape(execID)+"/start", bytes.NewReader(payload))
	if err != nil {
		conn.Close()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write exec start request: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read exec start response: %w", err)
	}
	// Once the deadline elapses we don't want it to kill the long-lived stream.
	_ = conn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reader)
		conn.Close()
		return nil, fmt.Errorf("exec start: status %d: %s", resp.StatusCode, string(body))
	}

	return &ExecSession{
		ID:     execID,
		Conn:   conn,
		Reader: reader,
	}, nil
}

// ExecResize forwards a window-resize event to a running PTY exec.
func (c *Client) ExecResize(ctx context.Context, execID string, height, width int) error {
	if execID == "" {
		return errors.New("execID is empty")
	}
	if height <= 0 || width <= 0 {
		return nil
	}
	query := url.Values{}
	query.Set("h", fmt.Sprintf("%d", height))
	query.Set("w", fmt.Sprintf("%d", width))
	if err := c.doJSON(ctx, http.MethodPost, "/exec/"+url.PathEscape(execID)+"/resize", query, nil, nil, nil); err != nil {
		return fmt.Errorf("exec resize: %w", err)
	}
	return nil
}

// ExecInspect returns the exit code and running state of an exec instance.
// Call this after the hijacked stream closes to learn the process exit code.
func (c *Client) ExecInspect(ctx context.Context, execID string) (exitCode int, running bool, err error) {
	if execID == "" {
		return 0, false, errors.New("execID is empty")
	}
	var inspect struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/exec/"+url.PathEscape(execID)+"/json", nil, nil, nil, &inspect); err != nil {
		return 0, false, fmt.Errorf("exec inspect: %w", err)
	}
	return inspect.ExitCode, inspect.Running, nil
}
