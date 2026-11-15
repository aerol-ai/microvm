package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrEntrypointLogsUnsupported means the worker keeps no entrypoint output:
// it was adopted from a sandboxd older than entrypoint logs, or it runs the
// wasmtime engine. Callers answer it with HTTP 501.
var ErrEntrypointLogsUnsupported = errors.New("entrypoint logs are not supported by this wasm worker")

// EntrypointLogs reads the sandbox's entrypoint state, with its kept output
// when logs is set.
func (c *Client) EntrypointLogs(ctx context.Context, sandboxID string, logs bool) (EntrypointLogs, error) {
	conn, reply, err := c.entrypointRequest(ctx, sandboxID, entrypointLogsPayload{Logs: logs})
	if conn != nil {
		_ = conn.Close()
	}
	return reply, err
}

// FollowEntrypoint reads the entrypoint's state and kept output, then
// streams its live output: Recv on the returned stream gives each chunk and
// ends with the exit when the entrypoint ends (at once if it already has).
// The stream is nil when no entrypoint has run. Close must be called.
func (c *Client) FollowEntrypoint(ctx context.Context, sandboxID string) (EntrypointLogs, *ExecStream, error) {
	conn, reply, err := c.entrypointRequest(ctx, sandboxID, entrypointLogsPayload{Logs: true, Follow: true})
	if err != nil || !reply.Ran {
		if conn != nil {
			_ = conn.Close()
		}
		return reply, nil, err
	}
	return reply, &ExecStream{client: c, sandboxID: sandboxID, conn: conn}, nil
}

// entrypointRequest sends one MsgEntrypointLogs and reads its reply. On
// success the connection is returned open, with no deadline, for a follow.
func (c *Client) entrypointRequest(ctx context.Context, sandboxID string, p entrypointLogsPayload) (net.Conn, EntrypointLogs, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := encodePayload(p)
	if err != nil {
		return nil, EntrypointLogs{}, err
	}
	conn, err := c.dialContext(ctx)
	if err != nil {
		return nil, EntrypointLogs{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	reply, err := func() (Envelope, error) {
		if err := writeFrame(conn, Envelope{Type: MsgEntrypointLogs, SandboxID: sandboxID, Payload: body}); err != nil {
			return Envelope{}, err
		}
		return readFrame(conn)
	}()
	if err != nil {
		_ = conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, EntrypointLogs{}, ctxErr
		}
		return nil, EntrypointLogs{}, err
	}
	switch reply.Type {
	case MsgOK:
		var logs EntrypointLogs
		if err := decodePayload(reply.Payload, &logs); err != nil {
			_ = conn.Close()
			return nil, EntrypointLogs{}, err
		}
		if !stop() {
			_ = conn.Close()
			return nil, EntrypointLogs{}, ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, logs, nil
	case MsgError:
		_ = conn.Close()
		return nil, EntrypointLogs{}, entrypointError(reply)
	case MsgInvokeResult:
		// A per-sandbox worker older than entrypoint logs answers every
		// type it does not know with an empty invoke result.
		if len(reply.Payload) == 0 {
			_ = conn.Close()
			return nil, EntrypointLogs{}, ErrEntrypointLogsUnsupported
		}
	}
	_ = conn.Close()
	return nil, EntrypointLogs{}, fmt.Errorf("unexpected reply type %q", reply.Type)
}

// entrypointError maps a refused MsgEntrypointLogs to the typed errors.
func entrypointError(reply Envelope) error {
	var p errorPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return err
	}
	switch {
	case p.Code == errCodeStreamingUnsupported:
		return fmt.Errorf("%w: %s", ErrEntrypointLogsUnsupported, p.Message)
	case p.Code == errCodeStreamLimit:
		return fmt.Errorf("%w: %s", ErrStreamLimit, p.Message)
	case strings.HasPrefix(p.Message, string(MsgEntrypointLogs)+" not supported"):
		// A resident host older than entrypoint logs refuses unknown types
		// by name.
		return ErrEntrypointLogsUnsupported
	}
	return errors.New(p.Message)
}
