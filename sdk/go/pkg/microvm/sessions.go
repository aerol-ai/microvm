package microvm

import (
	"context"

	apiclient "github.com/aerol-ai/microvm/sdk/go/internal/apiclient"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// SessionAttachOptions mirrors apiclient.SessionAttachOptions; re-exported
// here so callers don't need to import the internal package.
type SessionAttachOptions = apiclient.SessionAttachOptions

// SessionAttachHandle is the live-session counterpart of ExecStreamHandle.
// It outlives the underlying process — Close() detaches without killing.
type SessionAttachHandle struct {
	inner *apiclient.SessionAttachHandle
}

func (c *Client) CreateSession(ctx context.Context, sandboxID string, opts sdktypes.CreateSessionOptions) (sdktypes.Session, error) {
	return c.inner.CreateSession(ctx, sandboxID, opts)
}

func (c *Client) ListSessions(ctx context.Context, sandboxID string) ([]sdktypes.Session, error) {
	return c.inner.ListSessions(ctx, sandboxID)
}

func (c *Client) GetSession(ctx context.Context, sandboxID, sessionID string) (sdktypes.Session, error) {
	return c.inner.GetSession(ctx, sandboxID, sessionID)
}

func (c *Client) DeleteSession(ctx context.Context, sandboxID, sessionID string) error {
	return c.inner.DeleteSession(ctx, sandboxID, sessionID)
}

func (c *Client) SignalSession(ctx context.Context, sandboxID, sessionID, signal string) error {
	return c.inner.SignalSession(ctx, sandboxID, sessionID, signal)
}

func (c *Client) ResizeSession(ctx context.Context, sandboxID, sessionID string, cols, rows int) error {
	return c.inner.ResizeSession(ctx, sandboxID, sessionID, cols, rows)
}

func (c *Client) SessionLog(ctx context.Context, sandboxID, sessionID string) ([]byte, error) {
	return c.inner.SessionLog(ctx, sandboxID, sessionID)
}

func (c *Client) SessionRecording(ctx context.Context, sandboxID, sessionID string) ([]byte, error) {
	return c.inner.SessionRecording(ctx, sandboxID, sessionID)
}

func (c *Client) AttachSession(ctx context.Context, sandboxID, sessionID string, options SessionAttachOptions) (*SessionAttachHandle, error) {
	handle, err := c.inner.AttachSession(ctx, sandboxID, sessionID, options)
	if err != nil {
		return nil, err
	}
	return &SessionAttachHandle{inner: handle}, nil
}

// Sandbox-scoped sugar.

func (s *Sandbox) CreateSession(ctx context.Context, opts sdktypes.CreateSessionOptions) (sdktypes.Session, error) {
	return s.client.CreateSession(ctx, s.ID, opts)
}

func (s *Sandbox) ListSessions(ctx context.Context) ([]sdktypes.Session, error) {
	return s.client.ListSessions(ctx, s.ID)
}

func (s *Sandbox) GetSession(ctx context.Context, sessionID string) (sdktypes.Session, error) {
	return s.client.GetSession(ctx, s.ID, sessionID)
}

func (s *Sandbox) DeleteSession(ctx context.Context, sessionID string) error {
	return s.client.DeleteSession(ctx, s.ID, sessionID)
}

func (s *Sandbox) SignalSession(ctx context.Context, sessionID, signal string) error {
	return s.client.SignalSession(ctx, s.ID, sessionID, signal)
}

func (s *Sandbox) ResizeSession(ctx context.Context, sessionID string, cols, rows int) error {
	return s.client.ResizeSession(ctx, s.ID, sessionID, cols, rows)
}

func (s *Sandbox) SessionLog(ctx context.Context, sessionID string) ([]byte, error) {
	return s.client.SessionLog(ctx, s.ID, sessionID)
}

func (s *Sandbox) SessionRecording(ctx context.Context, sessionID string) ([]byte, error) {
	return s.client.SessionRecording(ctx, s.ID, sessionID)
}

func (s *Sandbox) AttachSession(ctx context.Context, sessionID string, options SessionAttachOptions) (*SessionAttachHandle, error) {
	return s.client.AttachSession(ctx, s.ID, sessionID, options)
}

// Handle methods.

func (h *SessionAttachHandle) Write(data []byte) error {
	return h.inner.Write(data)
}

func (h *SessionAttachHandle) WriteString(data string) error {
	return h.inner.WriteString(data)
}

func (h *SessionAttachHandle) Resize(cols, rows int) error {
	return h.inner.Resize(cols, rows)
}

func (h *SessionAttachHandle) Signal(name string) error {
	return h.inner.Signal(name)
}

func (h *SessionAttachHandle) Close() error {
	return h.inner.Close()
}

func (h *SessionAttachHandle) Wait() (int, string, error) {
	return h.inner.Wait()
}
