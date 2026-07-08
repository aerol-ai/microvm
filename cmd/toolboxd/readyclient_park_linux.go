//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func runParkedReadyHandshake(logger *slog.Logger, srv *server, socketPath, bootstrapToken, parkNonce string) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), readyDialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		logger.Warn("park ready socket dial failed", "error", err)
		return
	}
	defer conn.Close()

	// Bound the full handshake on the real socket; tests call parkedReadyOnConn
	// directly without a deadline so a paired reader can run on loaded CI.
	_ = conn.SetDeadline(time.Now().Add(readyDialTimeout))
	if err := parkedReadyOnConn(logger, srv, conn, bootstrapToken, parkNonce); err != nil {
		logger.Warn("park ready handshake failed", "error", err)
	}
}

// parkedReadyOnConn runs the guest-side parked→adopt→ready exchange on an
// already-connected unix socket. The caller sets conn deadlines when needed.
func parkedReadyOnConn(logger *slog.Logger, srv *server, conn net.Conn, bootstrapToken, parkNonce string) error {
	if logger == nil || srv == nil || conn == nil {
		return fmt.Errorf("park handshake: missing logger, server, or connection")
	}
	bootstrapToken = strings.TrimSpace(bootstrapToken)
	parkNonce = strings.TrimSpace(parkNonce)
	if bootstrapToken == "" || parkNonce == "" {
		return fmt.Errorf("park handshake: bootstrap token and nonce are required")
	}

	if err := readyproto.EncodeParked(conn, readyproto.ParkedSignal{
		Event:        readyproto.EventParked,
		Token:        bootstrapToken,
		Nonce:        parkNonce,
		AgentVersion: version.Version,
	}); err != nil {
		return fmt.Errorf("parked write: %w", err)
	}

	frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("adopt read: %w", err)
	}

	srv.adoptIdentity(frame.SandboxID, frame.Token)

	if err := readyproto.Encode(conn, readyproto.ReadySignal{
		Event:        readyproto.EventReady,
		SandboxID:    frame.SandboxID,
		Token:        frame.Token,
		Nonce:        frame.Nonce,
		AgentVersion: version.Version,
	}); err != nil {
		return fmt.Errorf("ready ack: %w", err)
	}

	srv.mu.RLock()
	deferred := append([]string(nil), srv.deferredCmd...)
	srv.mu.RUnlock()
	if len(deferred) > 0 {
		startUserCommandFn(logger, deferred)
	}
	return nil
}
