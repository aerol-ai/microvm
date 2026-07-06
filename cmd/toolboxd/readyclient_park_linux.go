//go:build linux

package main

import (
	"bufio"
	"context"
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

	if err := readyproto.EncodeParked(conn, readyproto.ParkedSignal{
		Event:        readyproto.EventParked,
		Token:        bootstrapToken,
		Nonce:        parkNonce,
		AgentVersion: version.Version,
	}); err != nil {
		logger.Warn("park ready socket write failed", "error", err)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(readyDialTimeout))
	frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
	if err != nil {
		logger.Warn("park adopt frame read failed", "error", err)
		return
	}

	srv.adoptIdentity(frame.SandboxID, frame.Token)

	if err := readyproto.Encode(conn, readyproto.ReadySignal{
		Event:        readyproto.EventReady,
		SandboxID:    frame.SandboxID,
		Token:        frame.Token,
		Nonce:        frame.Nonce,
		AgentVersion: version.Version,
	}); err != nil {
		logger.Warn("park adopt ack failed", "error", err)
		return
	}

	srv.mu.RLock()
	deferred := append([]string(nil), srv.deferredCmd...)
	srv.mu.RUnlock()
	if len(deferred) > 0 {
		startUserCommandFn(logger, deferred)
	}
}
