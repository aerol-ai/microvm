//go:build linux

package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

const readyDialTimeout = 3 * time.Second

func dialReadySocket(logger *slog.Logger, socketPath, sandboxID, token, nonce string) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return
	}
	token = strings.TrimSpace(token)
	nonce = strings.TrimSpace(nonce)
	sandboxID = strings.TrimSpace(sandboxID)
	if token == "" || nonce == "" || sandboxID == "" {
		logger.Warn("ready socket dial skipped: missing handshake fields")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), readyDialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		logger.Warn("ready socket dial failed", "error", err)
		return
	}
	defer conn.Close()

	sig := readyproto.ReadySignal{
		Event:        readyproto.EventReady,
		SandboxID:    sandboxID,
		Token:        token,
		Nonce:        nonce,
		AgentVersion: version.Version,
	}
	if err := readyproto.Encode(conn, sig); err != nil {
		logger.Warn("ready socket write failed", "error", err)
	}
}

func announceReady(logger *slog.Logger, sandboxID, token, nonce, socketPath string) {
	if strings.TrimSpace(socketPath) == "" {
		return
	}
	go dialReadySocket(logger, socketPath, sandboxID, token, nonce)
}

// scrubReadyEnv removes readiness env vars so user commands never inherit them.
func scrubReadyEnv() {
	os.Unsetenv("SB_READY_SOCKET")
	os.Unsetenv("SB_READY_NONCE")
}
