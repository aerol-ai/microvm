//go:build !linux

package main

// vsock_other.go is the stub for non-Linux builds. The toolbox only ever
// runs inside a Linux guest in production, but cmd/toolboxd compiles on
// darwin too for IDE-driven dev/test loops. Rather than fence off the
// whole vsock surface with build tags inside main.go, the stub exposes
// the same vsockServer type and Serve / Close methods with a
// "not supported on this OS" error from newVsockServer.

import (
	"context"
	"errors"
	"log/slog"
)

type vsockServer struct{}

func newVsockServer(_ uint32, _ VsockHandler, _ *slog.Logger) (*vsockServer, error) {
	return nil, errors.New("vsock: AF_VSOCK is Linux-only; toolbox vsock listener disabled")
}

func (s *vsockServer) Serve(ctx context.Context) error { return nil }
func (s *vsockServer) Close() error                    { return nil }
