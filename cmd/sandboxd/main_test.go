package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/pkg/daemon"
)

func TestRunDelegatesToDaemonRun(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	called := false
	orig := runDaemon
	t.Cleanup(func() { runDaemon = orig })

	runDaemon = func(ctx context.Context, l *slog.Logger, _ daemon.ProviderFactory) error {
		called = true
		if ctx == nil || l == nil {
			t.Fatalf("expected non-nil ctx and logger")
		}
		return nil
	}

	if err := run(context.Background(), logger); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !called {
		t.Fatalf("expected runDaemon to be called")
	}
}

func TestRunReturnsDaemonError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	orig := runDaemon
	t.Cleanup(func() { runDaemon = orig })

	runDaemon = func(context.Context, *slog.Logger, daemon.ProviderFactory) error {
		return errors.New("boom")
	}

	if err := run(context.Background(), logger); err == nil || err.Error() != "boom" {
		t.Fatalf("run() error = %v, want boom", err)
	}
}
