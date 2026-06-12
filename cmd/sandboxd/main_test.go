package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
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

func TestMainSuccess(t *testing.T) {
	origDaemon := runDaemon
	t.Cleanup(func() { runDaemon = origDaemon })
	runDaemon = func(context.Context, *slog.Logger, daemon.ProviderFactory) error {
		return nil
	}

	origExit := osExit
	t.Cleanup(func() { osExit = origExit })
	exited := false
	osExit = func(code int) {
		exited = true
	}

	main()

	if exited {
		t.Fatalf("expected main not to call osExit on success")
	}
}

func TestMainError(t *testing.T) {
	origDaemon := runDaemon
	t.Cleanup(func() { runDaemon = origDaemon })
	runDaemon = func(context.Context, *slog.Logger, daemon.ProviderFactory) error {
		return errors.New("boom")
	}

	origExit := osExit
	t.Cleanup(func() { osExit = origExit })
	exitCode := -1
	osExit = func(code int) {
		exitCode = code
	}

	main()

	if exitCode != 1 {
		t.Fatalf("expected main to call osExit(1) on error, got %d", exitCode)
	}
}

func TestMainWasmWorkerSuccess(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"sandboxd", "--wasm-worker", "/tmp/wasm.sock"}

	origWorker := runWasmWorkerCLI
	t.Cleanup(func() { runWasmWorkerCLI = origWorker })
	called := false
	runWasmWorkerCLI = func(args []string) error {
		called = true
		if len(args) != 1 || args[0] != "/tmp/wasm.sock" {
			t.Fatalf("RunCLI args = %v", args)
		}
		return nil
	}

	origExit := osExit
	exited := false
	osExit = func(int) { exited = true }
	t.Cleanup(func() { osExit = origExit })

	main()

	if !called {
		t.Fatal("expected wasm worker CLI to run")
	}
	if exited {
		t.Fatal("expected main not to exit on wasm worker success")
	}
}

func TestMainWasmWorkerError(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"sandboxd", "--wasm-worker", "/tmp/wasm.sock"}

	origWorker := runWasmWorkerCLI
	t.Cleanup(func() { runWasmWorkerCLI = origWorker })
	runWasmWorkerCLI = func([]string) error { return errors.New("worker boom") }

	origExit := osExit
	exitCode := -1
	osExit = func(code int) { exitCode = code }
	t.Cleanup(func() { osExit = origExit })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	main()

	_ = w.Close()
	var stderr bytes.Buffer
	_, _ = io.Copy(&stderr, r)

	if exitCode != 1 {
		t.Fatalf("expected osExit(1), got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "worker boom") {
		t.Fatalf("stderr = %q, want worker boom", stderr.String())
	}
}
