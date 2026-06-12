package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aerol-ai/microvm/pkg/daemon"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

var (
	runDaemon        = daemon.Run
	runWasmWorkerCLI = worker.RunCLI
	osExit           = os.Exit
)

func run(ctx context.Context, logger *slog.Logger) error {
	return runDaemon(ctx, logger, nil)
}

// cmd/sandboxd is the open-source entrypoint. It passes a nil provider factory,
// so daemon.Run uses controlplane.Noop(): the daemon is PAT-only (user-token
// validation rejected, usage reporting discarded, no enforcement loop). The
// entire boot sequence lives in pkg/daemon.Run, which a managed build reuses by
// supplying a real provider factory.
func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--wasm-worker" {
		if err := runWasmWorkerCLI(os.Args[2:]); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			osExit(1)
		}
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, logger); err != nil {
		logger.Error("sandboxd exited with error", "error", err)
		osExit(1)
	}
}
