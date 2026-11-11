// Command aerolvm-supervisor is the first process of the Kubernetes worker
// pod's runtime container (internal/supervisor): it shapes the container's
// cgroup for sandboxes and keeps containerd running in it. It ships in the
// aerolvm-runtime image, apart from sandboxd, so an AerolVM upgrade never
// restarts the container that holds the sandboxes.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aerol-ai/microvm/internal/supervisor"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := supervisor.Run(ctx, supervisor.SettingsFromEnv(), supervisor.RealOS(), log); err != nil {
		log.Error("supervisor: cannot run sandboxes in this container", "error", err)
		os.Exit(1)
	}
}
