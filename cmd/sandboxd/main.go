package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aerol-ai/microvm/pkg/daemon"
	"github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

var (
	runDaemon              = daemon.Run
	runWasmWorkerCLI       = worker.RunCLI
	runWasmResidentHostCLI = worker.RunCLIResident
	runIsolateJailShim     = isolate.RunJailShim
	osExit                 = os.Exit
)

// providerFactory is nil in every shipped build, which is what makes this the
// open-source entrypoint (see the comment on main below). It is a variable
// only so the integration harness can supply a real controlplane.Provider
// behind an explicit build tag — enterprise mode requires a non-noop Witness,
// and without one the daemon correctly refuses to start, which would make the
// enterprise scenarios untestable.
//
// Default file: always nil. See provider_itest.go, which is compiled ONLY with
// `-tags itestwitness`. A release build cannot pick it up by accident.
var providerFactory daemon.ProviderFactory

func run(ctx context.Context, logger *slog.Logger) error {
	return runDaemon(ctx, logger, providerFactory)
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

	// Isolate jail shim: the daemon re-exec'd between fork and exec of a
	// workerd group process to chroot, drop privileges, set no_new_privs and
	// install seccomp — what os/exec cannot express (pkg/isolate/shim_linux.go).
	// Spawned only by a jailed isolate group; exits 125 on any failure so the
	// parent's "workerd exited during startup" has a cause beside it.
	if len(os.Args) >= 2 && os.Args[1] == isolate.JailShimFlag {
		if err := runIsolateJailShim(os.Args[2:]); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			osExit(125)
		}
		return
	}

	// Resident-module host: one process compiles a module once and hosts many
	// isolated sandbox instances (plans/wasm-resident-module-host.md). Spawned
	// only when SB_WASM_RESIDENT_HOST_ENABLED routes a create here.
	if len(os.Args) >= 2 && os.Args[1] == "--wasm-resident-host" {
		if err := runWasmResidentHostCLI(os.Args[2:]); err != nil {
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
