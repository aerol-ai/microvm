package daemon

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// egressOperatorPoll is how often a changed operator file is noticed
// without a SIGHUP (plans/egress-domain-filtering.md §5.10).
const egressOperatorPoll = 10 * time.Second

// floorFilePoll is how often the deny-floor file is read; tests shorten it.
var floorFilePoll = egressOperatorPoll

// wireEgressOperator loads the private-cloud operator file
// (SB_EGRESS_OPERATOR_FILE) for every runtime on every platform: the default
// policy and the ceiling apply at create, before any runtime is chosen.
// Unset is a no-op. A file that is present but invalid at boot refuses
// creates until it is fixed (the watcher picks up the fix); an invalid
// reload keeps the last good file.
func wireEgressOperator(ctx context.Context, cfg config.Config, svc *service.Service, logger *slog.Logger) {
	netrules.SetSandboxInterconnect(cfg.SandboxInterconnect)
	if cfg.EgressOperatorFile == "" {
		// No file: the floor still holds the cloud metadata endpoints.
		svc.ApplyEgressFloor(ctx)
		return
	}
	// Isolate egress leaves from sandboxd's own process, so its guard follows
	// the file here (the internal zone only with internal_zone.isolate).
	onChange := func(op *operator.Operator) {
		svc.OnEgressOperatorChange(op)
		pkgisolate.SetEgressDialGuard(op.IsolateGuard())
		up, err := op.UpstreamDialer()
		if err != nil {
			// Keep the previous chain: sending without the credentials (or
			// direct, in a network with no other way out) helps nobody.
			logger.Error("egress upstream proxy not updated for isolate", "error", err)
			return
		}
		pkgisolate.SetEgressUpstream(up)
	}
	w := operator.NewWatcher(cfg.EgressOperatorFile, logger, onChange)
	if err := w.BootError(); err != nil {
		logger.Error("egress operator file invalid; every create is refused with 503 until it is fixed", "path", cfg.EgressOperatorFile, "error", err)
	}
	svc.SetEgressOperator(w)
	go w.Run(ctx, egressOperatorPoll)
	go reloadOnSIGHUP(ctx, w, "egress operator file", logger)
}

// wireEgressFloorFile follows the deny-floor file (SB_EGRESS_DENY_FLOOR_FILE,
// review R4) while sandboxd runs. On Kubernetes the operator keeps the API
// server's current addresses in it. A change reaches isolate's dial guard
// at its next dial (the guard reads the extra floor each time) and the host
// firewall here, installed again with the operator file in force. The WASM
// workers and the egress gateway watch the same file themselves.
func wireEgressFloorFile(ctx context.Context, cfg config.Config, svc *service.Service, logger *slog.Logger) {
	if cfg.EgressDenyFloorFile == "" {
		return
	}
	go egresspolicy.WatchFloorFile(ctx, cfg.EgressDenyFloorFile, floorFilePoll, logger, func() {
		svc.RefreshEgressFloor(ctx)
	})
}

// reloader is an operator file a SIGHUP re-reads: the egress operator file
// and the create policy file reload the same way.
type reloader interface{ Reload() error }

func reloadOnSIGHUP(ctx context.Context, w reloader, what string, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := w.Reload(); err != nil {
				logger.Warn(what+" reload failed; keeping the last good file", "error", err)
			}
		}
	}
}
