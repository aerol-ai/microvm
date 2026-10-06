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
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// egressOperatorPoll is how often a changed operator file is noticed
// without a SIGHUP (plans/egress-domain-filtering.md §5.10).
const egressOperatorPoll = 10 * time.Second

// wireEgressOperator loads the private-cloud operator file
// (SB_EGRESS_OPERATOR_FILE) for every runtime on every platform: the default
// policy and the ceiling apply at create, before any runtime is chosen.
// Unset is a no-op. A file that is present but invalid at boot refuses
// creates until it is fixed (the watcher picks up the fix); an invalid
// reload keeps the last good file.
func wireEgressOperator(ctx context.Context, cfg config.Config, svc *service.Service, logger *slog.Logger) {
	if cfg.EgressOperatorFile == "" {
		return
	}
	// Isolate egress leaves from sandboxd's own process, so its guard follows
	// the file here (the internal zone only with internal_zone.isolate).
	onChange := func(op *operator.Operator) {
		svc.OnEgressOperatorChange(op)
		pkgisolate.SetEgressDialGuard(op.IsolateGuard())
	}
	w := operator.NewWatcher(cfg.EgressOperatorFile, logger, onChange)
	if err := w.BootError(); err != nil {
		logger.Error("egress operator file invalid; every create is refused with 503 until it is fixed", "path", cfg.EgressOperatorFile, "error", err)
	}
	svc.SetEgressOperator(w)
	go w.Run(ctx, egressOperatorPoll)
	go reloadOnSIGHUP(ctx, w, logger)
}

func reloadOnSIGHUP(ctx context.Context, w *operator.Watcher, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := w.Reload(); err != nil {
				logger.Warn("egress operator file reload failed; keeping the last good file", "error", err)
			}
		}
	}
}
