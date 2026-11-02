package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// prepareBlockSets moves a manager's block-alls into the block sets
// (pkg/docker/netrules blockset.go): a block is an element add, the create
// path's lift another, and only letting go of an address deletes. A failure
// leaves the manager on the per-address rules, which stay correct, only
// slower, so it is logged and boot goes on. Reports whether the sets serve
// the manager.
func prepareBlockSets(rules *netrules.Manager, name string, logger *slog.Logger) bool {
	if rules == nil || !rules.Enabled() {
		return false
	}
	if err := rules.PrepareBlockSets(); err != nil {
		logger.Warn("netrules: block sets not fully prepared; block-all keeps per-address rules where needed",
			"manager", name, "error", err)
	}
	return true
}

// blockSetReassertInterval is the block-set check cadence. Tests shrink it.
var blockSetReassertInterval = 30 * time.Second

// startBlockSetReassert checks the block table against what this process
// put in it, on a ticker: a ruleset flush or a lost element is put back,
// and a release nothing here made is deleted (ReassertBlockSets). The
// sets are the process's, so one manager's loop covers every runtime; it
// also runs on the chain reassert ticks. Returns the stop func.
func startBlockSetReassert(ctx context.Context, rules *netrules.Manager, logger *slog.Logger) func() {
	ctx, cancel := context.WithCancel(ctx)
	if rules == nil {
		return cancel
	}
	go func() {
		t := time.NewTicker(blockSetReassertInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reassertBlockSets(rules, logger)
			}
		}
	}()
	return cancel
}

func reassertBlockSets(rules *netrules.Manager, logger *slog.Logger) {
	repaired, err := rules.ReassertBlockSets()
	if err != nil {
		logger.Warn("netrules: re-assert block sets failed", "error", err)
		return
	}
	if repaired {
		logger.Warn("netrules: block sets repaired (a flush, or elements lost)", "table", netrules.BlockTable)
	}
}
