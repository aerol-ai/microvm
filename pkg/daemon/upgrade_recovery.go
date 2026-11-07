package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
)

// Seams for tests.
var (
	recoverUpgrades        = nodeupgrade.Recover
	newUpgradeRecoveryHost = func() nodeupgrade.Host { return &nodeupgrade.SystemHost{} }
	writeStoreOpened       = nodeupgrade.WriteStoreOpenedMarker
)

// recoverInterruptedUpgrade resolves an upgrade the machine lost mid-swap
// (a reboot, a killed upgrader) before anything else boots
// (plans/kubectl-style-cluster-ops.md §6.3, "a reboot mid-swap"): an op
// with every new file in place is marked done, any other has its swapped
// files put back, so the node never runs a half-swapped set. An op whose
// upgrader still holds the lock (it started this sandboxd) is left to it.
//
// Boot cost: one stat of the upgrade directory beside the database on a
// node that never upgraded; a lock and a directory read otherwise, and
// file hashes only for an op left unfinished.
//
// It returns an error only when it put the sandboxd binary itself back:
// this process is then the newer binary, and exiting lets systemd start
// the previous one. Any other problem is logged; it must not stop a boot.
func recoverInterruptedUpgrade(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	out := &slogLines{logger: logger.With("component", "upgrade-recovery")}
	results, err := recoverUpgrades(ctx, nodeupgrade.StateDirFor(cfg.DBPath), newUpgradeRecoveryHost(), out)
	out.flush()
	if err != nil {
		logger.Warn("could not check for an interrupted upgrade", "error", err)
		return nil
	}
	for _, r := range results {
		if r.Err != nil {
			logger.Warn("interrupted upgrade resolved with problems", "op", r.Op, "result", r.Result, "error", r.Err)
		} else {
			logger.Info("interrupted upgrade resolved", "op", r.Op, "result", r.Result)
		}
		if r.RevertedSandboxd {
			return fmt.Errorf("an interrupted upgrade (op %s) was reverted, the sandboxd binary with it; exiting so systemd starts the previous binary", r.Op)
		}
	}
	return nil
}

// markStoreOpened writes the boot marker the upgrader reads (§6.3 step
// 9): the store opened and migrated, so a failure from here on must never
// be answered by restoring the database backup. Best effort: without it a
// failed upgrade would restore a backup it need not, which the next boot
// of the old binary reads anyway.
func markStoreOpened(cfg config.Config, logger *slog.Logger) {
	if err := writeStoreOpened(cfg.DBPath, version.Version); err != nil {
		logger.Warn("could not write the store-opened marker", "error", err)
	}
}

// slogLines turns the upgrader's progress lines into log records.
type slogLines struct {
	logger *slog.Logger
	mu     sync.Mutex
	buf    bytes.Buffer
}

func (w *slogLines) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// No newline yet: keep the rest for the next write.
			w.buf.Reset()
			w.buf.WriteString(line)
			break
		}
		w.logger.Info(line[:len(line)-1])
	}
	return len(p), nil
}

func (w *slogLines) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.logger.Info(w.buf.String())
		w.buf.Reset()
	}
}
