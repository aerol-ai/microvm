package createpolicy

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// ErrInvalidAtBoot is returned when the file is set but did not load at
// startup. Callers refuse creates and resizes (503 create_policy_invalid):
// the limits are unknown, so failing closed is the only safe answer.
var ErrInvalidAtBoot = errors.New("create policy file invalid")

// Watcher keeps the last good policy, the same way the egress operator
// file's watcher does (internal/egress/operator): a changed file is picked
// up by an mtime poll and by Reload (SIGHUP); an invalid reload keeps the
// last good policy and counts a failure. Unlike the egress file, a path that
// names no file is an error at boot, not "no policy": an operator who set
// the variable expects its rules, and a missing file would drop them all.
type Watcher struct {
	path string
	cur  atomic.Pointer[Policy]
	// tried is the mtime of the last attempt, good or bad: the poll loads a
	// given version of the file once, so a broken edit counts one failure
	// rather than one per tick.
	tried    atomic.Int64
	failures atomic.Uint64
	bootErr  error
	log      *slog.Logger
}

// NewWatcher loads path once. An empty path means no policy (nil Policy,
// today's behavior). A file that is missing or invalid leaves BootError set
// until a later reload succeeds.
func NewWatcher(path string, log *slog.Logger) *Watcher {
	w := &Watcher{path: path, log: log}
	if path == "" {
		return w
	}
	if err := w.Reload(); err != nil {
		w.bootErr = errors.Join(ErrInvalidAtBoot, err)
	}
	return w
}

// Current returns the last good policy, or nil.
func (w *Watcher) Current() *Policy {
	if w == nil {
		return nil
	}
	return w.cur.Load()
}

// BootError reports a file that has not loaded since startup. It clears
// once a reload succeeds.
func (w *Watcher) BootError() error {
	if w == nil || w.cur.Load() != nil {
		return nil
	}
	return w.bootErr
}

// Failures counts failed loads (aerolvm_create_policy_load_failures_total).
func (w *Watcher) Failures() uint64 {
	if w == nil {
		return 0
	}
	return w.failures.Load()
}

// Reload re-reads the file now.
func (w *Watcher) Reload() error {
	st, err := os.Stat(w.path)
	if err != nil {
		w.failures.Add(1)
		return err
	}
	w.tried.Store(st.ModTime().UnixNano())
	p, err := Load(w.path)
	if err != nil {
		w.failures.Add(1)
		if w.log != nil {
			w.log.Error("create policy file invalid; keeping the last good one", "path", w.path, "error", err)
		}
		return err
	}
	prev := w.cur.Swap(p)
	if w.log != nil && (prev == nil || prev.Hash() != p.Hash()) {
		w.log.Info("create policy loaded", "path", w.path, "hash", p.Hash())
	}
	return nil
}

// Run polls the file's mtime every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context, interval time.Duration) {
	if w == nil || w.path == "" {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := os.Stat(w.path)
			if err != nil || st.ModTime().UnixNano() == w.tried.Load() {
				continue
			}
			_ = w.Reload()
		}
	}
}
