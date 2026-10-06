package operator

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// ErrInvalidAtBoot is returned when the file exists but does not validate at
// startup. Callers refuse creates (503 egress_operator_config_invalid): the
// default policy is unknown, so failing closed is the only safe answer.
var ErrInvalidAtBoot = errors.New("egress operator file invalid")

// Watcher keeps the last good operator file. A changed file is picked up by
// an mtime poll (and Reload, e.g. on SIGHUP); an invalid reload keeps the last
// good one and counts a failure.
type Watcher struct {
	path     string
	cur      atomic.Pointer[Operator]
	mtime    atomic.Int64
	failures atomic.Uint64
	bootErr  error
	log      *slog.Logger
	onChange func(*Operator)
}

// NewWatcher loads path once. An empty path means no operator file (nil
// Operator, today's behavior). A file that is present but invalid leaves
// BootError set.
func NewWatcher(path string, log *slog.Logger, onChange func(*Operator)) *Watcher {
	w := &Watcher{path: path, log: log, onChange: onChange}
	if path == "" {
		return w
	}
	if err := w.Reload(); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			w.bootErr = errors.Join(ErrInvalidAtBoot, err)
		}
	}
	return w
}

// Current returns the last good file, or nil.
func (w *Watcher) Current() *Operator {
	if w == nil {
		return nil
	}
	return w.cur.Load()
}

// BootError reports an invalid file at startup.
func (w *Watcher) BootError() error {
	if w == nil {
		return nil
	}
	if w.cur.Load() != nil {
		return nil
	}
	return w.bootErr
}

// Failures counts invalid reloads
// (aerolvm_egress_operator_config_load_failures_total).
func (w *Watcher) Failures() uint64 { return w.failures.Load() }

// Reload re-reads the file now.
func (w *Watcher) Reload() error {
	st, err := os.Stat(w.path)
	if err != nil {
		w.failures.Add(1)
		return err
	}
	op, err := Load(w.path)
	if err != nil {
		w.failures.Add(1)
		if w.log != nil {
			w.log.Error("egress operator file invalid; keeping the last good one", "path", w.path, "error", err)
		}
		return err
	}
	w.mtime.Store(st.ModTime().UnixNano())
	prev := w.cur.Swap(op)
	if w.onChange != nil && (prev == nil || prev.Hash() != op.Hash()) {
		w.onChange(op)
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
			if err != nil || st.ModTime().UnixNano() == w.mtime.Load() {
				continue
			}
			_ = w.Reload()
		}
	}
}
