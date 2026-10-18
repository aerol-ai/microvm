package identity

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// FilePollInterval is how often a changed identity file is noticed without
// a SIGHUP: a deny_subjects entry applies within one poll of the file
// reaching the node (§5.5).
const FilePollInterval = 10 * time.Second

// ErrInvalidAtBoot marks an identity file that was missing or invalid when
// the daemon started. OIDC tokens get 503 until a good file loads; the PAT
// and avm_ tokens are unaffected (§11).
var ErrInvalidAtBoot = errors.New("identity file invalid at boot")

// Watcher keeps the last good identity file, the same machinery as the
// egress operator file: strict load, last good kept in an atomic pointer,
// an mtime poll plus Reload (SIGHUP), and a hash metric for drift between
// nodes. An invalid reload keeps the last good file and counts an error.
type Watcher struct {
	path string
	cur  atomic.Pointer[Config]
	// tried is the mtime of the last attempt, good or bad, so the poll
	// loads one version of the file once and a broken edit counts one
	// error, not one per tick.
	tried    atomic.Int64
	reloadMu sync.Mutex
	bootErr  error
	log      *slog.Logger
	// changed is signalled (never blocking) after every load whose hash
	// differs from the file before it, including the first. RecordChanges
	// drains it.
	changed chan struct{}
}

// NewWatcher loads path once. A file that is missing or invalid leaves
// BootError set; the poll picks up the fix.
func NewWatcher(path string, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	w := &Watcher{path: path, log: log, changed: make(chan struct{}, 1)}
	if err := w.Reload(); err != nil {
		w.bootErr = errors.Join(ErrInvalidAtBoot, err)
	}
	return w
}

// Current returns the last good file, or nil when none has loaded yet.
func (w *Watcher) Current() *Config {
	if w == nil {
		return nil
	}
	return w.cur.Load()
}

// BootError reports a missing or invalid file at startup, until a good one
// loads.
func (w *Watcher) BootError() error {
	if w == nil || w.cur.Load() != nil {
		return nil
	}
	return w.bootErr
}

// Reload re-reads the file now. An unchanged hash swaps nothing and signals
// no change; an invalid file keeps the last good one.
func (w *Watcher) Reload() error {
	w.reloadMu.Lock()
	defer w.reloadMu.Unlock()
	st, err := os.Stat(w.path)
	if err != nil {
		w.loadFailed(err)
		return err
	}
	w.tried.Store(st.ModTime().UnixNano())
	cfg, err := Load(w.path)
	if err != nil {
		w.loadFailed(err)
		return err
	}
	prev := w.cur.Load()
	if prev != nil && prev.Hash() == cfg.Hash() {
		return nil
	}
	w.cur.Store(cfg)
	publishFileHash(cfg.Hash())
	if prev != nil {
		w.log.Info("identity file reloaded", "path", w.path, "old_hash", prev.Hash(), "new_hash", cfg.Hash())
	} else {
		w.log.Info("identity file loaded", "path", w.path, "hash", cfg.Hash())
	}
	select {
	case w.changed <- struct{}{}:
	default:
	}
	return nil
}

func (w *Watcher) loadFailed(err error) {
	identityFileLoadErrors.Add(1)
	w.log.Error("identity file invalid; keeping the last good one", "path", w.path, "error", err)
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

// RecordChanges writes the identity_config evidence (D20) until ctx ends:
// after every change the watcher signals, and at start for the file it
// loaded at boot, it hands the file in force to record. record reports
// whether it is done; while it is not (the cluster audit gate is closed,
// or a durable write failed) it is retried every retry interval. One
// goroutine records, always with the current file, so a slow retry can
// never write an older file over a newer one.
func RecordChanges(ctx context.Context, w *Watcher, record func(Summary) bool, retry time.Duration) {
	if w == nil || record == nil {
		return
	}
	t := time.NewTicker(retry)
	defer t.Stop()
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.changed:
		case <-t.C:
			if !pending {
				continue
			}
		}
		if cfg := w.Current(); cfg != nil {
			pending = !record(cfg.Summary())
		}
	}
}
