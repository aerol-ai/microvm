package createpolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// writeFile puts body at path with the given mtime in one step: it writes
// and dates a temp file, then renames it over path. Writing path in place
// would let a running poll see it twice, once half-written with the time
// of the write and again after Chtimes, and count one edit as several loads.
func writeFile(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestWatcherNoPathIsNoPolicy(t *testing.T) {
	w := NewWatcher("", quietLog())
	if w.Current() != nil || w.BootError() != nil || w.Failures() != 0 {
		t.Fatal("an unset path must be today's behavior: no policy, no error")
	}
	w.Run(context.Background(), time.Millisecond) // returns at once
	var nilWatcher *Watcher
	if nilWatcher.Current() != nil || nilWatcher.BootError() != nil || nilWatcher.Failures() != 0 {
		t.Fatal("a nil watcher must read as no policy")
	}
	nilWatcher.Run(context.Background(), time.Millisecond)
}

// TestWatcherMissingFileFailsClosed: unlike the egress file, a set path with
// no file behind it is a boot error, so creates are refused rather than run
// with no rules.
func TestWatcherMissingFileFailsClosed(t *testing.T) {
	w := NewWatcher(filepath.Join(t.TempDir(), "absent.yaml"), quietLog())
	if err := w.BootError(); !errors.Is(err, ErrInvalidAtBoot) {
		t.Fatalf("BootError = %v, want ErrInvalidAtBoot", err)
	}
	if w.Failures() != 1 {
		t.Fatalf("failures = %d", w.Failures())
	}
}

// TestWatcherBadFileRefusedThenFixed: an invalid file at boot leaves the
// boot error set; the poll picks up the fix and clears it; a later bad edit
// keeps the last good policy.
func TestWatcherBadFileRefusedThenFixed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	base := time.Now().Add(-time.Hour)
	writeFile(t, path, "version: 1\nruntimes: [podman]\n", base)
	w := NewWatcher(path, quietLog())
	if err := w.BootError(); !errors.Is(err, ErrInvalidAtBoot) || w.Current() != nil {
		t.Fatalf("a bad file must be refused at boot: err=%v cur=%v", err, w.Current())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, 5*time.Millisecond); close(done) }()
	writeFile(t, path, "version: 1\nruntimes: [docker]\n", base.Add(time.Minute))
	deadline := time.Now().Add(5 * time.Second)
	for w.Current() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if w.Current() == nil || w.BootError() != nil {
		t.Fatalf("the poll must load the fixed file: cur=%v err=%v", w.Current(), w.BootError())
	}
	good := w.Current().Hash()

	failures := w.Failures()
	writeFile(t, path, "version: 1\nruntimes: []\n", base.Add(2*time.Minute))
	deadline = time.Now().Add(5 * time.Second)
	for w.Failures() == failures && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if w.Failures() != failures+1 {
		t.Fatalf("a bad edit must count one failure, got %d -> %d", failures, w.Failures())
	}
	if w.Current() == nil || w.Current().Hash() != good {
		t.Fatal("a bad edit must keep the last good policy")
	}
}

func TestWatcherReloadPicksUpChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writeFile(t, path, "version: 1\nlimits:\n  max_cpu: 2\n", time.Now().Add(-time.Hour))
	w := NewWatcher(path, quietLog())
	if err := w.Current().CheckSize(3, 0, 0); err == nil {
		t.Fatal("boot policy must apply")
	}
	writeFile(t, path, "version: 1\nlimits:\n  max_cpu: 8\n", time.Now())
	if err := w.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := w.Current().CheckSize(3, 0, 0); err != nil {
		t.Fatalf("reload must replace the policy: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := w.Reload(); err == nil {
		t.Fatal("reloading a removed file must fail")
	}
	if w.Current() == nil {
		t.Fatal("a failed reload keeps the last good policy")
	}
}
