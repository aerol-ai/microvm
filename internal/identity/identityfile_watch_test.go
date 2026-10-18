package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeIdentityFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Bump the mtime past the last poll so the change is seen even on a
	// filesystem with a coarse clock.
	future := time.Now().Add(time.Duration(len(body)) * time.Millisecond)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func drained(w *Watcher) bool {
	select {
	case <-w.changed:
		return true
	default:
		return false
	}
}

func TestWatcherLoadReloadKeepLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.yaml")
	writeIdentityFile(t, path, minimalIssuer)
	errsBefore := identityFileLoadErrors.Value()
	w := NewWatcher(path, nil)
	if w.BootError() != nil || w.Current() == nil {
		t.Fatalf("boot: err %v current %v", w.BootError(), w.Current())
	}
	first := w.Current()
	if !drained(w) {
		t.Fatal("the first load must signal a change (a boot record is due)")
	}
	if got := identityFileInfo.String(); !strings.Contains(got, first.Hash()) {
		t.Fatalf("file info metric = %s, want the hash", got)
	}

	// Unchanged content: no swap, no change signal.
	writeIdentityFile(t, path, minimalIssuer)
	if err := w.Reload(); err != nil || w.Current() != first || drained(w) {
		t.Fatalf("unchanged reload: err %v, swapped %v", err, w.Current() != first)
	}

	// An invalid edit keeps the last good file and counts an error.
	writeIdentityFile(t, path, minimalIssuer+"bogus: 1\n")
	if err := w.Reload(); err == nil || w.Current() != first || drained(w) {
		t.Fatalf("invalid reload: err %v, current kept %v", err, w.Current() == first)
	}
	if identityFileLoadErrors.Value() <= errsBefore {
		t.Fatal("an invalid load must count aerolvm_identity_file_load_errors_total")
	}

	// A good edit swaps and signals.
	writeIdentityFile(t, path, minimalIssuer+"deny_subjects: [\"okta:00u1\"]\n")
	if err := w.Reload(); err != nil || w.Current() == first || !drained(w) || !w.Current().Denied("okta", "00u1") {
		t.Fatalf("good reload: err %v", err)
	}
	if strings.Contains(identityFileInfo.String(), first.Hash()) {
		t.Fatal("the old hash must leave aerolvm_identity_file_info")
	}

	// A deleted file keeps the last good one too.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := w.Reload(); err == nil || w.Current() == nil {
		t.Fatalf("missing file: err %v", err)
	}
}

func TestWatcherBootErrors(t *testing.T) {
	dir := t.TempDir()
	missing := NewWatcher(filepath.Join(dir, "nope.yaml"), nil)
	if !errors.Is(missing.BootError(), ErrInvalidAtBoot) || missing.Current() != nil {
		t.Fatalf("missing file at boot: %v", missing.BootError())
	}
	path := filepath.Join(dir, "identity.yaml")
	writeIdentityFile(t, path, "")
	empty := NewWatcher(path, nil)
	if !errors.Is(empty.BootError(), ErrEmptyFile) {
		t.Fatalf("empty file at boot must be invalid (4.3): %v", empty.BootError())
	}
	// The fix clears the boot error.
	writeIdentityFile(t, path, minimalIssuer)
	if err := empty.Reload(); err != nil || empty.BootError() != nil || empty.Current() == nil {
		t.Fatalf("after the fix: err %v boot %v", err, empty.BootError())
	}
	var nilWatcher *Watcher
	if nilWatcher.Current() != nil || nilWatcher.BootError() != nil {
		t.Fatal("a nil watcher has no file and no error")
	}
	nilWatcher.Run(context.Background(), time.Millisecond)
}

func TestWatcherRunPicksUpEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.yaml")
	writeIdentityFile(t, path, minimalIssuer)
	w := NewWatcher(path, nil)
	drained(w)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, 5*time.Millisecond); close(done) }()
	writeIdentityFile(t, path, minimalIssuer+"deny_subjects: [\"okta:00u9\"]\n")
	deadline := time.Now().Add(5 * time.Second)
	for !w.Current().Denied("okta", "00u9") {
		if time.Now().After(deadline) {
			t.Fatal("the poll did not pick up the edit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// TestWatcherOnReload: the hook runs after every Reload, whether the file
// changed, is unchanged (a SIGHUP that only asks for the keys again) or is
// invalid, and after the poll's reloads too, but never for the boot load.
func TestWatcherOnReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.yaml")
	writeIdentityFile(t, path, minimalIssuer)
	w := NewWatcher(path, nil)
	var calls atomic.Int32
	w.OnReload(func() { calls.Add(1) })
	w.OnReload(nil) // ignored: the hook stays
	var nilWatcher *Watcher
	nilWatcher.OnReload(func() { t.Fatal("a nil watcher has no reloads") })
	if calls.Load() != 0 {
		t.Fatal("the boot load ran before the hook was registered, so it must not count")
	}

	steps := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"unchanged (a SIGHUP)", minimalIssuer, false},
		{"changed", minimalIssuer + "deny_subjects: [\"okta:00u1\"]\n", false},
		{"invalid", minimalIssuer + "bogus: 1\n", true},
	}
	for i, s := range steps {
		writeIdentityFile(t, path, s.body)
		if err := w.Reload(); (err != nil) != s.wantErr {
			t.Fatalf("%s: reload err %v", s.name, err)
		}
		if got := calls.Load(); got != int32(i+1) {
			t.Fatalf("%s: hook ran %d times, want %d", s.name, got, i+1)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, 5*time.Millisecond); close(done) }()
	// A few ticks over an unchanged mtime first: the poll must not reload,
	// so the hook must not run.
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != int32(len(steps)) {
		t.Fatalf("the poll ran the hook %d times over an unchanged file", got-int32(len(steps)))
	}
	writeIdentityFile(t, path, minimalIssuer+"deny_subjects: [\"okta:00u2\"]\n")
	waitFor(t, "the poll's reload to run the hook", func() bool { return calls.Load() == int32(len(steps)+1) })
	cancel()
	<-done
}

// recorder is a fake Service.RecordIdentityConfig: it remembers the last
// recorded hash and refuses while closed, like a closed cluster audit gate.
type recorder struct {
	mu     sync.Mutex
	open   bool
	last   string
	writes []Summary
}

func (r *recorder) record(s Summary) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.open {
		return false
	}
	if s.Hash != r.last {
		r.writes = append(r.writes, s)
		r.last = s.Hash
	}
	return true
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestRecordChanges is the D20 hook: the boot load is recorded, a closed
// gate is retried until it opens, a change is recorded once, and an
// unchanged reload records nothing.
func TestRecordChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.yaml")
	writeIdentityFile(t, path, minimalIssuer)
	w := NewWatcher(path, nil)
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RecordChanges(ctx, w, rec.record, 5*time.Millisecond); close(done) }()

	time.Sleep(20 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("recorded while the gate was closed")
	}
	rec.mu.Lock()
	rec.open = true
	rec.mu.Unlock()
	waitFor(t, "the boot record once the gate opens", func() bool { return rec.count() == 1 })

	writeIdentityFile(t, path, minimalIssuer)
	_ = w.Reload()
	time.Sleep(20 * time.Millisecond)
	if rec.count() != 1 {
		t.Fatalf("an unchanged reload wrote a record: %d", rec.count())
	}

	writeIdentityFile(t, path, minimalIssuer+"deny_subjects: [\"okta:x\"]\n")
	if err := w.Reload(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the change record", func() bool { return rec.count() == 2 })
	rec.mu.Lock()
	got := rec.writes[1]
	rec.mu.Unlock()
	if got.Hash != w.Current().Hash() || len(got.Deny) != 1 {
		t.Fatalf("recorded %+v, want the current file", got)
	}
	cancel()
	<-done
	RecordChanges(context.Background(), nil, rec.record, time.Millisecond)
}
