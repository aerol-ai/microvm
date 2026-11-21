package operator

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A file the process may not read is reported once, and the next good load
// is applied even though the file did not change: the caller that failed
// closed must be told it can open again.
func TestWatcherOnUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var applied, unreadable atomic.Int32
	w := NewWatcher(path, nil, func(*Operator) { applied.Add(1) })
	if w.Current() == nil {
		t.Fatalf("operator file did not load: %v", w.BootError())
	}
	w.OnUnreadable(nil) // ignored
	w.OnUnreadable(func(error) { unreadable.Add(1) })
	(*Watcher)(nil).OnUnreadable(func(error) {})

	denied := &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	w.noteRead(denied)
	w.noteRead(denied)
	w.noteRead(&fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist})
	w.noteRead(nil)
	if unreadable.Load() != 1 {
		t.Fatalf("unreadable reported %d times, want once", unreadable.Load())
	}
	before := applied.Load()
	if err := w.Reload(); err != nil {
		t.Fatal(err)
	}
	if applied.Load() != before+1 {
		t.Fatal("the good load after an unreadable one was not applied")
	}
	if err := w.Reload(); err != nil || applied.Load() != before+1 {
		t.Fatal("an unchanged file was applied again")
	}

	// The poll keeps retrying while unreadable, and stops on ctx.
	w.unreadable.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for w.unreadable.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if w.unreadable.Load() {
		t.Fatal("the poll did not reload an unreadable file")
	}
	// A stat the process may not make is reported too.
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Dir(path), 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(filepath.Dir(path), 0o700)
		_ = w.Reload()
		if unreadable.Load() != 2 {
			t.Fatalf("permission-denied stat reported %d times", unreadable.Load())
		}
	}
}
