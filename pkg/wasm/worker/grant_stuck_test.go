//go:build unix

package worker

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// hungOpens stands in an open that hangs in the kernel for each FIFO in
// fifos (an open of a FIFO for reading waits for a writer, as an open on a
// stalled NFS or FUSE mount waits for its server), and counts the opens
// stuck there right now.
func hungOpens(t *testing.T, fifos ...string) *atomic.Int32 {
	t.Helper()
	var stuck atomic.Int32
	hung := map[string]bool{}
	for _, f := range fifos {
		if err := syscall.Mkfifo(f, 0o600); err != nil {
			t.Fatal(err)
		}
		hung[f] = true
	}
	prev := grantOpener
	grantOpener = func(path string, strict bool) (*os.File, error) {
		if !hung[path] {
			return openGrantPath(path, strict)
		}
		stuck.Add(1)
		defer stuck.Add(-1)
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	t.Cleanup(func() {
		// Let every stuck open return before the next test.
		for _, f := range fifos {
			if fd, err := syscall.Open(f, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0); err == nil {
				_ = syscall.Close(fd)
			}
		}
		waitFor(t, "the stuck opens to return", func() bool { return stuck.Load() == 0 })
		grantOpener = prev
	})
	return &stuck
}

// An open stuck on a stalled mount holds one of sandboxd's threads until it
// returns. Every message that names the path again (each exec, instantiate,
// set-capability and restore names the sandbox's mounts) must not start
// another: that would grow sandboxd's threads without bound.
func TestOpenGrantStuckPathOpensOnce(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "stalled-mount")
	stuck := hungOpens(t, fifo)
	if _, err := openGrant(fifo, 20*time.Millisecond, false); !errors.Is(err, errGrantTimeout) {
		t.Fatalf("first open = %v, want a timeout", err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, err := openGrant(fifo, 20*time.Millisecond, false); err == nil {
				_ = f.Close()
				t.Error("a stuck path opened")
			}
		}()
	}
	wg.Wait()
	if n := stuck.Load(); n != 1 {
		t.Fatalf("%d opens of the stalled path are stuck, want 1", n)
	}
}

// A grant's open is bounded: one that hangs in the kernel (a stalled
// mount) times out, the message goes without that grant, and the path is
// not opened again until the stuck open returns, when its file is closed.
func TestOpenGrantTimesOut(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// A FIFO itself is refused at once: the open does not wait for a
	// writer (O_NONBLOCK), and it is not a folder or a regular file.
	if f, err := openGrant(fifo, 5*time.Second, false); err == nil || errors.Is(err, errGrantTimeout) {
		_ = f
		t.Fatalf("FIFO grant = %v, want refused at once", err)
	}
	hung := filepath.Join(dir, "stalled-mount")
	stuck := hungOpens(t, hung)
	start := time.Now()
	if _, err := openGrant(hung, 50*time.Millisecond, false); !errors.Is(err, errGrantTimeout) {
		t.Fatalf("hung open = %v, want a timeout", err)
	}
	if took := time.Since(start); took > 5*time.Second || stuck.Load() != 1 {
		t.Fatalf("hung open gave up after %v with %d stuck", took, stuck.Load())
	}
	if _, err := openGrant(hung, 5*time.Second, false); !errors.Is(err, errGrantStuck) {
		t.Fatalf("second open of the stuck path = %v, want refused at once", err)
	}
	// Other paths open as before, and a message naming both goes with the
	// one that opened.
	files, names := openGrants([]string{hung, dir})
	closeFiles(files)
	if len(names) != 1 || names[0] != dir {
		t.Fatalf("granted %v, want only %s", names, dir)
	}
	// The mount answers: the stuck open returns, its file is closed, and
	// the path opens again.
	fd, err := syscall.Open(hung, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the stuck open to return", func() bool {
		grantOpensMu.Lock()
		defer grantOpensMu.Unlock()
		_, still := grantStuck[hung]
		return !still && stuck.Load() == 0
	})
	_ = syscall.Close(fd)
}

// At most maxGrantOpens opens run at once, stuck ones included: stalled
// mounts cannot take sandboxd's threads up to the runtime's limit.
func TestOpenGrantCapsOpensInFlight(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	stuck := hungOpens(t, a, b)
	prev := maxGrantOpens
	maxGrantOpens = 2
	t.Cleanup(func() { maxGrantOpens = prev })
	for _, p := range []string{a, b} {
		if _, err := openGrant(p, 20*time.Millisecond, false); !errors.Is(err, errGrantTimeout) {
			t.Fatalf("%s = %v", p, err)
		}
	}
	if _, err := openGrant(dir, 5*time.Second, false); !errors.Is(err, errGrantBusy) {
		t.Fatalf("open past the cap = %v, want refused at once", err)
	}
	if stuck.Load() != 2 {
		t.Fatalf("%d stuck, want 2", stuck.Load())
	}
	for _, p := range []string{a, b} {
		if fd, err := syscall.Open(p, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0); err == nil {
			defer syscall.Close(fd)
		}
	}
	waitFor(t, "the stuck opens to end", func() bool {
		grantOpensMu.Lock()
		defer grantOpensMu.Unlock()
		return len(grantStuck) == 0
	})
	f, err := openGrant(dir, 5*time.Second, false)
	if err != nil {
		t.Fatalf("open once the stuck ones ended = %v", err)
	}
	_ = f.Close()
}
