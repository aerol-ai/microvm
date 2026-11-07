//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// These run the real inotify watcher, so only on Linux (the CI runners).

// collector drains a watcher's batch until the events it waits for arrive.
type collector struct {
	t     *testing.T
	batch *watchBatch
	seen  []watchEvent
}

func (c *collector) drain() {
	c.seen = append(c.seen, c.batch.take()...)
}

// waitFor waits until want appears, in order, as a subsequence of the events.
func (c *collector) waitFor(want ...watchEvent) {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.drain()
		if hasSubsequence(c.seen, want) {
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("events %v\nnever held, in order, %v", c.seen, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// settle collects for a while, for checks that something did NOT happen.
func (c *collector) settle() {
	time.Sleep(300 * time.Millisecond)
	c.drain()
}

func (c *collector) has(ev watchEvent) bool {
	for _, got := range c.seen {
		if got == ev {
			return true
		}
	}
	return false
}

func hasSubsequence(events, want []watchEvent) bool {
	i := 0
	for _, ev := range events {
		if i < len(want) && ev == want[i] {
			i++
		}
	}
	return i == len(want)
}

func startTestWatch(t *testing.T, root string, recursive bool, budget *watchBudget, maxDirs int) (*inotifyWatcher, *collector) {
	t.Helper()
	batch := newWatchBatch(watchMaxPending)
	dw, err := newInotifyWatcher(root, recursive, batch, budget, maxDirs)
	if err != nil {
		t.Fatalf("watch %s: %v", root, err)
	}
	w := dw.(*inotifyWatcher)
	t.Cleanup(w.Close)
	return w, &collector{t: t, batch: batch}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestInotifyEventKinds(t *testing.T) {
	root := t.TempDir()
	_, c := startTestWatch(t, root, false, newWatchBudget(4, 64), 64)
	a, b, sub := filepath.Join(root, "a.txt"), filepath.Join(root, "b.txt"), filepath.Join(root, "sub")

	must(t, os.WriteFile(a, nil, 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: a})
	f, err := os.OpenFile(a, os.O_WRONLY|os.O_APPEND, 0)
	must(t, err)
	_, err = f.WriteString("hello")
	must(t, err)
	must(t, f.Close())
	c.waitFor(watchEvent{Type: watchEventWrite, Path: a})
	must(t, os.Chmod(a, 0o600))
	c.waitFor(watchEvent{Type: watchEventChmod, Path: a})
	must(t, os.Rename(a, b))
	c.waitFor(watchEvent{Type: watchEventRename, Path: a}, watchEvent{Type: watchEventCreate, Path: b})
	must(t, os.Remove(b))
	c.waitFor(watchEvent{Type: watchEventRemove, Path: b})
	must(t, os.Mkdir(sub, 0o755))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: sub, IsDir: true})
	must(t, os.Remove(sub))
	c.waitFor(watchEvent{Type: watchEventRemove, Path: sub, IsDir: true})
	// The root's own mode change is reported; it has no parent watch.
	must(t, os.Chmod(root, 0o750))
	c.waitFor(watchEvent{Type: watchEventChmod, Path: root, IsDir: true})
}

func TestInotifyNonRecursiveIgnoresSubfolders(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	must(t, os.Mkdir(sub, 0o755))
	w, c := startTestWatch(t, root, false, newWatchBudget(4, 64), 64)
	must(t, os.WriteFile(filepath.Join(sub, "deep.txt"), []byte("x"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "top.txt"), []byte("x"), 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: filepath.Join(root, "top.txt")})
	c.settle()
	for _, ev := range c.seen {
		if strings.HasPrefix(ev.Path, sub+"/") {
			t.Fatalf("non-recursive watch reported %v", ev)
		}
	}
	if len(w.byWD) != 1 {
		t.Fatalf("non-recursive watch holds %d watches, want 1", len(w.byWD))
	}
}

func TestInotifyRecursiveWatchesExistingAndNewFolders(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "x", "y")
	must(t, os.MkdirAll(old, 0o755))
	// A link back up the tree must not be followed (it would loop).
	must(t, os.Symlink(root, filepath.Join(root, "x", "loop")))
	budget := newWatchBudget(4, 64)
	w, c := startTestWatch(t, root, true, budget, 64)
	if len(w.byWD) != 3 {
		t.Fatalf("start walk watches %d folders, want 3 (root, x, x/y): %v", len(w.byWD), w.byWD)
	}

	// A folder that existed at start.
	must(t, os.WriteFile(filepath.Join(old, "f"), []byte("x"), 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: filepath.Join(old, "f")})

	// A new nested folder with a file made before its watch could be added:
	// the scan of the new folder reports it.
	fresh := filepath.Join(root, "new", "a", "b")
	must(t, os.MkdirAll(fresh, 0o755))
	must(t, os.WriteFile(filepath.Join(fresh, "early.txt"), []byte("x"), 0o644))
	c.waitFor(
		watchEvent{Type: watchEventCreate, Path: filepath.Join(root, "new"), IsDir: true},
		watchEvent{Type: watchEventCreate, Path: filepath.Join(fresh, "early.txt")},
	)
	// And later changes inside it are watched.
	must(t, os.WriteFile(filepath.Join(fresh, "late.txt"), []byte("x"), 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: filepath.Join(fresh, "late.txt")})
	if _, dirs := budget.usage(); dirs != 6 {
		t.Fatalf("budget counts %d folders, want 6", dirs)
	}
}

func TestInotifyFolderMovedOutIsUnwatched(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	sub := filepath.Join(root, "sub")
	must(t, os.MkdirAll(filepath.Join(sub, "inner"), 0o755))
	budget := newWatchBudget(4, 64)
	w, c := startTestWatch(t, root, true, budget, 64)

	moved := filepath.Join(outside, "sub")
	must(t, os.Rename(sub, moved))
	c.waitFor(watchEvent{Type: watchEventRename, Path: sub, IsDir: true})
	must(t, os.WriteFile(filepath.Join(moved, "after.txt"), []byte("x"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "marker"), nil, 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: filepath.Join(root, "marker")})
	c.settle()
	for _, ev := range c.seen {
		if strings.Contains(ev.Path, "after.txt") {
			t.Fatalf("a folder moved out of the tree still reports: %v", ev)
		}
	}
	if len(w.byWD) != 1 {
		t.Fatalf("watches after the move = %v, want only the root", w.byWD)
	}
	if _, dirs := budget.usage(); dirs != 1 {
		t.Fatalf("budget holds %d folders after the move, want 1", dirs)
	}
}

func TestInotifyFolderRenamedInsideTree(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "old", "inner"), 0o755))
	_, c := startTestWatch(t, root, true, newWatchBudget(4, 64), 64)
	must(t, os.Rename(filepath.Join(root, "old"), filepath.Join(root, "new")))
	c.waitFor(
		watchEvent{Type: watchEventRename, Path: filepath.Join(root, "old"), IsDir: true},
		watchEvent{Type: watchEventCreate, Path: filepath.Join(root, "new"), IsDir: true},
	)
	file := filepath.Join(root, "new", "inner", "f.txt")
	must(t, os.WriteFile(file, []byte("x"), 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: file})
}

func TestInotifyWatchLimitReportsOverflow(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "b", "c"} {
		must(t, os.Mkdir(filepath.Join(root, d), 0o755))
	}
	// Per stream: the root and one folder.
	budget := newWatchBudget(4, 64)
	w, c := startTestWatch(t, root, true, budget, 2)
	c.drain()
	if len(w.byWD) != 2 {
		t.Fatalf("watches = %d, want the cap of 2", len(w.byWD))
	}
	var overflow *watchEvent
	for i, ev := range c.seen {
		if ev.Type == watchEventOverflow {
			overflow = &c.seen[i]
		}
	}
	if overflow == nil || overflow.Reason != watchOverflowLimit || overflow.Path == "" {
		t.Fatalf("start walk past the cap: events %v, want a watch_limit overflow naming a folder", c.seen)
	}
	// A new folder past the cap is reported too.
	must(t, os.Mkdir(filepath.Join(root, "d"), 0o755))
	c.waitFor(
		watchEvent{Type: watchEventCreate, Path: filepath.Join(root, "d"), IsDir: true},
		watchEvent{Type: watchEventOverflow, Path: filepath.Join(root, "d"), Reason: watchOverflowLimit},
	)
	if _, dirs := budget.usage(); dirs != 2 {
		t.Fatalf("budget = %d folders, want 2", dirs)
	}

	// The toolboxd-wide cap: a second watch finds no folder left.
	shared := newWatchBudget(4, 2)
	startTestWatch(t, root, false, shared, 64)
	startTestWatch(t, filepath.Join(root, "a"), false, shared, 64)
	if _, err := newInotifyWatcher(filepath.Join(root, "b"), false, newWatchBatch(8), shared, 64); err != errWatchLimit {
		t.Fatalf("third watch with the toolboxd cap reached: %v, want errWatchLimit", err)
	}
	if fail := watchOpenFailure(root, errWatchLimit); fail.status != http.StatusTooManyRequests {
		t.Fatalf("limit maps to %d", fail.status)
	}
}

func maxQueuedEvents(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events")
	if err != nil {
		t.Skipf("cannot read max_queued_events: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Skip(err)
	}
	return n
}

// The kernel's queue overflows while nobody reads: the watcher reports it,
// and in recursive mode rescans, so a folder made in the lost events is
// watched afterwards.
func TestInotifyKernelQueueOverflow(t *testing.T) {
	limit := maxQueuedEvents(t)
	if limit > 100000 {
		t.Skipf("max_queued_events is %d; too many files to make in a unit test", limit)
	}
	root := t.TempDir()
	batch := newWatchBatch(watchMaxPending)
	w, err := openInotifyWatcher(root, true, batch, newWatchBudget(4, 64), 64)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= limit; i++ {
		f, err := os.Create(filepath.Join(root, "f"+strconv.Itoa(i)))
		must(t, err)
		must(t, f.Close())
	}
	lost := filepath.Join(root, "made-in-the-overflow")
	must(t, os.Mkdir(lost, 0o755))
	go w.read()
	t.Cleanup(w.Close)
	c := &collector{t: t, batch: batch}
	c.waitFor(watchEvent{Type: watchEventOverflow, Reason: watchOverflowKernel})
	file := filepath.Join(lost, "after.txt")
	must(t, os.WriteFile(file, []byte("x"), 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: file})
}

// The parser on hand-made records: an overflow, a name padded with NULs,
// an unknown watch and a truncated tail.
func TestInotifyParsesRawEvents(t *testing.T) {
	root := t.TempDir()
	// Not started: this test is the only reader of the maps.
	w, err := openInotifyWatcher(root, false, newWatchBatch(16), newWatchBudget(4, 64), 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.file.Close() })
	record := func(wd int32, mask uint32, name string, pad int) []byte {
		b := make([]byte, unix.SizeofInotifyEvent+len(name)+pad)
		binary.NativeEndian.PutUint32(b[0:], uint32(wd))
		binary.NativeEndian.PutUint32(b[4:], mask)
		binary.NativeEndian.PutUint32(b[12:], uint32(len(name)+pad))
		copy(b[unix.SizeofInotifyEvent:], name)
		return b
	}
	var buf []byte
	buf = append(buf, record(-1, unix.IN_Q_OVERFLOW, "", 0)...)
	buf = append(buf, record(w.rootWD, unix.IN_CREATE, "made", 12)...)
	buf = append(buf, record(w.rootWD+100, unix.IN_CREATE, "stranger", 0)...)
	buf = append(buf, record(w.rootWD, unix.IN_CREATE, "cut-off", 0)[:unix.SizeofInotifyEvent+2]...)
	if w.handle(buf) {
		t.Fatal("handle ended the watch")
	}
	got := w.batch.take()
	want := []watchEvent{
		{Type: watchEventOverflow, Reason: watchOverflowKernel},
		{Type: watchEventCreate, Path: filepath.Join(root, "made")},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
}

func TestInotifyRootRemovedEndsTheWatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "watched")
	must(t, os.Mkdir(root, 0o755))
	budget := newWatchBudget(4, 64)
	w, c := startTestWatch(t, root, true, budget, 64)
	must(t, os.RemoveAll(root))
	select {
	case <-w.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not end when its folder was removed")
	}
	if w.Reason() != "the watched folder was removed" {
		t.Fatalf("reason = %q", w.Reason())
	}
	c.drain()
	if !c.has(watchEvent{Type: watchEventRemove, Path: root, IsDir: true}) {
		t.Fatalf("events %v have no remove for the root", c.seen)
	}
	w.Close()
	if _, dirs := budget.usage(); dirs != 0 {
		t.Fatalf("budget holds %d folders after the watch ended", dirs)
	}
}

func TestInotifyRootMovedEndsTheWatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "watched")
	must(t, os.Mkdir(root, 0o755))
	w, c := startTestWatch(t, root, false, newWatchBudget(4, 64), 64)
	must(t, os.Rename(root, filepath.Join(parent, "elsewhere")))
	select {
	case <-w.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not end when its folder moved")
	}
	c.drain()
	if w.Reason() != "the watched folder was moved" || !c.has(watchEvent{Type: watchEventRename, Path: root, IsDir: true}) {
		t.Fatalf("reason %q, events %v", w.Reason(), c.seen)
	}
}

// A root given as a symlink is followed, and events use the path given.
func TestInotifyRootSymlinkIsFollowed(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	must(t, os.Symlink(real, link))
	_, c := startTestWatch(t, link, false, newWatchBudget(4, 64), 64)
	must(t, os.WriteFile(filepath.Join(real, "f"), nil, 0o644))
	c.waitFor(watchEvent{Type: watchEventCreate, Path: filepath.Join(link, "f")})
}

// inotifyFDs counts this process's open inotify instances.
func inotifyFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	n := 0
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == "anon_inode:inotify" {
			n++
		}
	}
	return n
}

func TestInotifyCloseFreesTheKernelHandle(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	budget := newWatchBudget(4, 64)
	before := inotifyFDs(t)
	var watchers []dirWatcher
	for range 3 {
		w, err := newInotifyWatcher(root, true, newWatchBatch(8), budget, 64)
		must(t, err)
		watchers = append(watchers, w)
	}
	if got := inotifyFDs(t); got != before+3 {
		t.Fatalf("inotify fds = %d, want %d", got, before+3)
	}
	for _, w := range watchers {
		w.Close()
		w.Close() // twice is fine
		select {
		case <-w.Done():
		default:
			t.Fatal("reader still running after Close")
		}
	}
	if got := inotifyFDs(t); got != before {
		t.Fatalf("inotify fds after Close = %d, want %d", got, before)
	}
	if _, dirs := budget.usage(); dirs != 0 {
		t.Fatalf("budget holds %d folders after Close", dirs)
	}
}

// End to end through the HTTP route with the real kernel watch: a socket
// close frees the inotify instance and the stream slot.
func TestFileWatchRouteWithInotify(t *testing.T) {
	oldRuntime, oldBudget := watchRuntimeFn, fileWatchBudget
	t.Cleanup(func() { watchRuntimeFn, fileWatchBudget = oldRuntime, oldBudget })
	watchRuntimeFn = func() string { return watchRuntimeGvisor }
	budget := newWatchBudget(4, 64)
	fileWatchBudget = budget

	root := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()
	before := inotifyFDs(t)
	conn, _, err := dialWatch(t, srv, "path="+root+"&recursive=true")
	if err != nil {
		t.Fatal(err)
	}
	if start := readWatchMessage(t, conn); start.Type != "start" {
		t.Fatalf("first message = %+v", start)
	}
	must(t, os.MkdirAll(filepath.Join(root, "d"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "d", "f.txt"), []byte("x"), 0o644))
	var events []watchEvent
	deadline := time.Now().Add(5 * time.Second)
	want := watchEvent{Type: watchEventCreate, Path: filepath.Join(root, "d", "f.txt")}
	for !hasSubsequence(events, []watchEvent{want}) {
		if time.Now().After(deadline) {
			t.Fatalf("events %v never held %v", events, want)
		}
		msg := readWatchMessage(t, conn)
		events = append(events, msg.Events...)
	}
	must(t, conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")))
	_ = conn.Close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		streams, dirs := budget.usage()
		if streams == 0 && dirs == 0 && inotifyFDs(t) == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after close: %d streams, %d folders, %d inotify fds (was %d)", streams, dirs, inotifyFDs(t), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// E2B's WatchDir with the real kernel watch, and its inotify instance freed
// when the client goes.
func TestEnvdWatchDirWithInotify(t *testing.T) {
	oldRuntime, oldBudget := watchRuntimeFn, fileWatchBudget
	t.Cleanup(func() { watchRuntimeFn, fileWatchBudget = oldRuntime, oldBudget })
	watchRuntimeFn = func() string { return watchRuntimeFirecracker }
	budget := newWatchBudget(4, 64)
	fileWatchBudget = budget

	root := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()
	before := inotifyFDs(t)
	ctx, cancel := context.WithCancel(context.Background())
	resp := startEnvdWatchDir(t, srv, ctx, map[string]any{"path": root, "recursive": true}, nil)
	if _, env := readEnvelope(t, resp.Body); env["start"] == nil {
		t.Fatalf("first envelope = %v", env)
	}
	must(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sub", "f.txt"), []byte("x"), 0o644))
	seen := map[string]bool{}
	for !seen["sub/f.txt EVENT_TYPE_CREATE"] {
		_, env := readEnvelope(t, resp.Body)
		ev := filesystemEvent(t, env)
		seen[ev["name"].(string)+" "+ev["type"].(string)] = true
	}
	if !seen["sub EVENT_TYPE_CREATE"] {
		t.Fatalf("events %v have no create for the folder", seen)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		streams, dirs := budget.usage()
		if streams == 0 && dirs == 0 && inotifyFDs(t) == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the client left: %d streams, %d folders, %d inotify fds (was %d)", streams, dirs, inotifyFDs(t), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
