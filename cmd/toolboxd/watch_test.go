package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeDirWatcher stands in for inotify: the test adds events to its batch
// and ends it by hand.
type fakeDirWatcher struct {
	root      string
	recursive bool
	batch     *watchBatch
	done      chan struct{}
	endOnce   sync.Once
	reason    string
	closed    atomic.Bool
}

func (f *fakeDirWatcher) Done() <-chan struct{} { return f.done }
func (f *fakeDirWatcher) Reason() string        { return f.reason }
func (f *fakeDirWatcher) Close() {
	f.closed.Store(true)
	f.end("")
}

func (f *fakeDirWatcher) end(reason string) {
	f.endOnce.Do(func() {
		f.reason = reason
		close(f.done)
	})
}

// watchHarness swaps the watcher's seams for one test: the runtime gate, the
// kernel watch, the flush ticker and a fresh budget.
type watchHarness struct {
	t        *testing.T
	watchers chan *fakeDirWatcher
	tick     chan time.Time
	interval chan time.Duration
	budget   *watchBudget
	openErr  error
}

func newWatchHarness(t *testing.T, runtime string) *watchHarness {
	t.Helper()
	h := &watchHarness{
		t:        t,
		watchers: make(chan *fakeDirWatcher, 16),
		tick:     make(chan time.Time),
		interval: make(chan time.Duration, 16),
		budget:   newWatchBudget(4, 64),
	}
	oldRuntime, oldFactory, oldTicker, oldBudget := watchRuntimeFn, newDirWatcherFn, watchTickerFn, fileWatchBudget
	t.Cleanup(func() {
		watchRuntimeFn, newDirWatcherFn, watchTickerFn, fileWatchBudget = oldRuntime, oldFactory, oldTicker, oldBudget
	})
	watchRuntimeFn = func() string { return runtime }
	fileWatchBudget = h.budget
	watchTickerFn = func(d time.Duration) (<-chan time.Time, func()) {
		h.interval <- d
		return h.tick, func() {}
	}
	newDirWatcherFn = func(root string, recursive bool, batch *watchBatch, budget *watchBudget, maxDirs int) (dirWatcher, error) {
		if h.openErr != nil {
			return nil, h.openErr
		}
		f := &fakeDirWatcher{root: root, recursive: recursive, batch: batch, done: make(chan struct{})}
		h.watchers <- f
		return f, nil
	}
	return h
}

func (h *watchHarness) next() *fakeDirWatcher {
	h.t.Helper()
	select {
	case f := <-h.watchers:
		return f
	case <-time.After(5 * time.Second):
		h.t.Fatal("no watch was opened")
		return nil
	}
}

func (h *watchHarness) flush() {
	h.t.Helper()
	select {
	case h.tick <- time.Now():
	case <-time.After(5 * time.Second):
		h.t.Fatal("the stream never waited for a flush")
	}
}

// waitIdle waits until every stream slot is back.
func (h *watchHarness) waitIdle() {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		streams, _ := h.budget.usage()
		if streams == 0 {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%d watch streams still open", streams)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func dialWatch(t *testing.T, srv *httptest.Server, query string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/files/watch?" + query
	return websocket.DefaultDialer.Dial(url, nil)
}

func readWatchMessage(t *testing.T, conn *websocket.Conn) watchMessage {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg watchMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read watch message: %v", err)
	}
	return msg
}

func TestClassifyWatchRuntime(t *testing.T) {
	const ubuntu = "#21~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 10 12:00:00 UTC 2026"
	cases := []struct {
		name, cmdline, uname, want string
	}{
		{"firecracker guest", "console=ttyS0 reboot=k panic=1 pci=off nomodules quiet ipv6.disable_ipv6=1 ip=10.0.0.2::10.0.0.1:255.255.255.252::eth0:off init=/usr/local/bin/toolboxd-init virtio_mmio.device=4K@0xd0000000:5", "#1 SMP Mon Oct 6 00:00:00 UTC 2026", watchRuntimeFirecracker},
		{"firecracker init alone", "init=/usr/local/bin/toolboxd-init\n", "", watchRuntimeFirecracker},
		{"gvisor sentry", "BOOT_IMAGE=/vmlinuz-4.4.0 quiet\n", gvisorUnameVersion, watchRuntimeGvisor},
		{"gvisor with a newline", "", gvisorUnameVersion + "\n", watchRuntimeGvisor},
		{"runc container reads the node's", "BOOT_IMAGE=/boot/vmlinuz-6.8.0-1015-aws root=PARTUUID=abc ro console=ttyS0", ubuntu, watchRuntimeShared},
		// The snapshot export helper VM is not a sandbox and never serves HTTP.
		{"export helper vm", "console=ttyS0 reboot=k panic=1 init=/toolboxd aerolvm_export=1", ubuntu, watchRuntimeShared},
		{"init path inside another clause", "xinit=/usr/local/bin/toolboxd-init", ubuntu, watchRuntimeShared},
		{"init path as a prefix", "init=/usr/local/bin/toolboxd-init-old", ubuntu, watchRuntimeShared},
		{"nothing readable", "", "", watchRuntimeShared},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyWatchRuntime(tc.cmdline, tc.uname); got != tc.want {
				t.Fatalf("classifyWatchRuntime = %q, want %q", got, tc.want)
			}
		})
	}
}

// The runtime is read from the kernel once, at the first watch.
func TestDetectWatchRuntimeReadsOnce(t *testing.T) {
	oldCmdline, oldUname := readKernelCmdlineFn, unameVersionFn
	t.Cleanup(func() {
		readKernelCmdlineFn, unameVersionFn = oldCmdline, oldUname
		watchRuntimeOnce = sync.Once{}
		watchRuntimeCached = ""
	})
	reads := 0
	watchRuntimeOnce = sync.Once{}
	readKernelCmdlineFn = func() string { reads++; return "" }
	unameVersionFn = func() string { return gvisorUnameVersion }
	for range 3 {
		if got := detectWatchRuntime(); got != watchRuntimeGvisor {
			t.Fatalf("detectWatchRuntime = %q", got)
		}
	}
	if reads != 1 {
		t.Fatalf("the kernel command line was read %d times, want once", reads)
	}
	// The real readers work on any OS: they only must not fail.
	_ = oldCmdline()
	_ = oldUname()
}

// The Firecracker driver and toolboxd must agree on the init path, or every
// Firecracker sandbox would answer 501 to a watch.
func TestFirecrackerInitArgMatchesTheDriver(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "runtime", "firecracker", "coldboot_agent.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var guestInitPath string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if name.Name == "guestInitPath" && i < len(spec.Values) {
				if lit, ok := spec.Values[i].(*ast.BasicLit); ok {
					guestInitPath, _ = strconv.Unquote(lit.Value)
				}
			}
		}
		return true
	})
	if guestInitPath == "" {
		t.Fatalf("no guestInitPath constant in %s", path)
	}
	if firecrackerInitArg != "init="+guestInitPath {
		t.Fatalf("toolboxd looks for %q, the driver boots with init=%s", firecrackerInitArg, guestInitPath)
	}
}

func TestWatchBatchFoldsRepeatsAndKeepsOrder(t *testing.T) {
	b := newWatchBatch(100)
	for _, ev := range []watchEvent{
		{Type: watchEventCreate, Path: "/w/a"},
		{Type: watchEventWrite, Path: "/w/a"},
		{Type: watchEventWrite, Path: "/w/a"}, // folded into the write before
		{Type: watchEventWrite, Path: "/w/b"},
		{Type: watchEventWrite, Path: "/w/a"}, // still a's latest event: folded
		{Type: watchEventRemove, Path: "/w/a"},
		{Type: watchEventCreate, Path: "/w/a"}, // a create after a remove is new
		{Type: watchEventCreate, Path: "/w/d", IsDir: true},
		{Type: watchEventCreate, Path: "/w/d"}, // same path, other kind: kept
	} {
		b.add(ev)
	}
	got := b.take()
	want := []watchEvent{
		{Type: watchEventCreate, Path: "/w/a"},
		{Type: watchEventWrite, Path: "/w/a"},
		{Type: watchEventWrite, Path: "/w/b"},
		{Type: watchEventRemove, Path: "/w/a"},
		{Type: watchEventCreate, Path: "/w/a"},
		{Type: watchEventCreate, Path: "/w/d", IsDir: true},
		{Type: watchEventCreate, Path: "/w/d"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("batch = %v\nwant    %v", got, want)
	}
	if again := b.take(); again != nil {
		t.Fatalf("second take = %v, want nil", again)
	}
	// A new batch does not fold into the last one.
	b.add(watchEvent{Type: watchEventWrite, Path: "/w/b"})
	if got := b.take(); len(got) != 1 {
		t.Fatalf("after take = %v", got)
	}
}

func TestWatchBatchCapReportsOverflowOnce(t *testing.T) {
	b := newWatchBatch(3)
	for i := range 10 {
		b.add(watchEvent{Type: watchEventCreate, Path: fmt.Sprintf("/w/%d", i)})
	}
	b.addOverflow(watchOverflowKernel, "")
	b.addOverflow(watchOverflowKernel, "")
	b.addOverflow(watchOverflowLimit, "/w/deep")
	b.addOverflow(watchOverflowLimit, "/w/deeper")
	got := b.take()
	if len(got) != 6 {
		t.Fatalf("batch = %v, want 3 events and 3 overflows", got)
	}
	want := []watchEvent{
		{Type: watchEventOverflow, Reason: watchOverflowBuffer},
		{Type: watchEventOverflow, Reason: watchOverflowKernel},
		{Type: watchEventOverflow, Path: "/w/deep", Reason: watchOverflowLimit},
	}
	if fmt.Sprint(got[3:]) != fmt.Sprint(want) {
		t.Fatalf("overflows = %v, want %v", got[3:], want)
	}
	// The next batch reports a new overflow again.
	b.addOverflow(watchOverflowKernel, "")
	if got := b.take(); len(got) != 1 || got[0].Reason != watchOverflowKernel {
		t.Fatalf("next batch = %v", got)
	}
}

func TestWatchBudget(t *testing.T) {
	b := newWatchBudget(2, 3)
	if !b.openStream() || !b.openStream() || b.openStream() {
		t.Fatal("stream cap of 2 not enforced")
	}
	b.closeStream()
	if !b.openStream() {
		t.Fatal("a closed stream's slot was not given back")
	}
	for i := range 3 {
		if !b.takeDir() {
			t.Fatalf("dir %d refused under the cap", i)
		}
	}
	if b.takeDir() {
		t.Fatal("dir cap of 3 not enforced")
	}
	b.giveDirs(2)
	if streams, dirs := b.usage(); streams != 2 || dirs != 1 {
		t.Fatalf("usage = %d streams, %d dirs; want 2, 1", streams, dirs)
	}
}

func TestWatchOpenFailureStatuses(t *testing.T) {
	cases := []struct {
		err    error
		status int
		text   string
	}{
		{errWatchLimit, http.StatusTooManyRequests, "too many folders"},
		{fmt.Errorf("init: %w", syscall.EMFILE), http.StatusTooManyRequests, "no inotify instances"},
		{errFileWatchUnsupported, http.StatusNotImplemented, fileWatchUnsupportedMsg},
		{syscall.ENOSYS, http.StatusNotImplemented, fileWatchUnsupportedMsg},
		{syscall.ENOENT, http.StatusNotFound, "path not found: /w"},
		{&os.PathError{Op: "stat", Path: "/w", Err: syscall.EACCES}, http.StatusForbidden, "permission denied: /w"},
		{syscall.EPERM, http.StatusForbidden, "permission denied"},
		{syscall.ENOTDIR, http.StatusConflict, "not a folder: /w"},
		{errors.New("boom"), http.StatusInternalServerError, "file watch failed: boom"},
	}
	for _, tc := range cases {
		got := watchOpenFailure("/w", tc.err)
		if got.status != tc.status || !strings.Contains(got.Error(), tc.text) {
			t.Errorf("watchOpenFailure(%v) = %d %q, want %d containing %q", tc.err, got.status, got.msg, tc.status, tc.text)
		}
	}
}

// R8: Docker and containerd (a shared kernel) answer a clear 501 before
// anything else is checked, on the REST route and on all four E2B calls.
func TestFileWatchRefusedOnSharedKernel(t *testing.T) {
	newWatchHarness(t, watchRuntimeShared)
	h := authedRoutes(newEnvdTestServer(t))
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/files/watch?path=/does/not/matter", nil),
		httptest.NewRequest(http.MethodGet, "/files/watch", nil),
		httptest.NewRequest(http.MethodGet, "/files/watch?path=/tmp&recursive=sometimes", nil),
	}
	for _, rpc := range []string{"WatchDir", "CreateWatcher", "GetWatcherEvents", "RemoveWatcher"} {
		requests = append(requests, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/"+rpc, strings.NewReader("not even json")))
	}
	for _, req := range requests {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), fileWatchUnsupportedMsg) {
			t.Errorf("%s %s = %d %s, want 501 %q", req.Method, req.URL, rr.Code, rr.Body.String(), fileWatchUnsupportedMsg)
		}
	}
}

func TestFileWatchRefusedWithoutToken(t *testing.T) {
	newWatchHarness(t, watchRuntimeGvisor)
	srv := newEnvdTestServer(t)
	rr := httptest.NewRecorder()
	srv.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/watch?path=/tmp", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("watch without a token = %d, want 401", rr.Code)
	}
}

func TestFileWatchRequestErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		query  string
		setup  func(h *watchHarness)
		status int
		text   string
	}{
		{"no path", "", nil, http.StatusBadRequest, "path is required"},
		{"bad recursive", "path=" + dir + "&recursive=sometimes", nil, http.StatusBadRequest, "recursive must be true or false"},
		{"missing folder", "path=" + filepath.Join(dir, "nope"), nil, http.StatusNotFound, "path not found"},
		{"a file", "path=" + file, nil, http.StatusConflict, "not a folder"},
		{"all slots taken", "path=" + dir, func(h *watchHarness) {
			for h.budget.openStream() {
			}
		}, http.StatusTooManyRequests, "too many file watches"},
		{"kernel refuses", "path=" + dir, func(h *watchHarness) { h.openErr = errWatchLimit }, http.StatusTooManyRequests, "too many folders"},
		{"not a websocket", "path=" + dir, nil, http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newWatchHarness(t, watchRuntimeFirecracker)
			if tc.setup != nil {
				tc.setup(h)
			}
			streamsBefore, _ := h.budget.usage()
			rr := httptest.NewRecorder()
			authedRoutes(newEnvdTestServer(t)).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/watch?"+tc.query, nil))
			if rr.Code != tc.status || !strings.Contains(rr.Body.String(), tc.text) {
				t.Fatalf("= %d %s, want %d %q", rr.Code, rr.Body.String(), tc.status, tc.text)
			}
			if tc.name == "not a websocket" {
				// The watch was armed before the upgrade failed: it must be gone.
				if f := h.next(); !f.closed.Load() {
					t.Fatal("watch not closed after a failed upgrade")
				}
			}
			if streams, _ := h.budget.usage(); streams != streamsBefore {
				t.Fatalf("stream slots %d after a refused watch, want %d", streams, streamsBefore)
			}
		})
	}
}

// The stream protocol: start once armed, events batched per flush with
// overflow passed through, the end of the watch, then a normal close.
func TestFileWatchStreamProtocol(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeGvisor)
	dir := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()

	conn, _, err := dialWatch(t, srv, "path="+dir+"&recursive=true")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fake := h.next()
	if fake.root != dir || !fake.recursive {
		t.Fatalf("watch opened on %q recursive=%v", fake.root, fake.recursive)
	}
	if start := readWatchMessage(t, conn); start.Type != "start" || start.Path != dir || !start.Recursive {
		t.Fatalf("first message = %+v", start)
	}
	if d := <-h.interval; d != 250*time.Millisecond {
		t.Fatalf("flush interval = %v, want 250ms", d)
	}

	// Everything added between two flushes arrives in one frame.
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: dir + "/a"})
	fake.batch.add(watchEvent{Type: watchEventWrite, Path: dir + "/a"})
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: dir + "/sub", IsDir: true})
	fake.batch.addOverflow(watchOverflowKernel, "")
	h.flush()
	msg := readWatchMessage(t, conn)
	if msg.Type != "events" || len(msg.Events) != 4 {
		t.Fatalf("batch frame = %+v", msg)
	}
	if msg.Events[2] != (watchEvent{Type: watchEventCreate, Path: dir + "/sub", IsDir: true}) ||
		msg.Events[3] != (watchEvent{Type: watchEventOverflow, Reason: watchOverflowKernel}) {
		t.Fatalf("events = %+v", msg.Events)
	}

	// An empty flush sends nothing: the next frame is the next real batch.
	h.flush()
	fake.batch.add(watchEvent{Type: watchEventChmod, Path: dir + "/a"})
	h.flush()
	if msg := readWatchMessage(t, conn); len(msg.Events) != 1 || msg.Events[0].Type != watchEventChmod {
		t.Fatalf("frame after an empty flush = %+v", msg)
	}

	// The folder goes: its last events, the end, a normal close.
	fake.batch.add(watchEvent{Type: watchEventRemove, Path: dir, IsDir: true})
	fake.end("the watched folder was removed")
	if msg := readWatchMessage(t, conn); msg.Type != "events" || msg.Events[0].Type != watchEventRemove {
		t.Fatalf("last batch = %+v", msg)
	}
	if end := readWatchMessage(t, conn); end.Type != "end" || end.Reason != "the watched folder was removed" {
		t.Fatalf("end message = %+v", end)
	}
	_, _, err = conn.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("after end: %v, want a normal close", err)
	}
	h.waitIdle()
	if !fake.closed.Load() {
		t.Fatal("the kernel watch was not closed")
	}
}

// A client that goes away frees the kernel watch and the stream slot.
func TestFileWatchClientCloseCleansUp(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeFirecracker)
	dir := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()

	var fakes []*fakeDirWatcher
	var conns []*websocket.Conn
	for range 3 {
		conn, _, err := dialWatch(t, srv, "path="+dir)
		if err != nil {
			t.Fatal(err)
		}
		readWatchMessage(t, conn)
		conns = append(conns, conn)
		fakes = append(fakes, h.next())
	}
	if streams, _ := h.budget.usage(); streams != 3 {
		t.Fatalf("open streams = %d, want 3", streams)
	}
	// One closes politely, one just drops the TCP connection.
	_ = conns[0].WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = conns[0].Close()
	_ = conns[1].UnderlyingConn().Close()
	deadline := time.Now().Add(5 * time.Second)
	for !fakes[0].closed.Load() || !fakes[1].closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("watches not closed after their clients left")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if fakes[2].closed.Load() {
		t.Fatal("a live client's watch was closed")
	}
	if streams, _ := h.budget.usage(); streams != 1 {
		t.Fatalf("open streams = %d after two clients left, want 1", streams)
	}
	_ = conns[2].Close()
	h.waitIdle()
}

// The fourth watch in a sandbox capped at 3 is refused, and allowed again
// once one closes.
func TestFileWatchStreamCap(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeGvisor)
	h.budget.maxStreams = 3
	dir := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()
	var conns []*websocket.Conn
	for range 3 {
		conn, _, err := dialWatch(t, srv, "path="+dir)
		if err != nil {
			t.Fatal(err)
		}
		readWatchMessage(t, conn)
		h.next()
		conns = append(conns, conn)
	}
	_, resp, err := dialWatch(t, srv, "path="+dir)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("fourth watch: err=%v resp=%v, want 429", err, resp)
	}
	_ = conns[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, _, err := dialWatch(t, srv, "path="+dir)
		if err == nil {
			readWatchMessage(t, conn)
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slot after a watch closed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, c := range conns[1:] {
		_ = c.Close()
	}
	h.waitIdle()
}

// A connection that drops while events wait to be sent ends the stream and
// frees the watch.
func TestFileWatchDroppedConnectionWithPendingEvents(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeGvisor)
	dir := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()
	conn, _, err := dialWatch(t, srv, "path="+dir)
	if err != nil {
		t.Fatal(err)
	}
	readWatchMessage(t, conn)
	fake := h.next()
	// Drop the TCP connection under the server, then make it write.
	_ = conn.UnderlyingConn().Close()
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: dir + "/a"})
	select {
	case h.tick <- time.Now():
	case <-time.After(5 * time.Second):
	}
	h.waitIdle()
	if !fake.closed.Load() {
		t.Fatal("watch not closed")
	}
}

func TestWatchMessageJSON(t *testing.T) {
	raw, err := json.Marshal(watchMessage{Type: "events", Events: []watchEvent{
		{Type: watchEventCreate, Path: "/w/a"},
		{Type: watchEventCreate, Path: "/w/d", IsDir: true},
		{Type: watchEventOverflow, Reason: watchOverflowBuffer},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"events","events":[{"type":"create","path":"/w/a"},{"type":"create","path":"/w/d","is_dir":true},{"type":"overflow","reason":"event_buffer"}]}`
	if string(raw) != want {
		t.Fatalf("wire = %s\nwant   %s", raw, want)
	}
}
