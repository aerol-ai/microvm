package main

// watch.go streams file-system events for a folder (plan F5,
// plans/agent-sandbox-feature-parity.md). The kernel side is inotify
// (watch_linux.go); this file holds what does not need Linux: the runtime
// gate, the limits, the 250 ms batching and the WebSocket protocol. E2B's
// envd watcher calls share all of it (envd_watch.go).
//
// Wire protocol of GET /files/watch?path=...&recursive=true (a WebSocket):
//
//	{"type":"start","path":"/abs","recursive":true}  once, when the watch is armed
//	{"type":"events","events":[{"type":"create","path":"/abs/a","is_dir":false},...]}
//	{"type":"end","reason":"..."}                     the watch ended on its own
//
// Event types are create, write, remove, rename and chmod, plus overflow
// ({"type":"overflow","reason":"kernel_queue|event_buffer|watch_limit"}),
// which means events were lost and the caller should list the folder again.
// A rename shows as rename for the old name and create for the new one, as
// inotify reports it. The client sends nothing; it closes the socket to stop.
// Failures before the upgrade are plain JSON errors (400, 403, 404, 409, 429,
// 501), so an SDK can tell them apart.

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

const (
	watchEventCreate   = "create"
	watchEventWrite    = "write"
	watchEventRemove   = "remove"
	watchEventRename   = "rename"
	watchEventChmod    = "chmod"
	watchEventOverflow = "overflow"

	// Overflow reasons. Each one means some events were not delivered.
	watchOverflowKernel = "kernel_queue" // IN_Q_OVERFLOW: the kernel dropped events
	watchOverflowBuffer = "event_buffer" // more than watchMaxPending events in one batch
	watchOverflowLimit  = "watch_limit"  // a folder could not be watched (limits below)

	// watchFlushInterval batches events: an editor saving a file or a build
	// writing thousands produces bursts, and one frame per burst is far
	// cheaper for the client and every proxy on the way than one per event.
	watchFlushInterval = 250 * time.Millisecond
	// watchWriteWait bounds one frame's write, so a client that stopped
	// reading frees its watch instead of holding it until TCP gives up.
	watchWriteWait = 10 * time.Second

	fileWatchUnsupportedMsg = "file watching needs a gVisor or Firecracker sandbox"
)

// The limits are variables so tests can lower them. Every stream holds one
// inotify instance and every watched folder one inotify watch, both drawn
// from the sandbox kernel's per-user budget (fs.inotify.max_user_instances,
// default 128, and max_user_watches, as low as 8192 in a small VM) that the
// user's own tools (dev servers, test watchers) need too. The caps keep the
// agent to a share of it.
var (
	// watchMaxDirsPerStream caps the folders one recursive watch may hold.
	watchMaxDirsPerStream = 8192
	// watchMaxPending caps the events held for one stream between flushes;
	// beyond it events are dropped and an overflow is reported.
	watchMaxPending = 4096
	// fileWatchBudget is shared by every stream in this toolboxd: at most 16
	// watches open at once (a 17th answers 429) and 16384 folders in all.
	fileWatchBudget = newWatchBudget(16, 16384)
)

// errWatchLimit is a folder refused because a cap above (or the kernel's
// max_user_watches) is reached.
var errWatchLimit = errors.New("file watch limit reached")

// errFileWatchUnsupported is a build without inotify (toolboxd off Linux).
var errFileWatchUnsupported = errors.New(fileWatchUnsupportedMsg)

// watchEvent is one change, as sent to the client.
type watchEvent struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	IsDir  bool   `json:"is_dir,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// watchMessage is one WebSocket frame from toolboxd.
type watchMessage struct {
	Type      string       `json:"type"`
	Path      string       `json:"path,omitempty"`
	Recursive bool         `json:"recursive,omitempty"`
	Events    []watchEvent `json:"events,omitempty"`
	Reason    string       `json:"reason,omitempty"`
}

// watchBatch collects one stream's events until the next flush. The inotify
// reader adds, the stream loop takes.
type watchBatch struct {
	mu     sync.Mutex
	events []watchEvent
	// last maps a path to the index of its latest event, so a repeat of that
	// same event (a big write is hundreds of IN_MODIFY) is folded into it.
	// Only a repeat of the latest one folds: create, remove, create keeps all
	// three, in order.
	last     map[string]int
	overflow map[string]bool // reasons already reported in this batch
	max      int
}

func newWatchBatch(max int) *watchBatch {
	return &watchBatch{last: map[string]int{}, overflow: map[string]bool{}, max: max}
}

func (b *watchBatch) add(ev watchEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if i, ok := b.last[ev.Path]; ok && b.events[i].Type == ev.Type && b.events[i].IsDir == ev.IsDir {
		return
	}
	if len(b.events) >= b.max {
		b.overflowLocked(watchOverflowBuffer, "")
		return
	}
	b.last[ev.Path] = len(b.events)
	b.events = append(b.events, ev)
}

// addOverflow reports lost events. It is not bound by max: the client must
// learn that it missed something even when the batch is full.
func (b *watchBatch) addOverflow(reason, path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.overflowLocked(reason, path)
}

func (b *watchBatch) overflowLocked(reason, path string) {
	// One per reason per batch: a recursive watch past its limit refuses
	// every new folder, and one report says what the client needs to know.
	if b.overflow[reason] {
		return
	}
	b.overflow[reason] = true
	b.events = append(b.events, watchEvent{Type: watchEventOverflow, Path: path, Reason: reason})
}

// take returns the batch and starts a new one; nil when empty.
func (b *watchBatch) take() []watchEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) == 0 {
		return nil
	}
	out := b.events
	b.events = nil
	clear(b.last)
	clear(b.overflow)
	return out
}

// watchBudget is toolboxd's share of the kernel's inotify budget.
type watchBudget struct {
	mu         sync.Mutex
	streams    int
	dirs       int
	maxStreams int
	maxDirs    int
}

func newWatchBudget(maxStreams, maxDirs int) *watchBudget {
	return &watchBudget{maxStreams: maxStreams, maxDirs: maxDirs}
}

func (b *watchBudget) openStream() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.streams >= b.maxStreams {
		return false
	}
	b.streams++
	return true
}

func (b *watchBudget) closeStream() {
	b.mu.Lock()
	b.streams--
	b.mu.Unlock()
}

func (b *watchBudget) takeDir() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dirs >= b.maxDirs {
		return false
	}
	b.dirs++
	return true
}

func (b *watchBudget) giveDirs(n int) {
	b.mu.Lock()
	b.dirs -= n
	b.mu.Unlock()
}

func (b *watchBudget) usage() (streams, dirs int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.streams, b.dirs
}

// dirWatcher is one stream's kernel watch.
type dirWatcher interface {
	// Done is closed when the watch has ended: on its own (the watched
	// folder was removed or moved) or after Close.
	Done() <-chan struct{}
	// Reason says why the watch ended on its own. Valid once Done is closed.
	Reason() string
	// Close frees the kernel handle and waits for the reader goroutine. It
	// is safe to call more than once.
	Close()
}

// dirWatcherFactory starts a watch on root, adding events to batch and
// drawing folders from budget, at most maxDirs of them.
type dirWatcherFactory func(root string, recursive bool, batch *watchBatch, budget *watchBudget, maxDirs int) (dirWatcher, error)

// Runtime gate (CEO review R8, D16). On Docker and containerd (runc) every
// sandbox's root is the host's root user, and the kernel's inotify budget is
// per user: a sandbox that holds watches spends what every other sandbox on
// the node, and the node itself, need. gVisor's sentry and a Firecracker
// guest each run their own kernel with its own budget, so only they may
// watch. This is the product's policy, not an isolation boundary: root in a
// runc container can call inotify_init itself; the agent just does not offer
// a feature that would make it routine.
const (
	watchRuntimeFirecracker = "firecracker"
	watchRuntimeGvisor      = "gvisor"
	watchRuntimeShared      = "shared-kernel"

	// firecrackerInitArg is the kernel command-line clause the Firecracker
	// driver boots every agent guest with (coldBootArgs in
	// internal/runtime/firecracker/coldboot_agent.go, init= guestInitPath),
	// on cold boot and when a template is captured; a snapshot or warm-pool
	// restore keeps the kernel's command line. A container reads the node's
	// command line here, and gVisor makes up its own, so neither has it.
	// TestFirecrackerInitArgMatchesTheDriver keeps the two in step.
	firecrackerInitArg = "init=/usr/local/bin/toolboxd-init"
	// gvisorUnameVersion is the kernel version gVisor's sentry reports from
	// uname(2) (gvisor pkg/sentry/kernel/version.LinuxVersion), unchanged
	// since gVisor was released. A container reports the node's real kernel
	// build string, which is never this. A gVisor release that changed it
	// would make watching answer 501 (fail closed); UC-390 catches that.
	gvisorUnameVersion = "#1 SMP Sun Jan 10 15:06:54 PST 2016"
)

// classifyWatchRuntime names the runtime from the kernel command line and
// the uname version string.
func classifyWatchRuntime(cmdline, unameVersion string) string {
	for _, field := range strings.Fields(cmdline) {
		if field == firecrackerInitArg {
			return watchRuntimeFirecracker
		}
	}
	if strings.TrimSpace(unameVersion) == gvisorUnameVersion {
		return watchRuntimeGvisor
	}
	return watchRuntimeShared
}

var (
	readKernelCmdlineFn = func() string {
		raw, err := os.ReadFile("/proc/cmdline")
		if err != nil {
			return ""
		}
		return string(raw)
	}
	unameVersionFn = func() string {
		var u unix.Utsname
		if err := unix.Uname(&u); err != nil {
			return ""
		}
		return unix.ByteSliceToString(u.Version[:])
	}

	watchRuntimeOnce   sync.Once
	watchRuntimeCached string

	// watchRuntimeFn is a seam for tests.
	watchRuntimeFn = detectWatchRuntime
)

// detectWatchRuntime reads the runtime once: it cannot change while
// toolboxd runs.
func detectWatchRuntime() string {
	watchRuntimeOnce.Do(func() {
		watchRuntimeCached = classifyWatchRuntime(readKernelCmdlineFn(), unameVersionFn())
	})
	return watchRuntimeCached
}

func fileWatchAllowed() bool {
	switch watchRuntimeFn() {
	case watchRuntimeFirecracker, watchRuntimeGvisor:
		return true
	}
	return false
}

// watchTickerFn is a seam for tests: they flush by hand instead of waiting
// for the interval.
var watchTickerFn = func(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// watchRequestError is a watch refused before it starts, with the HTTP
// status the REST and envd handlers answer.
type watchRequestError struct {
	status int
	msg    string
}

func (e *watchRequestError) Error() string { return e.msg }

// fileWatch is one open watch: a stream slot, a kernel watch and its batch.
type fileWatch struct {
	root      string
	recursive bool
	batch     *watchBatch
	watcher   dirWatcher
	budget    *watchBudget
	closeOnce sync.Once
}

// openFileWatch checks the runtime and the path, takes a stream slot and
// arms the kernel watch. The order matters: the gate comes first so an
// unsupported sandbox always answers 501, whatever the path.
func openFileWatch(rawPath string, recursive bool) (*fileWatch, *watchRequestError) {
	if !fileWatchAllowed() {
		return nil, &watchRequestError{http.StatusNotImplemented, fileWatchUnsupportedMsg}
	}
	root, err := resolveDaytonaPath(rawPath, false)
	if err != nil {
		return nil, &watchRequestError{http.StatusBadRequest, err.Error()}
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, watchOpenFailure(root, err)
	}
	if !info.IsDir() {
		return nil, &watchRequestError{http.StatusConflict, "not a folder: " + root}
	}
	budget := fileWatchBudget
	if !budget.openStream() {
		return nil, &watchRequestError{http.StatusTooManyRequests, "too many file watches open in this sandbox; stop one first"}
	}
	batch := newWatchBatch(watchMaxPending)
	watcher, err := newDirWatcherFn(root, recursive, batch, budget, watchMaxDirsPerStream)
	if err != nil {
		budget.closeStream()
		return nil, watchOpenFailure(root, err)
	}
	return &fileWatch{root: root, recursive: recursive, batch: batch, watcher: watcher, budget: budget}, nil
}

func (fw *fileWatch) close() {
	fw.closeOnce.Do(func() {
		fw.watcher.Close()
		fw.budget.closeStream()
	})
}

// watchOpenFailure maps an error from stat or the kernel to a status.
func watchOpenFailure(path string, err error) *watchRequestError {
	switch {
	case errors.Is(err, errWatchLimit):
		return &watchRequestError{http.StatusTooManyRequests, "too many folders watched in this sandbox; stop another watch or watch a smaller folder"}
	case errors.Is(err, syscall.EMFILE):
		// fs.inotify.max_user_instances: the user's own tools hold the rest.
		return &watchRequestError{http.StatusTooManyRequests, "this sandbox's kernel has no inotify instances left; stop another file watcher"}
	case errors.Is(err, errFileWatchUnsupported), errors.Is(err, syscall.ENOSYS):
		return &watchRequestError{http.StatusNotImplemented, fileWatchUnsupportedMsg}
	case errors.Is(err, os.ErrNotExist):
		return &watchRequestError{http.StatusNotFound, "path not found: " + path}
	case errors.Is(err, os.ErrPermission):
		return &watchRequestError{http.StatusForbidden, "permission denied: " + path}
	case errors.Is(err, syscall.ENOTDIR):
		return &watchRequestError{http.StatusConflict, "not a folder: " + path}
	}
	return &watchRequestError{http.StatusInternalServerError, "file watch failed: " + err.Error()}
}

// handleFileWatch is GET /files/watch.
func (s *server) handleFileWatch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	recursive := false
	if raw := strings.TrimSpace(q.Get("recursive")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "recursive must be true or false")
			return
		}
		recursive = parsed
	}
	fw, werr := openFileWatch(q.Get("path"), recursive)
	if werr != nil {
		writeError(w, werr.status, werr.msg)
		return
	}
	conn, err := execStreamUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade wrote the HTTP error itself.
		fw.close()
		return
	}
	s.serveFileWatch(conn, fw)
}

// serveFileWatch runs one watch stream until the client goes, the watch ends
// on its own, or a write fails. It returns only once the kernel watch, the
// reader and the pinger are gone, so nothing outlives the socket.
func (s *server) serveFileWatch(conn *websocket.Conn, fw *fileWatch) {
	clientGone := make(chan struct{})
	defer func() {
		fw.close()
		_ = conn.Close()
		<-clientGone
	}()

	// The same keepalive as the exec stream: a watch can be silent for
	// hours, and proxies close sockets that look idle.
	extend, stopPings := armExecStreamLiveness(conn, s.execStreamLiveness())
	defer stopPings()
	go func() {
		defer close(clientGone)
		for {
			// The client sends nothing but control frames; reading is how
			// gorilla handles them and how a close is noticed.
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			extend()
		}
	}()

	if err := writeWatchMessage(conn, watchMessage{Type: "start", Path: fw.root, Recursive: fw.recursive}); err != nil {
		return
	}
	tick, stopTick := watchTickerFn(watchFlushInterval)
	defer stopTick()
	for {
		select {
		case <-clientGone:
			return
		case <-fw.watcher.Done():
			if flushWatchBatch(conn, fw.batch) != nil {
				return
			}
			_ = writeWatchMessage(conn, watchMessage{Type: "end", Reason: fw.watcher.Reason()})
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(watchWriteWait))
			return
		case <-tick:
			if err := flushWatchBatch(conn, fw.batch); err != nil {
				s.logger.Debug("file watch stream write failed", "path", fw.root, "error", err)
				return
			}
		}
	}
}

func flushWatchBatch(conn *websocket.Conn, batch *watchBatch) error {
	events := batch.take()
	if len(events) == 0 {
		return nil
	}
	return writeWatchMessage(conn, watchMessage{Type: "events", Events: events})
}

func writeWatchMessage(conn *websocket.Conn, msg watchMessage) error {
	if err := conn.SetWriteDeadline(time.Now().Add(watchWriteWait)); err != nil {
		return err
	}
	return conn.WriteJSON(msg)
}
