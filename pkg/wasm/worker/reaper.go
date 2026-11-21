package worker

import (
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"syscall"
	"weak"
)

// A worker is hostile once tenant code has escaped its engine, and a
// descriptor it sends sandboxd can make the last close or release of it
// block for good: a file on a FUSE or NFS mount whose server the tenant
// runs (FUSE flushes on every close(2); NFSv4 sends CLOSE on the last
// release and, on a hard mount, waits for the answer). The kernel releases
// a descriptor that rides a message wherever the message is dropped: a
// read(2) that takes the segment, or the close of a socket with it still
// queued. So no request goroutine of sandboxd's closes, or lets the kernel
// release, a descriptor a worker sent unless it is a socket:
//
//   - replies are read with every descriptor left in the socket's queue
//     (workerConn, Linux: a peek tells whether a segment carries any
//     without taking them), and a reply that carries one is refused;
//   - guest_listener's reply takes exactly one, which must be a socket:
//     getsockopt answers ENOTSOCK for anything else without touching a
//     file system, and closing a socket a worker made does not wait (the
//     worker may not set SO_LINGER);
//   - a connection whose queue may still hold descriptors, and any other
//     descriptor a worker sent, goes to the reaper: one goroutine with a
//     bounded queue, so stalled mounts hold one thread of sandboxd's in
//     all;
//   - a worker that sent one has broken the protocol and is quarantined:
//     sandboxd opens no connection to it, its supervisor kills it and does
//     not restart it, and its slot stays refused until it is stopped (a
//     sandbox stop or destroy).
//
// What a worker can leave with the reaper is bounded by what was in flight
// with it when it broke the protocol: one connection per exchange, plus the
// one descriptor a guest_listener reply takes. A reaper stalled for good
// fills its queue; what comes after is kept open, never closed on a
// request's goroutine, and counted (aerolvm_wasm_worker_reaper_held_total).

// ErrWorkerQuarantined: the worker sent sandboxd a descriptor outside the
// protocol, so sandboxd talks to it no more and its slot is not restarted
// until it is stopped.
var ErrWorkerQuarantined = errors.New("wasm worker quarantined: it sent sandboxd a descriptor outside the protocol")

// errWorkerSentFDs fails an exchange whose reply carried descriptors it
// may not carry.
var errWorkerSentFDs = errors.New("wasm worker sent descriptors the protocol does not allow")

var (
	workerQuarantines = expvar.NewInt("aerolvm_wasm_worker_quarantined_total")
	workerReaperHeld  = expvar.NewInt("aerolvm_wasm_worker_reaper_held_total")
)

// reaperQueue is how many closes wait behind one that stalls.
const reaperQueue = 1024

var reaper struct {
	once  sync.Once
	queue chan io.Closer
	mu    sync.Mutex
	// held is what came while the queue was full: kept referenced, since an
	// *os.File or connection nothing refers to is closed by its finalizer,
	// on the runtime's one finalizer goroutine.
	held []io.Closer
}

// reap closes c on the reaper's goroutine. It never blocks.
func reap(c io.Closer) {
	reaper.once.Do(func() {
		reaper.queue = make(chan io.Closer, reaperQueue)
		go func() {
			for c := range reaper.queue {
				_ = c.Close()
			}
		}()
	})
	select {
	case reaper.queue <- c:
	default:
		reaper.mu.Lock()
		reaper.held = append(reaper.held, c)
		reaper.mu.Unlock()
		workerReaperHeld.Add(1)
	}
}

// fdCloser closes a bare descriptor; unlike an *os.File it has no
// finalizer to close it anywhere else.
type fdCloser int

func (fd fdCloser) Close() error { return syscall.Close(int(fd)) }

// quarantined holds the socket paths of quarantined workers.
var quarantined sync.Map

// quarantineWorker quarantines the worker at path (see the top of this
// file): every supervisor that runs it kills it and keeps it down.
func quarantineWorker(path, why string) {
	if _, loaded := quarantined.LoadOrStore(path, why); loaded {
		return
	}
	workerQuarantines.Add(1)
	slog.Warn("wasm worker broke the protocol: sandboxd stops talking to it and stops it", "socket", path, "why", why)
	for _, s := range liveSupervisors() {
		s.quarantine(path)
	}
}

// workerQuarantined is ErrWorkerQuarantined for a quarantined path.
func workerQuarantined(path string) error {
	if why, ok := quarantined.Load(path); ok {
		return fmt.Errorf("%w (%v)", ErrWorkerQuarantined, why)
	}
	return nil
}

// supervisors lists every Supervisor, weakly: a quarantine reaches the one
// that runs the worker without keeping any alive.
var supervisors struct {
	sync.Mutex
	list []weak.Pointer[Supervisor]
}

func registerSupervisor(s *Supervisor) {
	supervisors.Lock()
	defer supervisors.Unlock()
	supervisors.list = append(liveLocked(nil), weak.Make(s))
}

func liveSupervisors() []*Supervisor {
	supervisors.Lock()
	defer supervisors.Unlock()
	var out []*Supervisor
	supervisors.list = liveLocked(&out)
	return out
}

// liveLocked drops collected supervisors from the list, and appends the
// rest to out when it is set.
func liveLocked(out *[]*Supervisor) []weak.Pointer[Supervisor] {
	kept := supervisors.list[:0]
	for _, w := range supervisors.list {
		if s := w.Value(); s != nil {
			kept = append(kept, w)
			if out != nil {
				*out = append(*out, s)
			}
		}
	}
	return kept
}
