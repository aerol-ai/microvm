package containerd

import (
	"context"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
)

// taskLogCapBytes bounds each per-sandbox task log file. containerd does not
// rotate task IO, so without a cap a chatty container fills the host disk and
// takes down the SQLite store and every other sandbox on the node.
const taskLogCapBytes int64 = 4 << 20 // 4 MiB

// A task's stdout and stderr are FIFOs that this process drains into the task
// log. containerd's shim holds each FIFO open itself, so when nothing here
// reads, output backs up: the FIFO fills, then the shim's pipe from the
// process, and the next write in the sandbox blocks forever, about 128 KiB
// after draining stopped. A web server writing an access log then hangs on its
// next request (cluster-bank-flagship UC-171, 2026-11-01). Two rules follow:
//   - the log file stays open for exactly as long as containerd's copy
//     goroutines run (taskLog), never just until Create returns;
//   - a task this process is not draining is re-attached (ensureTaskDrain),
//     which is every running task after sandboxd restarts.

// Seams: containerd's FIFO IO in production; tests point it at a temp dir.
var (
	newTaskIOCreator = func(w io.Writer) cio.Creator { return cio.NewCreator(cio.WithStreams(nil, w, w)) }
	newTaskIOAttach  = func(w io.Writer) cio.Attach { return cio.NewAttach(cio.WithStreams(nil, w, w)) }
)

// taskLog is one task's output sink, a size-capped file.
type taskLog struct {
	w         *cappedWriter
	handedOff atomic.Bool
	closeOnce sync.Once
	onClose   func()
}

// openTaskLog opens path for a new task (truncated) or for a task being
// re-attached (appended, keeping the cap across sandboxd restarts).
func openTaskLog(path string, reattach bool) (*taskLog, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if reattach {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	w := &cappedWriter{f: f, cap: taskLogCapBytes}
	if reattach {
		if info, serr := f.Stat(); serr == nil {
			w.written = info.Size()
			w.capped = w.written >= w.cap
		}
	}
	return &taskLog{w: w}, nil
}

func (l *taskLog) close() {
	l.closeOnce.Do(func() {
		l.w.close()
		if l.onClose != nil {
			l.onClose()
		}
	})
}

// release is what a caller runs when it is done with the log, on every path.
// Once containerd has built the task's IO the copy goroutines own the file and
// close it when they end, so release only closes a log containerd never took.
func (l *taskLog) release() {
	if !l.handedOff.Load() {
		l.close()
	}
}

// own closes the file when tio's copy goroutines end: the task was deleted,
// or its IO was cancelled.
func (l *taskLog) own(tio cio.IO) {
	go func() {
		tio.Wait()
		l.close()
	}()
}

func (l *taskLog) creator() cio.Creator {
	inner := newTaskIOCreator(l.w)
	return func(id string) (cio.IO, error) {
		l.handedOff.Store(true)
		tio, err := inner(id)
		if err != nil {
			l.close()
			return nil, err
		}
		l.own(tio)
		return tio, nil
	}
}

func (l *taskLog) attach() cio.Attach {
	inner := newTaskIOAttach(l.w)
	return func(fifos *cio.FIFOSet) (cio.IO, error) {
		l.handedOff.Store(true)
		tio, err := inner(fifos)
		if err != nil {
			l.close()
			return nil, err
		}
		l.own(tio)
		return tio, nil
	}
}

// taskLogIO returns the cio.Creator for a new task's output, and the release
// its caller runs on return. While the task's IO lives, the driver records
// that this process drains it.
func (d *Driver) taskLogIO(path string) (cio.Creator, func(), error) {
	l, err := openTaskLog(path, false)
	if err != nil {
		return nil, nil, err
	}
	inner := l.creator()
	return func(id string) (cio.IO, error) {
		d.drainedTasks.Store(id, l)
		l.onClose = func() { d.drainedTasks.CompareAndDelete(id, l) }
		return inner(id)
	}, l.release, nil
}

// ensureTaskDrain attaches this process to a running task's stdout and stderr
// unless it already drains them. After a sandboxd restart that is every
// running task: their only reader was the previous process. One attach per
// task per process; the mark goes when the copy goroutines end.
func (d *Driver) ensureTaskDrain(ctx context.Context, container cntr.Container) {
	id := container.ID()
	if _, drained := d.drainedTasks.Load(id); drained {
		return
	}
	path, err := d.taskLogPath(id)
	if err != nil {
		return
	}
	l, err := openTaskLog(path, true)
	if err != nil {
		d.logger.Warn("containerd: reopen task log to drain a running task failed", "container", id, "error", err)
		return
	}
	if _, raced := d.drainedTasks.LoadOrStore(id, l); raced {
		l.close()
		return
	}
	l.onClose = func() { d.drainedTasks.CompareAndDelete(id, l) }
	_, err = container.Task(ctx, l.attach())
	if !l.handedOff.Load() {
		// containerd never built the IO (no task, or nothing to attach):
		// drop the mark so a later pass can try again.
		l.close()
		return
	}
	if err != nil {
		return // containerd cancels the IO it built; own() then closes the log
	}
	d.logger.Info("containerd: draining a running task's output again", "container", id)
}

// cappedWriter persists up to cap bytes then silently drops the rest while
// still reporting full writes so io.Copy keeps draining the source FIFO. A
// write that fails (disk full, file closed) is dropped the same way: a
// failed write must never stop the copy, or the task blocks. The same
// instance backs both stdout and stderr, whose copy goroutines run
// concurrently, so Write is mutex-guarded.
type cappedWriter struct {
	mu      sync.Mutex
	f       *os.File
	cap     int64
	written int64
	capped  bool
	closed  bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.written >= c.cap {
		return len(p), nil
	}
	toWrite := p
	if remaining := c.cap - c.written; int64(len(p)) > remaining {
		toWrite = p[:remaining]
	}
	n, err := c.f.Write(toWrite)
	c.written += int64(n)
	if err != nil {
		// Stop writing (the file is gone or the disk is full) but keep
		// draining: report the bytes as taken.
		c.written = c.cap
		c.capped = true
		return len(p), nil
	}
	if !c.capped && c.written >= c.cap {
		c.capped = true
		_, _ = c.f.WriteString("\n[log truncated: task exceeded " + strconv.FormatInt(c.cap, 10) + " bytes]\n")
	}
	return len(p), nil
}

func (c *cappedWriter) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		_ = c.f.Close()
	}
}
