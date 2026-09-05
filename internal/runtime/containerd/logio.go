package containerd

import (
	"os"
	"strconv"
	"sync"

	"github.com/containerd/containerd/v2/pkg/cio"
)

// taskLogCapBytes bounds each per-sandbox task log file. containerd does not
// rotate task IO, so without a cap a chatty container fills the host disk and
// takes down the SQLite store and every other sandbox on the node.
const taskLogCapBytes int64 = 4 << 20 // 4 MiB

// taskLogIO returns a cio.Creator that persists task stdout/stderr to a
// size-capped file. The FIFO copy goroutine always sees a full write (the
// capped writer reports len(p) even after the cap), so the container never
// blocks on a full pipe once the file stops growing.
func taskLogIO(path string) (cio.Creator, func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	w := &cappedWriter{f: f, cap: taskLogCapBytes}
	creator := cio.NewCreator(cio.WithStreams(nil, w, w))
	return creator, func() { _ = f.Close() }, nil
}

// cappedWriter persists up to cap bytes then silently drops the rest while
// still reporting full writes so io.Copy keeps draining the source FIFO. The
// same instance backs both stdout and stderr, whose copy goroutines run
// concurrently, so Write is mutex-guarded.
type cappedWriter struct {
	mu      sync.Mutex
	f       *os.File
	cap     int64
	written int64
	capped  bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.written >= c.cap {
		return len(p), nil
	}
	toWrite := p
	if remaining := c.cap - c.written; int64(len(p)) > remaining {
		toWrite = p[:remaining]
	}
	n, err := c.f.Write(toWrite)
	c.written += int64(n)
	if !c.capped && c.written >= c.cap {
		c.capped = true
		_, _ = c.f.WriteString("\n[log truncated: task exceeded " + strconv.FormatInt(c.cap, 10) + " bytes]\n")
	}
	if err != nil {
		return n, err
	}
	return len(p), nil
}
