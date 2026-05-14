// Package netstats reads per-sandbox network byte counters from
// /proc/<pid>/net/dev. The procfs `net/` subtree is per-netns: opening it
// through a process PID joins that PID's network namespace, so a host-side
// reader sees the container's interfaces (eth0 etc.) and their cumulative
// rx/tx_bytes from the container's perspective.
//
// rx/tx semantics here are the *container's*: rx_bytes = bytes the container
// received (= ingress to the sandbox = NetworkBytesIn); tx_bytes = bytes the
// container sent (= egress from the sandbox = NetworkBytesOut). This matches
// what an operator would intuitively bill against.
//
// We deliberately ignore the host-side veth (the peer interface visible in
// the host netns). That path is correct too, but discovering it requires
// matching iflink/ifindex pairs — measurably more code than just reading
// /proc/<pid>/net/dev for a number that is already per-netns by construction.
//
// The "lo" interface is skipped: pure intra-container loopback shouldn't
// count against an external network quota.
package netstats

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// ErrNotRunning is returned when the procfs entry for the requested PID is
// gone — typically because the container exited between the caller obtaining
// the PID and the read. Callers should treat it as "no sample this tick"
// rather than a hard error, since reconcile/event paths will pick up the
// state change shortly.
var ErrNotRunning = errors.New("netstats: container process not present")

// Counters is one snapshot of per-container byte counters. Cumulative since
// container start — the poller computes deltas itself so it can survive
// container restarts without double-counting.
type Counters struct {
	BytesIn  int64 // container rx (ingress to sandbox)
	BytesOut int64 // container tx (egress from sandbox)
}

// Reader reads /proc/<pid>/net/dev. The fs.FS indirection exists so tests
// can supply an in-memory fixture — the production caller passes nil to use
// the real /proc.
type Reader struct {
	fsys fs.FS // when nil, reads /proc/<pid>/net/dev directly via os.Open
}

// NewReader builds a Reader against the host /proc.
func NewReader() *Reader { return &Reader{} }

// NewReaderFS builds a Reader against an injected filesystem rooted such
// that "<pid>/net/dev" resolves correctly. Used by tests.
func NewReaderFS(fsys fs.FS) *Reader { return &Reader{fsys: fsys} }

// Read returns the cumulative per-container byte counters for the given PID.
// PID 0 (Docker reports Pid:0 for a non-running container) yields
// ErrNotRunning so the poller can short-circuit without a procfs lookup.
func (r *Reader) Read(pid int) (Counters, error) {
	if pid <= 0 {
		return Counters{}, ErrNotRunning
	}

	data, err := r.openNetDev(pid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return Counters{}, ErrNotRunning
		}
		return Counters{}, err
	}
	defer data.Close()

	return parseNetDev(data)
}

// openNetDev returns a closer-backed reader for /proc/<pid>/net/dev.
type readCloser interface {
	Read([]byte) (int, error)
	Close() error
}

func (r *Reader) openNetDev(pid int) (readCloser, error) {
	if r.fsys != nil {
		f, err := r.fsys.Open(fmt.Sprintf("%d/net/dev", pid))
		if err != nil {
			return nil, err
		}
		return f.(readCloser), nil
	}
	return os.Open(fmt.Sprintf("/proc/%d/net/dev", pid))
}

// parseNetDev sums non-loopback rx/tx_bytes columns from a /proc/net/dev
// formatted stream. Format (after a 2-line header):
//
//	iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets ...
//
// Columns are whitespace-separated; rx_bytes is field index 1, tx_bytes is
// field index 9 of the post-colon tail.
func parseNetDev(r readCloser) (Counters, error) {
	scanner := bufio.NewScanner(r)
	var c Counters
	headerLines := 0
	for scanner.Scan() {
		if headerLines < 2 {
			headerLines++
			continue
		}
		line := scanner.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "" || iface == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 10 {
			continue
		}
		rx, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseInt(fields[8], 10, 64)
		if err != nil {
			continue
		}
		c.BytesIn += rx
		c.BytesOut += tx
	}
	if err := scanner.Err(); err != nil {
		return Counters{}, err
	}
	return c, nil
}
