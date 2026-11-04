// Package netsplice is the raw-TCP proxy core shared by sandboxd's proxies: a
// bidirectional splice that replays bytes already read into a bufio.Reader,
// and a per-key plus global connection limiter. The L4 wake proxy
// (internal/service) uses both. The egress FQDN proxy
// (plans/egress-domain-filtering.md §5.5, D12 and D17) has the same contract,
// so half-close, idle and cap semantics exist once, with one set of tests.
package netsplice

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// ErrIdleTimeout is returned by Splice when WithIdleTimeout ended the
// connection.
var ErrIdleTimeout = errors.New("netsplice: idle timeout")

// Option configures Splice.
type Option func(*options)

type options struct {
	idleTimeout time.Duration
}

// WithIdleTimeout ends the splice once no byte has moved in either direction
// for d, so a silent peer cannot pin two goroutines, two sockets and a limiter
// slot forever. Zero or negative (the default) waits indefinitely: the L4 wake
// proxy carries database connections that legitimately sit idle for hours.
//
// Detection is coarse on purpose (see splice.wait): a quiet connection closes
// between d and 2d after its last byte. A direction blocked for a whole
// period writing to a peer that does not read counts as idle too, since that
// peer pins the connection just the same.
func WithIdleTimeout(d time.Duration) Option {
	return func(o *options) { o.idleTimeout = d }
}

// Splice copies downstream<->upstream until BOTH directions finish, then
// closes both conns. Bytes already buffered in br (read past a PROXY header,
// or a peeked ClientHello) are written upstream FIRST. br may be nil.
//
// Half-close sequence (client finishes first; the mirror case is symmetric):
//
//	client            downstream ── Splice ── upstream            backend
//	  │ request ───────────►│  down→up copy  │─────────────────────►│
//	  │ CloseWrite (FIN) ──►│  EOF           │ CloseWrite(up) ─────►│ reads EOF
//	  │                     │                │                      │
//	  │◄────────────────────│  up→down copy  │◄──────────── response│
//	  │◄─ FIN ──────────────│ CloseWrite(down)  EOF ◄─── Close (FIN)│
//	                        └ both done: Close both conns, return nil
//
// Each direction forwards its EOF as a FIN (CloseWrite) and the other
// direction keeps flowing. A conn without CloseWrite (net.Pipe) is closed
// instead, which also ends the other direction. The old shape returned on the
// first finished direction and closed both conns, so a client that
// half-closed after its request never received the response.
//
// The copy runs raw conn to raw conn. Wrapping downstream in io.MultiReader
// (the shape before eng review 7A) hid the *net.TCPConn from io.Copy, so its
// bytes could not use Linux splice(2) and went through user space. That is
// why the prefix is written separately, and why idle detection samples with
// read deadlines instead of counting bytes through a wrapper.
//
// A copy error (a reset, a broken pipe) closes both conns and is not
// returned: for a proxy that is how connections normally end. Splice returns
// a prefix write error (nothing was copied and both conns are left to the
// caller), ErrIdleTimeout, or nil. It owns both conns' deadlines
// and clears any the caller left behind (a ClientHello peek timeout, say),
// which would otherwise end a healthy copy. No goroutine outlives the call.
func Splice(downstream, upstream net.Conn, br *bufio.Reader, opts ...Option) error {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	_ = downstream.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	if br != nil {
		if n := br.Buffered(); n > 0 {
			// Peek(Buffered()) is served from the buffer and cannot fail.
			prefix, _ := br.Peek(n)
			if _, err := upstream.Write(prefix); err != nil {
				return fmt.Errorf("write buffered prefix: %w", err)
			}
			_, _ = br.Discard(n)
		}
	}

	s := &splice{
		conns:   [2]net.Conn{downstream, upstream},
		idle:    o.idleTimeout,
		reports: make(chan report, 4),
	}
	go copyDirection(toUpstream, upstream, downstream, s.reports)
	go copyDirection(toDownstream, downstream, upstream, s.reports)
	return s.wait()
}

// Direction indexes: the src of direction i is conns[i].
const (
	toUpstream   = 0 // downstream → upstream
	toDownstream = 1 // upstream → downstream
)

// report is one direction's account of a finished io.Copy run.
type report struct {
	dir   int
	n     int64 // bytes moved since that direction's previous report
	final bool  // the direction stopped copying
	err   error // why it stopped; nil on a clean EOF
}

// copyDirection copies src to dst until EOF or an error, reporting each
// io.Copy run to the supervisor.
func copyDirection(dir int, dst, src net.Conn, reports chan<- report) {
	for {
		n, err := io.Copy(dst, src)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// An idle-sampler poke (Splice cleared every other deadline).
			// Only read deadlines are ever set, and a read that times out has
			// consumed nothing: splice(2) waits for readability before it
			// drains into its pipe, and io.Copy's buffer loop writes what it
			// read before it looks at the error. So resuming loses no byte.
			// Clear the deadline BEFORE reporting: the supervisor pokes again
			// only after this report, so the clear can never undo a poke.
			_ = src.SetReadDeadline(time.Time{})
			reports <- report{dir: dir, n: n}
			continue
		}
		if err == nil {
			// Clean EOF: forward it as a FIN so the peer sees end-of-stream
			// while the other direction keeps flowing.
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			} else {
				_ = dst.Close()
			}
		}
		reports <- report{dir: dir, n: n, final: true, err: err}
		return
	}
}

// aLongTimeAgo is a read deadline that fires immediately (the net/http trick).
var aLongTimeAgo = time.Unix(1, 0)

// splice is the supervisor state for one Splice call. Only wait's goroutine
// touches it, so it needs no lock.
type splice struct {
	conns   [2]net.Conn
	idle    time.Duration
	reports chan report

	live     int     // directions still copying
	finished [2]bool // direction sent its final report
	stopped  bool    // both conns closed; only draining final reports now
	result   error

	// Idle sampling state; see wait.
	sampling bool    // a poke is outstanding
	answered [2]bool // direction reported since the outstanding poke
	active   bool    // a byte or EOF was reported since the last verdict
}

// wait runs until both directions have sent their final report.
//
// Idle sampling: io.Copy between raw conns gives no progress callback, so
// activity is only visible when a copy run returns. Every idle period the
// supervisor pokes each live direction (a read deadline in the past), which
// makes its io.Copy return the bytes moved since its previous report, and
// the direction then resumes. When every live direction has answered, the
// verdict is: nothing moved since the previous verdict, so idle, or the next
// poke is one period away. Each direction resumes reading before the verdict,
// so every sampled window is at least one period long. A direction that does
// not answer within a period is blocked writing to a peer that is not
// reading, and counts as idle.
func (s *splice) wait() error {
	s.live = 2
	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	if s.idle > 0 {
		timer = time.NewTimer(s.idle)
		defer timer.Stop()
		timerC = timer.C
	}
	for s.live > 0 {
		select {
		case r := <-s.reports:
			s.answered[r.dir] = true
			if r.n > 0 || r.final {
				s.active = true
			}
			if r.final {
				s.finished[r.dir] = true
				s.live--
				if r.err != nil {
					s.stop(nil)
				}
			}
			if s.sampling && !s.stopped && s.allAnswered() {
				s.sampling = false
				if !s.active {
					s.stop(ErrIdleTimeout)
					continue
				}
				s.active = false
				timer.Reset(s.idle)
			}
		case <-timerC:
			if s.stopped {
				continue
			}
			if s.sampling {
				s.stop(ErrIdleTimeout)
				continue
			}
			s.sampling = true
			for dir := range s.conns {
				s.answered[dir] = false
				if !s.finished[dir] {
					_ = s.conns[dir].SetReadDeadline(aLongTimeAgo)
				}
			}
			timer.Reset(s.idle)
		}
	}
	s.stop(s.result)
	return s.result
}

// allAnswered reports whether every live direction answered the outstanding
// poke. A finished direction has nothing left to report.
func (s *splice) allAnswered() bool {
	for dir := range s.conns {
		if !s.finished[dir] && !s.answered[dir] {
			return false
		}
	}
	return true
}

// stop closes both conns once, which unblocks any copy still running so its
// final report arrives promptly. The first caller's err is the result.
func (s *splice) stop(err error) {
	if s.stopped {
		return
	}
	s.stopped = true
	s.result = err
	_ = s.conns[0].Close()
	_ = s.conns[1].Close()
}
