package service

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

// Shared raw-TCP proxy primitives. The L4 wake proxy uses them today. The
// sandboxd-owned host-port listeners in plans/ingress-proxy-routing.md §3.5
// will use them next, so connection caps, half-close and PROXY parsing exist
// once, not once per proxy (eng review 3A).

// proxyHeader is a parsed PROXY protocol v1 line.
type proxyHeader struct {
	Family  string // TCP4 | TCP6
	SrcAddr string
	DstAddr string
	SrcPort int
	DstPort int
}

// readProxyV1Header reads one PROXY v1 line from br. br must be sized to the
// maximum header length, so a peer cannot make it buffer without bound. Bytes
// after the line stay in br and belong to the proxied stream.
func readProxyV1Header(br *bufio.Reader) (proxyHeader, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return proxyHeader{}, errors.New("proxy protocol header too large")
	}
	if err != nil {
		return proxyHeader{}, fmt.Errorf("read proxy protocol header: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(line)))
	if len(fields) != 6 || fields[0] != "PROXY" {
		return proxyHeader{}, fmt.Errorf("malformed proxy protocol header %q", strings.TrimSpace(string(line)))
	}
	if fields[1] != "TCP4" && fields[1] != "TCP6" {
		return proxyHeader{}, fmt.Errorf("unsupported proxy protocol family %q", fields[1])
	}
	// Only the destination port is load-bearing (the wake proxy keys
	// exposures by it) and strictly validated, as before the extraction.
	// The source is informational: an unparsable source port reads as 0
	// rather than refusing a header the old parser accepted.
	srcPort, err := strconv.Atoi(fields[4])
	if err != nil || srcPort < 0 || srcPort > 65535 {
		srcPort = 0
	}
	dstPort, err := strconv.Atoi(fields[5])
	if err != nil || dstPort <= 0 || dstPort > 65535 {
		return proxyHeader{}, fmt.Errorf("invalid proxy protocol destination port %q", fields[5])
	}
	return proxyHeader{Family: fields[1], SrcAddr: fields[2], DstAddr: fields[3], SrcPort: srcPort, DstPort: dstPort}, nil
}

// readProxyV1DestinationPort is the wake proxy's view of the header: it keys
// exposures by host port.
func readProxyV1DestinationPort(br *bufio.Reader) (int, error) {
	h, err := readProxyV1Header(br)
	if err != nil {
		return 0, err
	}
	return h.DstPort, nil
}

// connLimiter caps concurrent connections per key (a sandbox ID) and
// globally. The hooks run under the limiter's lock, so state tied to a key's
// first acquire or last release (the wake proxy's activity generation)
// changes atomically with the count. The wake proxy relied on that when all
// of this lived under Service.l4LimitMu.
type connLimiter struct {
	perKeyMax func() int
	globalMax func() int

	mu     sync.Mutex
	byKey  map[string]int
	global int
}

func newConnLimiter(perKeyMax, globalMax func() int) *connLimiter {
	return &connLimiter{perKeyMax: perKeyMax, globalMax: globalMax, byKey: make(map[string]int)}
}

// tryAcquire reserves one slot for key. onAcquire(first) and the returned
// release's onRelease(last) run under the lock; either may be nil. The
// release func is idempotent, so a double release cannot drive counts
// negative or free another connection's slot.
func (l *connLimiter) tryAcquire(key string, onAcquire func(first bool), onRelease func(last bool)) (func(), bool) {
	perKeyMax, globalMax := l.perKeyMax(), l.globalMax()
	l.mu.Lock()
	if l.byKey[key] >= perKeyMax || l.global >= globalMax {
		l.mu.Unlock()
		return nil, false
	}
	first := l.byKey[key] == 0
	l.byKey[key]++
	l.global++
	if onAcquire != nil {
		onAcquire(first)
	}
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			last := l.byKey[key] <= 1
			if last {
				delete(l.byKey, key)
			} else {
				l.byKey[key]--
			}
			if l.global > 0 {
				l.global--
			}
			if onRelease != nil {
				onRelease(last)
			}
		})
	}, true
}

// withLock runs fn with the limiter's lock held, passing the live count for
// key. Use it for state guarded by the hooks.
func (l *connLimiter) withLock(key string, fn func(count int)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn(l.byKey[key])
}

// spliceConns copies downstream<->upstream until either side finishes, then
// closes both. Bytes already buffered in br (read past a PROXY header, or a
// peeked ClientHello) are written upstream FIRST. The copy then runs
// raw-conn to raw-conn: wrapping downstream in io.MultiReader (the old
// shape) hid the *net.TCPConn from io.Copy, so client->upstream bytes could
// not use Linux splice(2) and went through user space (eng review 7A).
func spliceConns(downstream, upstream net.Conn, br *bufio.Reader) error {
	if br != nil {
		if n := br.Buffered(); n > 0 {
			prefix, err := br.Peek(n)
			if err != nil {
				return fmt.Errorf("read buffered prefix: %w", err)
			}
			if _, err := upstream.Write(prefix); err != nil {
				return fmt.Errorf("write buffered prefix: %w", err)
			}
			_, _ = br.Discard(n)
		}
	}
	done := make(chan struct{}, 2)
	go proxyCopyAndCloseWrite(upstream, downstream, done)
	go proxyCopyAndCloseWrite(downstream, upstream, done)
	<-done
	_ = downstream.Close()
	_ = upstream.Close()
	return nil
}

// proxyCopyAndCloseWrite copies src to dst, then half-closes dst so the peer
// sees EOF while the other direction keeps flowing.
func proxyCopyAndCloseWrite(dst net.Conn, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
	done <- struct{}{}
}
