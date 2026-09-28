package service

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadProxyV1Header(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    proxyHeader
		wantErr string
	}{
		{name: "tcp4", line: "PROXY TCP4 1.2.3.4 5.6.7.8 40000 443\r\n",
			want: proxyHeader{Family: "TCP4", SrcAddr: "1.2.3.4", DstAddr: "5.6.7.8", SrcPort: 40000, DstPort: 443}},
		{name: "tcp6", line: "PROXY TCP6 ::1 ::2 1 30001\r\n",
			want: proxyHeader{Family: "TCP6", SrcAddr: "::1", DstAddr: "::2", SrcPort: 1, DstPort: 30001}},
		{name: "junk source port is informational", line: "PROXY TCP4 a b x 443\n",
			want: proxyHeader{Family: "TCP4", SrcAddr: "a", DstAddr: "b", SrcPort: 0, DstPort: 443}},
		{name: "bad dest port", line: "PROXY TCP4 a b 1 0\n", wantErr: "destination port"},
		{name: "unknown family", line: "PROXY UNKNOWN a b 1 2\n", wantErr: "family"},
		{name: "not proxy", line: "GET / HTTP/1.1\r\n", wantErr: "malformed"},
		{name: "too large", line: strings.Repeat("P", 300) + "\n", wantErr: "too large"},
		{name: "no newline", line: "PROXY TCP4 a b 1 2", wantErr: "read proxy protocol header"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReaderSize(strings.NewReader(tc.line), l4WakeProxyHeaderMaxBytes)
			got, err := readProxyV1Header(br)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%+v, %v), want %+v", got, err, tc.want)
			}
		})
	}
}

func TestConnLimiterCapsHooksAndIdempotentRelease(t *testing.T) {
	l := newConnLimiter(func() int { return 2 }, func() int { return 3 })
	var events []string
	acq := func(key string) func() {
		t.Helper()
		release, ok := l.tryAcquire(key,
			func(first bool) {
				events = append(events, key+":acquire:"+map[bool]string{true: "first", false: "more"}[first])
			},
			func(last bool) {
				events = append(events, key+":release:"+map[bool]string{true: "last", false: "more"}[last])
			})
		if !ok {
			t.Fatalf("acquire %s refused", key)
		}
		return release
	}
	a1, a2 := acq("a"), acq("a")
	if _, ok := l.tryAcquire("a", nil, nil); ok {
		t.Fatal("per-key cap 2 not enforced")
	}
	b1 := acq("b")
	if _, ok := l.tryAcquire("c", nil, nil); ok {
		t.Fatal("global cap 3 not enforced")
	}
	a1()
	a1() // idempotent: must not release a2's slot
	l.withLock("a", func(n int) {
		if n != 1 {
			t.Fatalf("count(a) = %d after double release of one slot, want 1", n)
		}
	})
	a2()
	b1()
	l.withLock("a", func(n int) {
		if n != 0 || l.global != 0 || len(l.byKey) != 0 {
			t.Fatalf("leaked state: count=%d global=%d keys=%v", n, l.global, l.byKey)
		}
	})
	want := []string{"a:acquire:first", "a:acquire:more", "b:acquire:first", "a:release:more", "a:release:last", "b:release:last"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("hook order = %v, want %v", events, want)
	}
}

func TestConnLimiterConcurrentAcquireRelease(t *testing.T) {
	l := newConnLimiter(func() int { return 1 << 20 }, func() int { return 1 << 20 })
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := []string{"x", "y"}[i%2]
			for j := 0; j < 200; j++ {
				release, ok := l.tryAcquire(key, nil, nil)
				if !ok {
					t.Error("unexpected refusal")
					return
				}
				release()
				release()
			}
		}(i)
	}
	wg.Wait()
	if l.global != 0 || len(l.byKey) != 0 {
		t.Fatalf("leaked after concurrent churn: global=%d keys=%v", l.global, l.byKey)
	}
}

// loopbackPair returns the two ends of a real TCP connection, so the splice
// path sees *net.TCPConn exactly as in production.
func loopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// The buffered prefix (bytes read past the PROXY header) must reach the
// upstream before anything still on the socket, byte-exact, and both
// directions flow while the connection is open. Contract note (unchanged by
// the 3A extraction): the splice ends when EITHER direction finishes and
// then closes both, so a response sent after the client half-closes is not
// delivered. See TODOS "L4 splice drops the response after a client
// half-close".
func TestSpliceConnsWritesBufferedPrefixFirst(t *testing.T) {
	clientSide, downstream := loopbackPair(t) // downstream = proxy's accepted conn
	upstream, backend := loopbackPair(t)      // upstream = proxy's dialed conn

	// The proxy has read "PROXY ...\n" + "HELLO-" from the client; "WORLD"
	// is still on the socket.
	if _, err := clientSide.Write([]byte("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\nHELLO-")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReaderSize(downstream, l4WakeProxyHeaderMaxBytes)
	if _, err := readProxyV1Header(br); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for br.Buffered() < len("HELLO-") && time.Now().Before(deadline) {
		_, _ = br.Peek(1)
	}

	spliced := make(chan error, 1)
	go func() { spliced <- spliceConns(downstream, upstream, br) }()

	if _, err := clientSide.Write([]byte("WORLD")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("HELLO-WORLD"))
	_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(backend, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "HELLO-WORLD" {
		t.Fatalf("backend got %q, want prefix then stream %q", got, "HELLO-WORLD")
	}
	// Reverse direction while both sides are open.
	if _, err := backend.Write([]byte("PONG")); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, 4)
	_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientSide, back); err != nil || string(back) != "PONG" {
		t.Fatalf("client got %q (%v), want PONG", back, err)
	}
	// Client finishing ends the splice and closes the upstream side.
	_ = clientSide.(*net.TCPConn).CloseWrite()
	select {
	case err := <-spliced:
		if err != nil {
			t.Fatalf("spliceConns: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("spliceConns did not return after the client finished")
	}
	_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
	if rest, _ := io.ReadAll(backend); len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes at backend: %q", rest)
	}
}

func TestSpliceConnsPrefixWriteFailure(t *testing.T) {
	_, downstream := loopbackPair(t)
	upstream, _ := loopbackPair(t)
	_ = upstream.Close()
	br := bufio.NewReader(bytes.NewReader([]byte("buffered")))
	_, _ = br.Peek(1)
	if err := spliceConns(downstream, upstream, br); err == nil || !strings.Contains(err.Error(), "write buffered prefix") {
		t.Fatalf("err = %v, want a buffered-prefix write error", err)
	}
}

// BenchmarkSpliceConns measures bulk client->upstream throughput through
// spliceConns over real loopback TCP (the direction review 7A moved onto
// raw-conn io.Copy). Run with -benchmem: per-op allocations must not grow
// with payload size.
func BenchmarkSpliceConns(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1<<20)
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		ln1, _ := net.Listen("tcp", "127.0.0.1:0")
		ln2, _ := net.Listen("tcp", "127.0.0.1:0")
		acc := func(ln net.Listener) chan net.Conn {
			ch := make(chan net.Conn, 1)
			go func() { c, _ := ln.Accept(); ch <- c }()
			return ch
		}
		a1, a2 := acc(ln1), acc(ln2)
		client, _ := net.Dial("tcp", ln1.Addr().String())
		upstream, _ := net.Dial("tcp", ln2.Addr().String())
		downstream, backend := <-a1, <-a2
		go func() { _ = spliceConns(downstream, upstream, nil) }()
		go func() {
			_, _ = client.Write(payload)
			_ = client.(*net.TCPConn).CloseWrite()
		}()
		_, _ = io.Copy(io.Discard, backend)
		_ = client.Close()
		_ = backend.Close()
		_ = ln1.Close()
		_ = ln2.Close()
	}
}
