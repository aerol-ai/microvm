package netsplice

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// loopbackPair returns the two ends of a real TCP connection, so the splice
// path sees *net.TCPConn exactly as in production.
func loopbackPair(t testing.TB) (client, server net.Conn) {
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

// startSplice runs Splice in the background and returns its result channel.
func startSplice(downstream, upstream net.Conn, br *bufio.Reader, opts ...Option) <-chan error {
	spliced := make(chan error, 1)
	go func() { spliced <- Splice(downstream, upstream, br, opts...) }()
	return spliced
}

// waitSplice fails the test unless Splice returns want within 5s.
func waitSplice(t *testing.T, spliced <-chan error, want error) {
	t.Helper()
	select {
	case err := <-spliced:
		if !errors.Is(err, want) {
			t.Fatalf("Splice = %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Splice did not return")
	}
}

// readAllWithin reads c to EOF under a 5s deadline.
func readAllWithin(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read to EOF: %v (got %d bytes)", err, len(got))
	}
	return got
}

// The buffered prefix (bytes read past a header) must reach the upstream
// before anything still on the socket, byte-exact, and both directions flow
// while the connection is open.
func TestSpliceWritesBufferedPrefixFirst(t *testing.T) {
	clientSide, downstream := loopbackPair(t) // downstream = proxy's accepted conn
	upstream, backend := loopbackPair(t)      // upstream = proxy's dialed conn

	// The proxy has read "HEADER\n" + "HELLO-" from the client; "WORLD" is
	// still on the socket.
	if _, err := clientSide.Write([]byte("HEADER\nHELLO-")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReaderSize(downstream, 256)
	if line, err := br.ReadSlice('\n'); err != nil || string(line) != "HEADER\n" {
		t.Fatalf("header = %q, %v", line, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for br.Buffered() < len("HELLO-") && time.Now().Before(deadline) {
		_, _ = br.Peek(1)
	}

	spliced := startSplice(downstream, upstream, br)

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
	// The client finishing is forwarded as a FIN, with nothing after it,
	// and the splice ends once the backend finishes too.
	_ = clientSide.(*net.TCPConn).CloseWrite()
	if rest := readAllWithin(t, backend); len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes at backend: %q", rest)
	}
	_ = backend.Close()
	waitSplice(t, spliced, nil)
	if rest := readAllWithin(t, clientSide); len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes at client: %q", rest)
	}
}

func TestSplicePrefixWriteFailure(t *testing.T) {
	_, downstream := loopbackPair(t)
	upstream, _ := loopbackPair(t)
	_ = upstream.Close()
	br := bufio.NewReader(bytes.NewReader([]byte("buffered")))
	_, _ = br.Peek(1)
	if err := Splice(downstream, upstream, br); err == nil || !strings.Contains(err.Error(), "write buffered prefix") {
		t.Fatalf("err = %v, want a buffered-prefix write error", err)
	}
}

// One side sends and half-closes; the other reads to EOF (which only arrives
// if Splice forwarded the FIN), then answers with more than the socket
// buffers hold and closes. The answer must arrive whole. Before the fix the
// first EOF closed both conns and the answer was lost.
func TestSpliceHalfCloseDeliversTheRest(t *testing.T) {
	answer := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	tests := []struct {
		name          string
		clientIsFirst bool
	}{
		{name: "client half-close still receives the full response", clientIsFirst: true},
		{name: "server half-close still receives the full request", clientIsFirst: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientSide, downstream := loopbackPair(t)
			upstream, backend := loopbackPair(t)
			spliced := startSplice(downstream, upstream, nil)

			first, second := clientSide, backend
			if !tc.clientIsFirst {
				first, second = backend, clientSide
			}
			go func() {
				_, _ = first.Write([]byte("hello"))
				_ = first.(*net.TCPConn).CloseWrite()
			}()
			if got := readAllWithin(t, second); string(got) != "hello" {
				t.Fatalf("second side got %q, want hello then EOF", got)
			}
			go func() {
				_, _ = second.Write(answer)
				_ = second.Close()
			}()
			if got := readAllWithin(t, first); !bytes.Equal(got, answer) {
				t.Fatalf("first side got %d bytes after its half-close, want all %d", len(got), len(answer))
			}
			waitSplice(t, spliced, nil)
		})
	}
}

func TestSpliceIdleTimeout(t *testing.T) {
	tests := []struct {
		name string
		idle time.Duration
		// drive sets up the peers' behaviour and returns the conns to splice
		// plus a check run after Splice returns.
		drive func(t *testing.T) (downstream, upstream net.Conn, after func())
		want  error
	}{
		{
			name: "both sides silent",
			idle: 50 * time.Millisecond,
			drive: func(t *testing.T) (net.Conn, net.Conn, func()) {
				_, downstream := loopbackPair(t)
				upstream, _ := loopbackPair(t)
				return downstream, upstream, func() {}
			},
			want: ErrIdleTimeout,
		},
		{
			name: "half-closed then silent",
			idle: 50 * time.Millisecond,
			drive: func(t *testing.T) (net.Conn, net.Conn, func()) {
				clientSide, downstream := loopbackPair(t)
				upstream, backend := loopbackPair(t)
				_ = clientSide.(*net.TCPConn).CloseWrite()
				// The backend sees the FIN but never answers or closes.
				go func() { _, _ = io.Copy(io.Discard, backend) }()
				return downstream, upstream, func() {}
			},
			want: ErrIdleTimeout,
		},
		{
			name: "peer that never reads",
			idle: 50 * time.Millisecond,
			drive: func(t *testing.T) (net.Conn, net.Conn, func()) {
				// net.Pipe is unbuffered, so the upstream→downstream copy
				// blocks writing to a client that never reads.
				_, downstream := net.Pipe()
				upstream, backend := net.Pipe()
				go func() {
					for {
						if _, err := backend.Write([]byte("data")); err != nil {
							return
						}
					}
				}()
				return downstream, upstream, func() {}
			},
			want: ErrIdleTimeout,
		},
		{
			name: "one-way stream is not idle",
			idle: 200 * time.Millisecond,
			drive: func(t *testing.T) (net.Conn, net.Conn, func()) {
				clientSide, downstream := loopbackPair(t)
				upstream, backend := loopbackPair(t)
				const chunks = 50 // 50 × 20ms = 1s, five idle periods
				received := make(chan int, 1)
				go func() {
					// The client never writes, so downstream→upstream stays
					// quiet for the whole stream. Once the backend's FIN
					// arrives, the client half-closes too and the splice
					// ends on its own.
					_ = clientSide.SetReadDeadline(time.Now().Add(10 * time.Second))
					got, _ := io.ReadAll(clientSide)
					_ = clientSide.(*net.TCPConn).CloseWrite()
					received <- len(got)
				}()
				go func() {
					for i := 0; i < chunks; i++ {
						if _, err := backend.Write([]byte("x")); err != nil {
							return
						}
						time.Sleep(20 * time.Millisecond)
					}
					_ = backend.Close()
				}()
				return downstream, upstream, func() {
					if got := <-received; got != chunks {
						t.Fatalf("client received %d bytes, want %d", got, chunks)
					}
				}
			},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			downstream, upstream, after := tc.drive(t)
			start := time.Now()
			spliced := startSplice(downstream, upstream, nil, WithIdleTimeout(tc.idle))
			waitSplice(t, spliced, tc.want)
			if elapsed := time.Since(start); tc.want != nil && elapsed < tc.idle {
				t.Fatalf("idle close after %v, before one idle period %v", elapsed, tc.idle)
			}
			after()
		})
	}
}

// Without WithIdleTimeout a silent connection stays up: the wake proxy
// carries database connections that sit idle for hours. It still ends once
// both directions finish.
func TestSpliceWithoutIdleTimeoutWaits(t *testing.T) {
	clientSide, downstream := loopbackPair(t)
	upstream, backend := loopbackPair(t)
	spliced := startSplice(downstream, upstream, nil)
	select {
	case err := <-spliced:
		t.Fatalf("Splice returned %v on a silent connection with no idle timeout", err)
	case <-time.After(150 * time.Millisecond):
	}
	_ = clientSide.Close()
	if rest := readAllWithin(t, backend); len(rest) != 0 {
		t.Fatalf("unexpected bytes at backend: %q", rest)
	}
	_ = backend.Close()
	waitSplice(t, spliced, nil)
}

// A copy error (here a TCP reset from the backend) ends the splice at once,
// closes the other side, and is not reported as a splice failure.
func TestSpliceCopyErrorClosesBoth(t *testing.T) {
	clientSide, downstream := loopbackPair(t)
	upstream, backend := loopbackPair(t)
	spliced := startSplice(downstream, upstream, nil)
	_ = backend.(*net.TCPConn).SetLinger(0) // Close sends RST, not FIN
	_ = backend.Close()
	waitSplice(t, spliced, nil)
	if rest := readAllWithin(t, clientSide); len(rest) != 0 {
		t.Fatalf("unexpected bytes at client: %q", rest)
	}
}

// A conn without CloseWrite (net.Pipe) cannot forward a FIN, so the
// finishing direction closes it outright, which also ends the other
// direction. The bytes sent before the close still arrive.
func TestSpliceClosesConnWithoutCloseWrite(t *testing.T) {
	clientSide, downstream := net.Pipe()
	upstream, backend := net.Pipe()
	spliced := startSplice(downstream, upstream, nil)
	go func() {
		_, _ = clientSide.Write([]byte("hello"))
		_ = clientSide.Close()
	}()
	_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(backend)
	if err != nil || string(got) != "hello" {
		t.Fatalf("backend got %q, %v; want hello then EOF", got, err)
	}
	waitSplice(t, spliced, nil)
}

// Splice owns the conns' deadlines. Expired ones a caller left behind (a
// ClientHello peek timeout, say) must not fail the prefix write or the copy.
func TestSpliceClearsCallerDeadlines(t *testing.T) {
	clientSide, downstream := loopbackPair(t)
	upstream, backend := loopbackPair(t)
	past := time.Now().Add(-time.Second)
	_ = downstream.SetDeadline(past)
	_ = upstream.SetDeadline(past)
	br := bufio.NewReader(strings.NewReader("prefix-"))
	_, _ = br.Peek(1)
	spliced := startSplice(downstream, upstream, br)
	go func() {
		_, _ = clientSide.Write([]byte("stream"))
		_ = clientSide.(*net.TCPConn).CloseWrite()
	}()
	if got := readAllWithin(t, backend); string(got) != "prefix-stream" {
		t.Fatalf("backend got %q, want prefix-stream", got)
	}
	_ = backend.Close()
	waitSplice(t, spliced, nil)
}

// BenchmarkSplice measures bulk client->upstream throughput through Splice
// over real loopback TCP (the direction review 7A moved onto raw-conn
// io.Copy). Run with -benchmem: per-op allocations must not grow with
// payload size.
func BenchmarkSplice(b *testing.B) {
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
		done := make(chan struct{})
		go func() { _ = Splice(downstream, upstream, nil); close(done) }()
		go func() {
			_, _ = client.Write(payload)
			_ = client.(*net.TCPConn).CloseWrite()
		}()
		_, _ = io.Copy(io.Discard, backend)
		_ = backend.Close()
		<-done
		_ = client.Close()
		_ = ln1.Close()
		_ = ln2.Close()
	}
}
