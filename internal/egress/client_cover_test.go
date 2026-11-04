package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clientCoverServe serves one connection on a fresh socket with script,
// standing in for a gateway that fails in ways the real server doesn't. The
// script's goroutine ends before the test does.
func clientCoverServe(t *testing.T, script func(c net.Conn, fr *frameReader)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "eg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		script(c, newFrameReader(c))
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return path
}

// clientCoverHello answers the client's handshake.
func clientCoverHello(c net.Conn, fr *frameReader) bool {
	var hello request
	if fr.read(&hello) != nil {
		return false
	}
	return writeFrame(c, response{ID: hello.ID, Version: ProtocolVersion}) == nil
}

func TestClientUnreachableGateway(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "none.sock"))
	ctx := context.Background()
	if err := c.Attach(ctx, allowSpec("sb", ipA)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Attach err = %v, want ErrUnavailable", err)
	}
	if _, err := c.Subscribe(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Subscribe err = %v, want ErrUnavailable", err)
	}
}

// TestClientCallDropsABrokenConnection: a call whose response is missing or
// answers another request fails as unavailable and doesn't return the
// connection to the pool, so the next call dials a fresh one instead of
// reading a stale response.
func TestClientCallDropsABrokenConnection(t *testing.T) {
	cases := []struct {
		name   string
		answer func(c net.Conn, req request)
		want   string
	}{
		{"no response", func(net.Conn, request) {}, "EOF"},
		{"another request's response", func(c net.Conn, req request) {
			_ = writeFrame(c, response{ID: req.ID + 7})
		}, "response id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := clientCoverServe(t, func(c net.Conn, fr *frameReader) {
				if !clientCoverHello(c, fr) {
					return
				}
				var req request
				if fr.read(&req) == nil {
					tc.answer(c, req)
				}
			})
			c := NewClient(path)
			t.Cleanup(c.Close)
			err := c.Detach(context.Background(), "sb", ipA)
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrUnavailable with %q", err, tc.want)
			}
			if len(c.pool) != 0 {
				t.Fatal("a broken connection went back to the pool")
			}
		})
	}
}

// TestClientCallOnAConnectionThePeerClosed: a pooled connection the gateway
// closed while idle (a gateway restart) fails the write as unavailable, and
// sandboxd retries on a fresh dial.
func TestClientCallOnAConnectionThePeerClosed(t *testing.T) {
	closed := make(chan struct{})
	path := clientCoverServe(t, func(c net.Conn, fr *frameReader) {
		defer close(closed)
		if !clientCoverHello(c, fr) {
			return
		}
		var req request
		if fr.read(&req) == nil {
			_ = writeFrame(c, response{ID: req.ID})
		}
		_ = c.Close()
	})
	c := NewClient(path)
	t.Cleanup(c.Close)
	ctx := context.Background()
	if err := c.Detach(ctx, "sb", ipA); err != nil {
		t.Fatal(err)
	}
	<-closed
	if err := c.Detach(ctx, "sb", ipA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if len(c.pool) != 0 {
		t.Fatal("a dead connection went back to the pool")
	}
}

// TestClientConnectionReuse: a payload that can't be encoded never reached
// the wire, so its connection stays pooled; a closed client still finishes
// a call but parks nothing, so Close leaves no connection behind.
func TestClientConnectionReuse(t *testing.T) {
	c, _, _, _ := startServer(t, ServerHooks{}, nil)
	ctx := context.Background()
	if err := c.call(ctx, opAttach, make(chan int), nil); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("unencodable payload err = %v, want an encoding error", err)
	}
	if len(c.pool) != 1 {
		t.Fatalf("pool holds %d, want the unused connection back", len(c.pool))
	}
	c.Close()
	if _, err := c.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.pool) != 0 {
		t.Fatal("a closed client pooled a connection")
	}
}

// TestClientPoolIsBounded: a connection that doesn't fit the pool is closed,
// not leaked.
func TestClientPoolIsBounded(t *testing.T) {
	c := NewClient("unused")
	defer c.Close()
	var peers []net.Conn
	defer func() {
		for _, p := range peers {
			_ = p.Close()
		}
	}()
	for i := 0; i <= DefaultPoolSize; i++ {
		a, b := net.Pipe()
		peers = append(peers, b)
		c.put(&clientConn{c: a, fr: newFrameReader(a)})
	}
	if len(c.pool) != DefaultPoolSize {
		t.Fatalf("pool holds %d, want %d", len(c.pool), DefaultPoolSize)
	}
	if _, err := peers[DefaultPoolSize].Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("overflow connection read = %v, want EOF (closed)", err)
	}
}

// TestSubscribeFailures: a subscribe the gateway can't take, doesn't ack or
// refuses fails as unavailable, so sandboxd's resubscribe loop backs off.
func TestSubscribeFailures(t *testing.T) {
	cases := []struct {
		name   string
		script func(c net.Conn, fr *frameReader)
		want   string
	}{
		{"subscribe write refused", func(c net.Conn, fr *frameReader) {
			var hello request
			if fr.read(&hello) != nil {
				return
			}
			// Shutting our read side before answering the hello makes the
			// client's next write fail (EPIPE on Linux) once it has the
			// answer; elsewhere the close that follows fails its read.
			if uc, ok := c.(*net.UnixConn); ok {
				_ = uc.CloseRead()
			}
			_ = writeFrame(c, response{ID: hello.ID, Version: ProtocolVersion})
		}, "subscribe"},
		{"no ack", func(c net.Conn, fr *frameReader) {
			if !clientCoverHello(c, fr) {
				return
			}
			var req request
			_ = fr.read(&req)
		}, "EOF"},
		{"refused", func(c net.Conn, fr *frameReader) {
			if !clientCoverHello(c, fr) {
				return
			}
			var req request
			if fr.read(&req) == nil {
				_ = writeFrame(c, response{ID: req.ID, Error: "no event hub"})
			}
		}, "no event hub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(clientCoverServe(t, tc.script))
			ch, err := c.Subscribe(context.Background())
			if ch != nil || !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Subscribe = %v, %v; want ErrUnavailable with %q", ch, err, tc.want)
			}
		})
	}
}

// TestSubscribeSkipsBareFramesAndStopsOnCancel: a frame without an event is
// not delivered as a zero event, and a reader stuck on a full channel (a
// consumer that stopped reading) still ends when ctx does, closing the
// channel instead of leaking the goroutine.
func TestSubscribeSkipsBareFramesAndStopsOnCancel(t *testing.T) {
	const sent = 264 // more than the channel holds
	path := clientCoverServe(t, func(c net.Conn, fr *frameReader) {
		if !clientCoverHello(c, fr) {
			return
		}
		var req request
		if fr.read(&req) != nil {
			return
		}
		// One write lands the ack, a bare frame and every event in the
		// client's read buffer together, so the stream reader never waits on
		// the socket and can only stop through ctx.
		var buf bytes.Buffer
		_ = writeFrame(&buf, response{ID: req.ID})
		_ = writeFrame(&buf, response{})
		for i := 0; i < sent; i++ {
			_ = writeFrame(&buf, response{Event: &Event{Kind: "audit"}})
		}
		if _, err := c.Write(buf.Bytes()); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := NewClient(path).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(ch) < cap(ch) {
		if time.Now().After(deadline) {
			t.Fatalf("channel holds %d of %d events", len(ch), cap(ch))
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	n := 0
	for e := range ch {
		if e.Kind != "audit" {
			t.Fatalf("delivered %+v, want only the audit events", e)
		}
		n++
	}
	if n < cap(ch) || n > sent {
		t.Fatalf("delivered %d events, want %d to %d", n, cap(ch), sent)
	}
}
