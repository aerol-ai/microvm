package toolboxhttp

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestEveryCallGetsItsOwnConnection: no connection is pooled between calls,
// so none can carry a call to the next sandbox that takes the address.
func TestEveryCallGetsItsOwnConnection(t *testing.T) {
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") != "close" {
			t.Errorf("a plain call did not ask to close its connection: %q", r.Header.Get("Connection"))
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	c := Client(5 * time.Second)
	for i := 0; i < 5; i++ {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if n := conns.Load(); n != 5 {
		t.Fatalf("5 calls used %d connections", n)
	}
}

// TestUpgradeStillWorks: a WebSocket-style upgrade is not marked
// "Connection: close" and gets its 101.
func TestUpgradeStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
			http.Error(w, "connection header "+r.Header.Get("Connection"), http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")
		_ = rw.Flush()
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", resp.StatusCode)
	}
	line, _ := bufio.NewReader(resp.Body.(io.Reader)).ReadString('o')
	if line != "hello" {
		t.Fatalf("upgraded stream = %q", line)
	}
}
