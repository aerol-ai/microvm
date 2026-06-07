package worker

import (
	"net"
	"testing"
)

func TestServerNetstatsTickDrainsCounters(t *testing.T) {
	srv := &Server{}
	srv.netUsageFor("sb-1").bytesIn.Add(10)
	srv.netUsageFor("sb-1").bytesOut.Add(20)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(serverConn)
	}()

	c := NewClient("")
	c.dial = func(string) (net.Conn, error) { return clientConn, nil }

	in, out, err := c.NetstatsTick("sb-1")
	if err != nil {
		t.Fatalf("NetstatsTick: %v", err)
	}
	if in != 10 || out != 20 {
		t.Fatalf("tick = in %d out %d, want 10/20", in, out)
	}
	_ = clientConn.Close()
	<-done
}
