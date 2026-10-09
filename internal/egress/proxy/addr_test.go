package proxy

import (
	"net"
	"testing"
)

func TestOneConnListenerAddr(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	if got := (&oneConnListener{conn: a}).Addr(); got != a.LocalAddr() {
		t.Fatalf("Addr = %v", got)
	}
}
