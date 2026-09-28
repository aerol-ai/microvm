package wasm

import (
	"net"
	"testing"
)

func TestCloseConnsNilAndActive(t *testing.T) {
	(*wazeroNetHost)(nil).closeConns()

	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	h := &wazeroNetHost{conns: map[uint64]net.Conn{1: a}}
	h.closeConns()
	if len(h.conns) != 0 {
		t.Fatalf("conns remain: %d", len(h.conns))
	}
}
