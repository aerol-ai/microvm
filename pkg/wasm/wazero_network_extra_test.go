package wasm

import (
	"context"
	"net"
	"testing"
)

func TestTcpRead_OutOfBounds(t *testing.T) {
	h := &wazeroNetHost{conns: make(map[uint64]net.Conn)}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	h.conns[1] = c1
	mod := &mockModule{
		mem: &mockMemory{},
	}
	// bufPtr = 1000, bufLen = 1000, out of bounds
	stack := []uint64{1, 1000, 1000}
	h.tcpRead(context.Background(), mod, stack)
	if stack[0] != uint64(int32(1)) { // errInvalid
		t.Fatalf("expected error return")
	}
}

func TestTcpWrite_OutOfBounds(t *testing.T) {
	h := &wazeroNetHost{conns: make(map[uint64]net.Conn)}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	h.conns[1] = c1
	mod := &mockModule{
		mem: &mockMemory{},
	}
	// bufPtr = 1000, bufLen = 1000, out of bounds
	stack := []uint64{1, 1000, 1000}
	h.tcpWrite(context.Background(), mod, stack)
	if stack[0] != uint64(int32(1)) { // errInvalid
		t.Fatalf("expected error return")
	}
}
