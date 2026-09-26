package wasm

import (
	"context"
	"net"
	"testing"
)

func TestCoverage95MultiNetworkCleanupAndInvalidMemory(t *testing.T) {
	h := newMultiNetHost()
	h.setHook("", &NetworkHook{})
	h.setHook("sandbox", &NetworkHook{Meter: &mockMeter{}})
	if h.resolveHook("sandbox") == nil {
		t.Fatal("hook was not stored")
	}

	left, right := net.Pipe()
	defer right.Close()
	h.putConn("sandbox", 7, left)
	h.closeConns("sandbox")
	if _, err := right.Write([]byte("x")); err == nil {
		t.Fatal("peer remained writable after closeConns")
	}
	if conn, _ := h.takeConn("sandbox", 7); conn != nil {
		t.Fatal("connection remained after closeConns")
	}

	h.closeConns("")
	h.clearSandbox("")
	h.clearSandbox("sandbox")
	if h.resolveHook("sandbox") != nil {
		t.Fatal("hook remained after clearSandbox")
	}
	h.closeAll()
	if h.resolveHook("sandbox") != nil {
		t.Fatal("closed host resolved a hook")
	}

	mod := &mockModule{name: "sandbox", mem: &mockMemory{buf: []byte("x")}}
	stack := []uint64{9, 1}
	h.tcpDial(context.Background(), mod, stack)
	if stack[0] != 3 {
		t.Fatalf("closed host tcpDial = %d, want blocked", stack[0])
	}

	active := newMultiNetHost()
	active.setHook("sandbox", &NetworkHook{Dial: &countingDialer{}})
	readStack := []uint64{1, 99, 1}
	active.tcpRead(context.Background(), mod, readStack)
	if readStack[0] != 2 {
		t.Fatalf("tcpRead unknown connection = %d, want closed", readStack[0])
	}
}
