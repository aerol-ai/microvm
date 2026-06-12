package wasm

import (
	"net"
	"testing"
)

type mockFile struct {
	addr *net.TCPAddr
}

func (m *mockFile) Addr() net.Addr {
	if m.addr == nil {
		return &net.UnixAddr{}
	}
	return m.addr
}

type nestedMockFile struct {
	F *mockFile
}

func TestTcpListenPort(t *testing.T) {
	if _, ok := tcpListenPort(nil); ok {
		t.Fatal("expected false for nil")
	}

	// Test direct struct with pointer receiver
	mf := mockFile{addr: &net.TCPAddr{Port: 8080}}
	if port, ok := tcpListenPort(&mf); !ok || port != 8080 {
		t.Fatalf("expected 8080, got %d", port)
	}

	// Test non-TCP addr
	mf2 := mockFile{}
	if _, ok := tcpListenPort(&mf2); ok {
		t.Fatal("expected false for non-TCP addr")
	}

	// Test nested struct
	nmf := nestedMockFile{F: &mockFile{addr: &net.TCPAddr{Port: 9090}}}
	if port, ok := tcpListenPort(&nmf); !ok || port != 9090 {
		t.Fatalf("expected 9090, got %d", port)
	}

	// Test recursive loop
	type loopStruct struct {
		Self *loopStruct
	}
	ls := &loopStruct{}
	ls.Self = ls
	if _, ok := tcpListenPort(ls); ok {
		t.Fatal("expected false for loop")
	}
}
