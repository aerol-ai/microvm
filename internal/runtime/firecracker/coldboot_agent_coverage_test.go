package firecracker

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestProbeToolboxTCP_UsesGuestToolboxPort(t *testing.T) {
	addr := net.JoinHostPort("127.0.0.1", "2280")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("toolbox port in use: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	dialed := false
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		dialed = true
		mu.Unlock()
		_ = conn.Close()
	}()

	d := New(Config{PostResumeTimeout: time.Second}, nil)
	d.probeToolboxTCP(context.Background(), "create", "sb-port", &TapSlot{
		GuestIP: "127.0.0.1",
		TapName: "tap0",
	}, false)
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !dialed {
		t.Fatal("probe did not dial toolbox port")
	}
}
