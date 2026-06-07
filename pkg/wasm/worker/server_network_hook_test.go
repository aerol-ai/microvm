package worker

import (
	"context"
	"net"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestServerBindNetworkHookMediatedDialNetstats(t *testing.T) {
	srv := &Server{}
	srv.mu.Lock()
	eng, err := wasmengine.NewEngineFor(context.Background(), "")
	if err != nil {
		srv.mu.Unlock()
		t.Fatalf("NewEngineFor: %v", err)
	}
	srv.eng = eng
	srv.mu.Unlock()
	defer func() { _ = eng.Close(context.Background()) }()

	const sandboxID = "sb-net-hook"
	srv.bindNetworkHook(sandboxID)

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("ping"))
	}()

	ne, ok := eng.(wasmengine.NetworkAwareEngine)
	if !ok {
		t.Fatal("engine missing NetworkAwareEngine")
	}
	_ = ne

	conn, err := srv.mediator().DialContext(context.Background(), sandboxID, "tcp", backend.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n == 0 {
		t.Fatal("expected bytes from backend")
	}

	in, out := srv.mediator().DrainUsage(sandboxID)
	if in != int64(n) {
		t.Fatalf("bytes_in = %d, want %d", in, n)
	}
	if out != 0 {
		t.Fatalf("bytes_out = %d, want 0", out)
	}
}
