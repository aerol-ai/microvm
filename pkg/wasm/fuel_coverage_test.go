package wasm

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverage95RuntimeAndListenerHelperBranches(t *testing.T) {
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", t.TempDir())
	runtime, err := newBaseRuntime(context.Background(), 1)
	if err != nil {
		t.Fatalf("newBaseRuntime: %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "not-a-cache-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", file)
	if _, err := newBaseRuntime(context.Background(), 0); err == nil {
		t.Fatal("file cache path unexpectedly initialized")
	}

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if port, ok := tcpListenPort(ln); !ok || port == 0 {
		t.Fatalf("tcpListenPort(listener) = %d, %v", port, ok)
	}
	if _, ok := tcpListenPort(nil); ok {
		t.Fatal("nil file unexpectedly exposed a port")
	}
	if got := MemoryLimitPages(int(^uint(0) >> 1)); got != ^uint32(0) {
		t.Fatalf("large memory cap = %d, want uint32 max", got)
	}
	if got := WallTimeoutFromCaps(Capabilities{WallTimeoutNs: -1}); got != DefaultWallTimeout {
		t.Fatalf("negative timeout = %v", got)
	}
}
