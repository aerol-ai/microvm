package wasm

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCoverage95SnapshotDefaultsAndHelpers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshot")
	if err := WriteSnapshotDir(dir, SnapshotCapture{Memory: []byte("memory")}); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	snap, err := ReadSnapshotDir(dir, "")
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if snap.Config.Engine != engineWazero || snap.Config.WASIVersion != wasiPreview1 {
		t.Fatalf("defaults = %+v", snap.Config)
	}
	if !DirExists(dir) {
		t.Fatal("written snapshot directory was not recognized")
	}
	if got, err := zstdCompress(nil); err != nil || len(got) != 0 {
		t.Fatalf("zstdCompress(nil) = %q, %v", got, err)
	}
	if got, err := zstdDecompress(nil); err != nil || len(got) != 0 {
		t.Fatalf("zstdDecompress(nil) = %q, %v", got, err)
	}
	if countGlobals([]byte("not-json")) != 0 {
		t.Fatal("invalid globals unexpectedly counted")
	}
	if err := os.Remove(filepath.Join(dir, configFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSnapshotDir(dir, ""); err == nil {
		t.Fatal("missing config unexpectedly decoded")
	}
}

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

func TestCoverage95EngineReinitializationAndPreopen(t *testing.T) {
	ctx := context.Background()
	module := wasmmod.WriteMinimalWasm(t, t.TempDir(), "minimal.wasm")
	engine, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close(ctx) })
	if err := engine.LoadModule(ctx, module, LoadOptions{MemoryMB: 1}); err != nil {
		t.Fatal(err)
	}
	caps := Capabilities{
		Env:      map[string]string{"COVERAGE_KEY": "value"},
		MemoryMB: 2,
		Preopens: []Preopen{{HostPath: t.TempDir()}},
	}
	if err := engine.Instantiate(ctx, caps); err != nil {
		t.Fatalf("Instantiate with a changed memory limit and preopen: %v", err)
	}
	if err := engine.StopInstance(ctx); err != nil {
		t.Fatal(err)
	}

	multi, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = multi.Close(ctx) })
	if err := multi.LoadModule(ctx, module); err != nil {
		t.Fatal(err)
	}
	if err := multi.Instantiate(ctx, "preopen", caps); err != nil {
		t.Fatalf("multi Instantiate with preopen: %v", err)
	}
	if _, err := multi.Run(ctx, "preopen", caps, ""); err != nil {
		t.Fatalf("multi Run with default export: %v", err)
	}
}
