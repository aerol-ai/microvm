package wasm

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/sys"
)

func TestMultiNetHost_HelperBranches(t *testing.T) {
	host := newMultiNetHost()
	if host.resolveHook("missing") != nil {
		t.Fatal("expected nil hook for unknown sandbox")
	}

	m := &mockMeter{}
	hook := &NetworkHook{SandboxID: "a", Dial: &countingDialer{}, Meter: m}
	host.setHook("a", hook)
	if got := host.resolveHook("a"); got != hook {
		t.Fatal("resolveHook did not return stored hook")
	}

	c1, c2 := net.Pipe()
	host.putConn("a", 1, c1)
	conn, meter := host.takeConn("a", 1)
	if conn == nil || meter == nil {
		t.Fatal("expected conn and meter from takeConn")
	}
	if host.popConn("a", 1) == nil {
		t.Fatal("expected conn from popConn")
	}
	if host.popConn("a", 1) != nil {
		t.Fatal("expected nil after popConn removed conn")
	}
	_ = conn.Close()
	_ = c2.Close()

	c3, c4 := net.Pipe()
	host.putConn("a", 2, c3)
	host.closeConns("a")
	_, meter2 := host.takeConn("a", 2)
	if meter2 != nil {
		t.Fatal("expected conn removed after closeConns")
	}
	_ = c4.Close()

	host.setHook("a", hook)
	c5, c6 := net.Pipe()
	host.putConn("a", 3, c5)
	host.closeAll()
	if host.resolveHook("a") != nil {
		t.Fatal("expected no hook after closeAll")
	}
	_, meter3 := host.takeConn("a", 3)
	if meter3 != nil {
		t.Fatal("expected conn removed after closeAll")
	}
	_ = c6.Close()
	if host.popConn("a", 3) != nil {
		t.Fatal("expected nil from popConn on closed host")
	}
}

func TestMultiInstanceEngine_RunReplacesOldInstance(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })

	if err := eng.LoadModule(ctx, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}

	caps := Capabilities{Args: []string{"wasm"}}
	res, err := eng.Run(ctx, "same", caps, "_start")
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("first Run exit=%d", res.ExitCode)
	}

	res2, err := eng.Run(ctx, "same", caps, "_start")
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if res2.ExitCode != 0 {
		t.Fatalf("second Run exit=%d", res2.ExitCode)
	}
	if got := eng.InstanceCount(); got != 1 {
		t.Fatalf("InstanceCount=%d, want 1", got)
	}

	res3, err := eng.Run(ctx, "same", caps, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing export")
	}
	if res3.ExitCode != 1 {
		t.Fatalf("expected exit code 1 on missing export, got %d", res3.ExitCode)
	}
}

func TestMultiInstanceEngine_InvokeExportErrors(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })

	if err := eng.LoadModule(ctx, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, "one", Capabilities{}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := eng.InvokeExport(ctx, "missing", "_start"); err == nil {
		t.Fatal("expected error for unknown sandbox")
	}
	if err := eng.InvokeExport(ctx, "one", "does-not-exist"); err == nil {
		t.Fatal("expected error for missing export")
	}
	if eng.instanceModule("one") == nil {
		t.Fatal("expected instanceModule to return a module")
	}
}

func TestWazeroEngine_LoadModuleClosesActiveModule(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, modPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 10}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := eng.LoadModule(ctx, modPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule again: %v", err)
	}
}

func TestWazeroEngine_LastLoadTimingsReported(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, modPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if got := eng.LastLoadTimings().Compile; got <= 0 {
		t.Fatalf("expected compile timing > 0, got %v", got)
	}
}

func TestWazeroEngine_EnsureWasiHostsNilRuntime(t *testing.T) {
	eng := &wazeroEngine{}
	if err := eng.ensureWasiSocketsHost(context.Background()); err != nil {
		t.Fatalf("ensureWasiSocketsHost: %v", err)
	}
	if err := eng.ensureWasiHTTPHost(context.Background()); err != nil {
		t.Fatalf("ensureWasiHTTPHost: %v", err)
	}
}

func TestWazeroEngine_WithWasip1Meter(t *testing.T) {
	ctx := context.Background()
	ctx2 := withWasip1Meter(ctx, nil)
	if ctx2 != ctx {
		t.Fatal("expected same ctx when hook is nil")
	}
	ctx3 := withWasip1Meter(ctx, &NetworkHook{Meter: &mockMeter{}})
	if ctx3 == nil {
		t.Fatal("expected non-nil ctx")
	}
}

type fakeListener struct{}

func (fakeListener) Addr() net.Addr { return &net.TCPAddr{Port: 54321} }

type fakeEntry struct{ File any }

type fakeFS struct{}

func (fakeFS) LookupFile(fd int32) (fakeEntry, bool) {
	return fakeEntry{File: &fakeListener{}}, true
}

type fakeSys struct{}

func (fakeSys) FS() *fakeFS { return &fakeFS{} }

type fakeMod struct {
	Sys *fakeSys
	api.Module
}

func (fakeMod) Name() string { return "fake" }

func TestResolvedListenPort_FakeModule(t *testing.T) {
	mod := &fakeMod{Sys: &fakeSys{}}
	if _, ok := moduleLookupFile(mod, 3); !ok {
		t.Fatal("expected moduleLookupFile to find a fake listener entry")
	}
	port, ok := ResolvedListenPort(mod)
	if !ok || port != 54321 {
		t.Fatalf("ResolvedListenPort = (%d,%v), want (54321,true)", port, ok)
	}
}

func TestSnapshotCodec_WriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "snapshot")
	cap := SnapshotCapture{
		Memory:    []byte("hello"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := WriteSnapshotDir(dst, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	snap, err := ReadSnapshotDir(dst, EngineNameWazero())
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if string(snap.Memory) != "hello" {
		t.Fatalf("snapshot memory = %q", string(snap.Memory))
	}
}

func TestExitCodeFromInvoke_WasiExit(t *testing.T) {
	if got := exitCodeFromInvoke(nil); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
	if got := exitCodeFromInvoke(context.Canceled); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	if got := exitCodeFromInvoke(sys.NewExitError(7)); got != 7 {
		t.Fatalf("expected 7, got %d", got)
	}
}
