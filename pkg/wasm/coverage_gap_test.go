package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func TestCoverageGap_ReadSnapshotDirIsolatedMismatchErrors(t *testing.T) {
	base := SnapshotCapture{
		Config: SnapshotConfig{
			SchemaVersion: snapshotSchemaVersion,
			Engine:        engineWazero,
			WASIVersion:   wasiPreview1,
		},
		Memory:    []byte("memory"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}

	t.Run("WASIStateChecksumMismatch", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteSnapshotDir(dir, base); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(dir, configFileName)
		cfgBytes, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		var cfg SnapshotConfig
		if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg.WASIStateChecksum = "sha256:deadbeef"
		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = ReadSnapshotDir(dir, engineWazero)
		if err == nil || !errors.Is(err, models.ErrSnapshotCorrupt) {
			t.Fatalf("expected ErrSnapshotCorrupt, got %v", err)
		}
	})

	t.Run("GlobalsCountMismatch", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteSnapshotDir(dir, base); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(dir, configFileName)
		cfgBytes, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		var cfg SnapshotConfig
		if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg.GlobalsCount = 999
		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = ReadSnapshotDir(dir, engineWazero)
		if err == nil || !errors.Is(err, models.ErrSnapshotCorrupt) {
			t.Fatalf("expected ErrSnapshotCorrupt, got %v", err)
		}
	})

	t.Run("CorruptMemoryZstd", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteSnapshotDir(dir, base); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, memoryFileName), []byte("not-zstd"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadSnapshotDir(dir, engineWazero)
		if err == nil || !errors.Is(err, models.ErrSnapshotCorrupt) {
			t.Fatalf("expected ErrSnapshotCorrupt, got %v", err)
		}
	})
}

func TestCoverageGap_WriteSnapshotDirReadOnlyParent(t *testing.T) {
	parent := t.TempDir()
	dst := filepath.Join(parent, "snap")
	if err := WriteSnapshotDir(dst, SnapshotCapture{Memory: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0o700)
	if err := WriteSnapshotDir(dst, SnapshotCapture{Memory: []byte("y")}); err == nil {
		t.Fatal("expected error writing into read-only parent")
	}
}

func TestCoverageGap_NewWazeroEngineInitRuntimeErrors(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", file)
	if _, err := newWazeroEngine(ctx); err == nil {
		t.Fatal("expected newWazeroEngine error for bad compile cache")
	}

	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")

	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatal(err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 10}); err != nil {
		t.Fatal(err)
	}

	old := compileModule
	compileModule = func(r wazero.Runtime, c context.Context, b []byte) (wazero.CompiledModule, error) {
		return nil, fmt.Errorf("compile failed")
	}
	t.Cleanup(func() { compileModule = old })
	if err := eng.ensureMemoryLimit(ctx, 20); err == nil {
		t.Fatal("expected ensureMemoryLimit compile error")
	}

	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", file)
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err == nil {
		t.Fatal("expected LoadModule initRuntime error")
	}
}

func TestCoverageGap_WazeroEngineInstantiateAndRunErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatal(err)
	}
	eng.compiled = nil
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 10}); err == nil {
		t.Fatal("expected Instantiate error without compiled module")
	}

	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatal(err)
	}
	if err := eng.compiled.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 10}); err == nil {
		t.Fatal("expected Instantiate error with closed compiled module")
	}

	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatal(err)
	}
	if err := eng.compiled.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Run(ctx, Capabilities{MemoryMB: 10}, "_start"); err == nil {
		t.Fatal("expected Run error with closed compiled module")
	}

	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", file)
	if _, err := eng.Run(ctx, Capabilities{MemoryMB: 20}, "_start"); err == nil {
		t.Fatal("expected Run error when ensureMemoryLimit fails")
	}
}

func TestCoverageGap_WazeroEngineSnapshotEdges(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	modPath := wasmmod.WriteCheckpointWasm(t, dir, "mem.wasm")

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)
	if err := eng.LoadModule(ctx, modPath, LoadOptions{MemoryMB: 16}); err != nil {
		t.Fatal(err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 16}); err != nil {
		t.Fatal(err)
	}
	mem := eng.module.Memory()
	if mem == nil {
		t.Fatal("expected memory")
	}
	eng.module = &snapshotModuleNoRead{Module: eng.module, mem: mem}
	if _, err := eng.CaptureSnapshot(ctx); err == nil {
		t.Fatal("expected CaptureSnapshot read error")
	}
}

type snapshotModuleNoRead struct {
	api.Module
	mem api.Memory
}

func (m *snapshotModuleNoRead) Memory() api.Memory { return &snapshotMemoryNoRead{inner: m.mem} }

type snapshotMemoryNoRead struct {
	api.Memory
	inner api.Memory
}

func (m *snapshotMemoryNoRead) Read(offset, byteCount uint32) ([]byte, bool) {
	return nil, false
}

func (m *snapshotMemoryNoRead) Size() uint32 { return m.inner.Size() }

func TestCoverageGap_MultiInstanceEngineErrors(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", file)
	if _, err := NewMultiInstanceEngine(ctx, 0); err == nil {
		t.Fatal("expected NewMultiInstanceEngine error")
	}
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")

	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")

	eng2, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng2.Close(ctx) })
	if err := eng2.LoadModule(ctx, modPath); err != nil {
		t.Fatal(err)
	}
	if err := eng2.compiled.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := eng2.Instantiate(ctx, "bad-inst", Capabilities{}); err == nil {
		t.Fatal("expected Instantiate error with closed compiled module")
	}

	eng4, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng4.Close(ctx) })
	if err := eng4.LoadModule(ctx, modPath); err != nil {
		t.Fatal(err)
	}
	if err := eng4.compiled.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := eng4.Run(ctx, "bad-run", Capabilities{}, "_start"); err == nil {
		t.Fatal("expected Run error with closed compiled module")
	}

	bare := &MultiInstanceEngine{}
	if err := bare.Close(ctx); err != nil {
		t.Fatal(err)
	}

	locked := &MultiInstanceEngine{netHost: newMultiNetHost(), netHostRegistered: true}
	locked.mu.Lock()
	if err := locked.ensureNetworkHostLocked(ctx); err != nil {
		t.Fatal(err)
	}
	locked.mu.Unlock()

	nilRuntime := &MultiInstanceEngine{netHost: newMultiNetHost()}
	nilRuntime.mu.Lock()
	if err := nilRuntime.ensureNetworkHostLocked(ctx); err == nil {
		t.Fatal("expected ensureNetworkHostLocked error without runtime")
	}
	nilRuntime.mu.Unlock()

	registered, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered.netHostRegistered = true
	registered.mu.Lock()
	if err := registered.ensureNetworkHostLocked(ctx); err != nil {
		t.Fatal(err)
	}
	registered.mu.Unlock()
	_ = registered.Close(ctx)
}

func TestCoverageGap_MultiNetHostReadWriteOutOfBounds(t *testing.T) {
	ctx := context.Background()
	host := newMultiNetHost()
	host.setHook("sb", &NetworkHook{Dial: &countingDialer{}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()

	mod := &mockModule{name: "sb", mem: &mockMemory{buf: []byte(ln.Addr().String())}}
	dialStack := []uint64{0, uint64(len(ln.Addr().String()))}
	host.tcpDial(ctx, mod, dialStack)
	connID := dialStack[0]
	if int32(connID) <= 0 {
		t.Fatalf("dial failed: %v", int32(connID))
	}
	host.tcpRead(ctx, mod, []uint64{connID, 1000, 4})
	host.tcpWrite(ctx, mod, []uint64{connID, 1000, 4})
}

func TestCoverageGap_MultiNetHostEdgeCalls(t *testing.T) {
	ctx := context.Background()
	host := newMultiNetHost()
	host.setHook("sb", &NetworkHook{Dial: &countingDialer{}})

	mod := &mockModule{name: "sb", mem: &mockMemory{buf: []byte("x")}}
	host.tcpDial(ctx, mod, []uint64{100, 100})

	left, right := net.Pipe()
	defer right.Close()
	host.putConn("sb", 3, left)
	host.tcpClose(ctx, mod, []uint64{3})
	if _, err := right.Write([]byte("x")); err == nil {
		t.Fatal("peer remained open after tcpClose")
	}

	host.tcpRead(ctx, mod, []uint64{99, 0, 1})
	host.tcpWrite(ctx, mod, []uint64{99, 0, 1})
}

func TestCoverageGap_ModuleLookupFileBranches(t *testing.T) {
	if _, ok := moduleLookupFile(&mockWazeroModNilFS{Sys: &mockWazeroSysNilFS{}}, 3); ok {
		t.Fatal("expected false for nil FS")
	}
	if _, ok := moduleLookupFile(&mockWazeroModValidFS{Sys: &mockWazeroSysValidFS{}}, 3); ok {
		t.Fatal("expected false when LookupFile misses")
	}
}

func TestCoverageGap_WasiHTTPHostReadBodyError(t *testing.T) {
	ctx := context.Background()
	hook := &NetworkHook{Dial: &countingDialer{}}
	netHost := &wazeroNetHost{hook: hook, conns: make(map[uint64]net.Conn)}
	host := &wasiHTTPHost{net: netHost}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "32")
		if _, err := w.Write([]byte("short")); err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	memBuf := make([]byte, 128)
	copy(memBuf, []byte(ts.URL))
	mod := &mockModule{mem: &mockMemory{buf: memBuf}}
	stack := []uint64{0, uint64(len(ts.URL)), 64, 64}
	host.httpGet(ctx, mod, stack)
	if stack[0] != 3 {
		t.Fatalf("expected errRequest(3), got %v", stack[0])
	}
}
