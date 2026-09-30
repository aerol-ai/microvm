package wasm

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// (func (export "_start") unreachable)
	cov96TrapWasmHex = "0061736d01000000" +
		"010401600000" +
		"03020100" +
		"070a01065f737461727400" + "00" +
		"0a050103" + "00000b"
	// (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
	// (func (export "_start") i32.const 3 call 0)
	cov96ExitWasmHex = "0061736d01000000" +
		"01080260017f00600000" +
		"0224" + "01" + "16" + "776173695f736e617073686f745f7072657669657731" + "09" + "70726f635f65786974" + "0000" +
		"03020101" +
		"070a01065f737461727400" + "01" +
		"0a0801060041031000" + "0b"
)

func cov96WriteWasm(t *testing.T, name, hexStr string) string {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cov96NoListenCaps() Capabilities {
	return Capabilities{WASIListenPort: WASIListenPortDisabled}
}

func TestCov96MultiInstanceRunGuestExitAndTrap(t *testing.T) {
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")
	ctx := context.Background()

	t.Run("proc_exit is a result, not an error", func(t *testing.T) {
		eng, err := NewMultiInstanceEngine(ctx, 16)
		if err != nil {
			t.Fatal(err)
		}
		if err := eng.LoadModule(ctx, cov96WriteWasm(t, "exit.wasm", cov96ExitWasmHex)); err != nil {
			t.Fatal(err)
		}
		res, err := eng.Run(ctx, "sb-exit", cov96NoListenCaps(), "_start")
		if err != nil || res.ExitCode != 3 {
			t.Fatalf("Run = %+v, %v; want exit code 3 and no error", res, err)
		}
	})

	t.Run("trap surfaces in stderr and error", func(t *testing.T) {
		eng, err := NewMultiInstanceEngine(ctx, 16)
		if err != nil {
			t.Fatal(err)
		}
		if err := eng.LoadModule(ctx, cov96WriteWasm(t, "trap.wasm", cov96TrapWasmHex)); err != nil {
			t.Fatal(err)
		}
		res, err := eng.Run(ctx, "sb-trap", cov96NoListenCaps(), "_start")
		if err == nil || !strings.Contains(res.Stderr, "unreachable") {
			t.Fatalf("Run = %+v, %v; want trap error echoed to stderr", res, err)
		}
	})
}

func TestCov96WazeroRunGuestExitIsNotAnError(t *testing.T) {
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")
	ctx := context.Background()
	eng, err := NewEngineFor(ctx, "wazero")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, cov96WriteWasm(t, "exit.wasm", cov96ExitWasmHex), LoadOptions{MemoryMB: 16}); err != nil {
		t.Fatal(err)
	}
	res, err := eng.Run(ctx, cov96NoListenCaps(), "_start")
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("Run = %+v, %v; want exit code 3 and no error", res, err)
	}
}

func TestCov96WazeroMemoryResizeFailsWhenRuntimeCannotBeRebuilt(t *testing.T) {
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")
	ctx := context.Background()
	notADir := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngineFor(ctx, "wazero")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, cov96WriteWasm(t, "exit.wasm", cov96ExitWasmHex), LoadOptions{MemoryMB: 16}); err != nil {
		t.Fatal(err)
	}
	caps := cov96NoListenCaps()
	caps.MemoryMB = 32

	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", notADir)
	if err := eng.Instantiate(ctx, caps); err == nil || !strings.Contains(err.Error(), "compilation cache") {
		t.Fatalf("Instantiate = %v, want compilation cache error", err)
	}
}

func TestCov96WazeroCloseIsIdempotent(t *testing.T) {
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")
	ctx := context.Background()
	eng, err := NewEngineFor(ctx, "wazero")
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Close(ctx); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := eng.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
