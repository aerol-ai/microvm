package wasmmod

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// MinimalWasmHex is a valid wasm module: (module (func) (export "_start" (func 0))).
// Used by pkg/wasm and pkg/wasmmod tests — the export name length must be 6, not 4.
const MinimalWasmHex = "0061736d0100000001040160000003020100070a01065f737461727400000a040102000b"

// WriteMinimalWasm writes a compile-ready empty _start module into dir/name.
func WriteMinimalWasm(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := hex.DecodeString(MinimalWasmHex)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
