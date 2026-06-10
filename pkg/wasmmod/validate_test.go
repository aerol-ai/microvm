package wasmmod

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeBytes(t *testing.T, name, hexStr string) string {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateFileCoreModuleOK(t *testing.T) {
	// MinimalWasmHex carries layer 0x0000 (core module).
	if err := ValidateFile(writeBytes(t, "core.wasm", MinimalWasmHex)); err != nil {
		t.Fatalf("core module should validate, got: %v", err)
	}
}

func TestValidateFileRejectsComponent(t *testing.T) {
	// Component Model preamble: magic + version 0x000d + layer 0x0001.
	const componentHdr = "0061736d0d000100"
	err := ValidateFile(writeBytes(t, "thing.component.wasm", componentHdr))
	if err == nil {
		t.Fatal("component artifact should be rejected")
	}
	if !errors.Is(err, ErrComponentModelUnsupported) {
		t.Fatalf("want ErrComponentModelUnsupported, got: %v", err)
	}
}

func TestValidateFileBadMagic(t *testing.T) {
	err := ValidateFile(writeBytes(t, "bad.wasm", "deadbeef01000000"))
	if err == nil {
		t.Fatal("bad magic should be rejected")
	}
	if errors.Is(err, ErrComponentModelUnsupported) {
		t.Fatalf("bad magic must not be reported as a component: %v", err)
	}
}

func TestValidateFileShortHeaderPassesMagic(t *testing.T) {
	// A 4-byte file has valid magic but no layer field — not our job to flag.
	if err := ValidateFile(writeBytes(t, "tiny.wasm", "0061736d")); err != nil {
		t.Fatalf("4-byte magic-only file should pass magic check, got: %v", err)
	}
}

func TestValidateFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.wasm")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(path); err == nil {
		t.Fatal("empty file should be rejected")
	}
}

func TestValidateFileTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.wasm")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(256<<20 + 1)
	f.Close()
	if err := ValidateFile(path); err == nil {
		t.Fatal("large file should be rejected")
	}
}
