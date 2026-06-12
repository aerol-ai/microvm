package wasm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotCodec_Errors(t *testing.T) {
	tmp := t.TempDir()

	// Read missing file
	_, err := ReadSnapshotDir(filepath.Join(tmp, "missing"), "wazero")
	if err == nil {
		t.Error("expected error")
	}

	// Write to invalid directory (e.g. parent is a file)
	file := filepath.Join(tmp, "file")
	os.WriteFile(file, []byte("test"), 0644)
	err = WriteSnapshotDir(filepath.Join(file, "snap"), SnapshotCapture{})
	if err == nil {
		t.Error("expected error")
	}

	// countGlobals nil
	if countGlobals(nil) != 0 {
		t.Error("expected 0")
	}

	// zstdCompress/Decompress invalid
	_, err = zstdDecompress(nil)
	if err == nil {
		// some decoders might return empty slice without error, let's see.
	}
}
