package wasm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotCodec_MoreErrors(t *testing.T) {
	// Write error paths
	badDir := filepath.Join("/does/not/exist/we/hope", "foo")
	cap := SnapshotCapture{
		Memory: []byte("some memory"),
	}
	if err := WriteSnapshotDir(badDir, cap); err == nil {
		t.Error("expected error writing to bad dir")
	}

	// Read error paths
	tmp := t.TempDir()

	// Corrupted config.json
	os.WriteFile(filepath.Join(tmp, configFileName), []byte("bad json"), 0644)
	if _, err := ReadSnapshotDir(tmp, ""); err == nil {
		t.Error("expected error decoding config")
	}

	// Schema version mismatch
	os.WriteFile(filepath.Join(tmp, configFileName), []byte(`{"schema_version": 999}`), 0644)
	if _, err := ReadSnapshotDir(tmp, ""); err == nil {
		t.Error("expected error on unsupported schema version")
	}

	// Engine mismatch
	os.WriteFile(filepath.Join(tmp, configFileName), []byte(`{"schema_version": 1, "engine": "foo"}`), 0644)
	if _, err := ReadSnapshotDir(tmp, "bar"); err == nil {
		t.Error("expected error on engine mismatch")
	}

	// Globals count mismatch
	os.WriteFile(filepath.Join(tmp, configFileName), []byte(`{"schema_version": 1, "engine": "wazero", "memory_checksum": "sha256:456c6db2ed40316e6d1c92d5351a44e54cd7da9c1b85994270d10dcae44a4789", "wasi_state_checksum": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "globals_count": 99}`), 0644)

	memZ, _ := zstdCompress([]byte("some memory"))
	os.WriteFile(filepath.Join(tmp, memoryFileName), memZ, 0644)
	os.WriteFile(filepath.Join(tmp, globalsFileName), []byte("[]"), 0644)
	os.WriteFile(filepath.Join(tmp, wasiStateFileName), []byte("{}"), 0644)

	if _, err := ReadSnapshotDir(tmp, "wazero"); err == nil {
		t.Error("expected error on globals count mismatch")
	}

	// WASI checksum mismatch
	os.WriteFile(filepath.Join(tmp, configFileName), []byte(`{"schema_version": 1, "engine": "wazero", "memory_checksum": "sha256:456c6db2ed40316e6d1c92d5351a44e54cd7da9c1b85994270d10dcae44a4789", "wasi_state_checksum": "sha256:bad"}`), 0644)
	if _, err := ReadSnapshotDir(tmp, "wazero"); err == nil {
		t.Error("expected error on wasi state checksum mismatch")
	}

	// DirExists false
	if DirExists("   ") {
		t.Error("DirExists empty string should be false")
	}
}

func TestReadSnapshotDir_MissingFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	cap := SnapshotCapture{
		Config:    SnapshotConfig{SchemaVersion: snapshotSchemaVersion},
		Memory:    []byte("mem"),
		Globals:   []byte("globals"),
		WASIState: []byte("wasi"),
	}

	// Missing memory
	_ = WriteSnapshotDir(dir, cap)
	_ = os.Remove(filepath.Join(dir, memoryFileName))
	if _, err := ReadSnapshotDir(dir, ""); err == nil {
		t.Error("expected error on missing memory")
	}

	// Missing globals
	_ = WriteSnapshotDir(dir, cap)
	_ = os.Remove(filepath.Join(dir, globalsFileName))
	if _, err := ReadSnapshotDir(dir, ""); err == nil {
		t.Error("expected error on missing globals")
	}

	// Missing wasi state
	_ = WriteSnapshotDir(dir, cap)
	_ = os.Remove(filepath.Join(dir, wasiStateFileName))
	if _, err := ReadSnapshotDir(dir, ""); err == nil {
		t.Error("expected error on missing wasi state")
	}
}

func TestWriteSnapshotDir_MkdirErr(t *testing.T) {
	// If the parent directory is a file, MkdirAll will fail!
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, []byte("data"), 0644)

	dir := filepath.Join(f, "snap")
	err := WriteSnapshotDir(dir, SnapshotCapture{Memory: []byte{}})
	if err == nil {
		t.Error("expected error on MkdirAll failure")
	}
}
