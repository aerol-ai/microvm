package wasm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSnapshotCodecRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mem.snap")
	cap := SnapshotCapture{
		Config: SnapshotConfig{
			SchemaVersion:   snapshotSchemaVersion,
			Engine:          engineWazero,
			EngineVersion:   "test",
			WASIVersion:     wasiPreview1,
			BaseModule:      SnapshotBaseModule{Digest: "sha256:abc", Size: 42},
			Entrypoint:      "_start",
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-1",
		},
		Memory:    []byte("linear-memory-bytes"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := WriteSnapshotDir(dir, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	got, err := ReadSnapshotDir(dir, engineWazero)
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if string(got.Memory) != string(cap.Memory) {
		t.Fatalf("memory = %q, want %q", got.Memory, cap.Memory)
	}
	if got.Config.CloneGeneration != cap.Config.CloneGeneration {
		t.Fatalf("clone_generation = %q", got.Config.CloneGeneration)
	}
}

func TestSnapshotCodecRejectsCorruptMemory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mem.snap")
	cap := SnapshotCapture{
		Config: SnapshotConfig{
			SchemaVersion: snapshotSchemaVersion,
			Engine:        engineWazero,
			BaseModule:    SnapshotBaseModule{Digest: "d", Size: 1},
		},
		Memory:    []byte("ok"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := WriteSnapshotDir(dir, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	memPath := filepath.Join(dir, memoryFileName)
	if err := osWriteCorrupt(memPath); err != nil {
		t.Fatalf("corrupt memory file: %v", err)
	}
	_, err := ReadSnapshotDir(dir, engineWazero)
	if !errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Fatalf("ReadSnapshotDir err = %v, want ErrSnapshotCorrupt", err)
	}
}

func osWriteCorrupt(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 0 {
		b[len(b)-1] ^= 0xff
	}
	return os.WriteFile(path, b, 0o600)
}
