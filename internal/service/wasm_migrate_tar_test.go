package service

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestWasmCheckpointTarRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "mem.snap")
	cap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			EngineVersion:   "test",
			WASIVersion:     "preview1",
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc", Size: 42},
			Entrypoint:      "_start",
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-migrate-1",
		},
		Memory:    []byte("linear-memory"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := wasmengine.WriteSnapshotDir(src, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	var tarBuf bytes.Buffer
	if err := writeWasmCheckpointTar(&tarBuf, src); err != nil {
		t.Fatalf("writeWasmCheckpointTar: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "mem.snap")
	if err := extractWasmCheckpointTar(bytes.NewReader(tarBuf.Bytes()), dst); err != nil {
		t.Fatalf("extractWasmCheckpointTar: %v", err)
	}
	got, err := wasmengine.ReadSnapshotDir(dst, wasmengine.EngineNameWazero())
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if got.Config.CloneGeneration != cap.Config.CloneGeneration {
		t.Fatalf("clone_generation = %q, want %q", got.Config.CloneGeneration, cap.Config.CloneGeneration)
	}
	if string(got.Memory) != string(cap.Memory) {
		t.Fatalf("memory = %q, want %q", got.Memory, cap.Memory)
	}
}
