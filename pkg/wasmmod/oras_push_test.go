package wasmmod

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWasmCheckpointRef(t *testing.T) {
	got := WasmCheckpointRef("aocr.example.com/", "cluster-1", "SB-1")
	want := "aocr.example.com/cluster/cluster-1/wasm-checkpoints/sb-1:latest"
	if got != want {
		t.Fatalf("WasmCheckpointRef = %q, want %q", got, want)
	}
}

func TestPushSnapshotArtifactRequiresInputs(t *testing.T) {
	_, err := PushSnapshotArtifact(t.Context(), ORASPushConfig{}, "", "")
	if err == nil {
		t.Fatal("expected error for empty inputs")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = PushSnapshotArtifact(t.Context(), ORASPushConfig{
		Host:      "aocr.example.com",
		ClusterID: "c1",
		PATPath:   t.TempDir() + "/missing",
	}, dir, WasmCheckpointRef("aocr.example.com", "c1", "sb-1"))
	if err == nil {
		t.Fatal("expected error without PAT")
	}
}
