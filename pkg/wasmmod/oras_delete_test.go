package wasmmod

import (
	"testing"
)

func TestDeleteSnapshotRefRequiresInputs(t *testing.T) {
	if err := DeleteSnapshotRef(t.Context(), ORASPushConfig{}, ""); err == nil {
		t.Fatal("expected error for empty ref")
	}
	if err := DeleteSnapshotRef(t.Context(), ORASPushConfig{
		Host:      "aocr.example.com",
		ClusterID: "c1",
		PATPath:   t.TempDir() + "/missing",
	}, WasmCheckpointRef("aocr.example.com", "c1", "sb-1")); err == nil {
		t.Fatal("expected error without PAT")
	}
}
