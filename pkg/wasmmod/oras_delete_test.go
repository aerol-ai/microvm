package wasmmod

import (
	"os"
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

	patFile := t.TempDir() + "/pat"
	if err := os.WriteFile(patFile, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSnapshotRef(t.Context(), ORASPushConfig{
		Host: "h", ClusterID: "c", PATPath: patFile,
	}, "http://\x00invalid"); err == nil {
		t.Fatal("expected err for bad registry ref")
	}
}
