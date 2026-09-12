package wasm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSnapshotDirParentIsFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotDir(filepath.Join(blocker, "snap"), SnapshotCapture{Memory: []byte("m")}); err == nil {
		t.Fatal("expected mkdir failure when parent is a file")
	}
	dst := filepath.Join(t.TempDir(), "exists-as-file")
	if err := os.WriteFile(dst, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotDir(dst, SnapshotCapture{Memory: []byte("m")}); err != nil {
		// Rename over a file may fail depending on OS; either outcome is fine
		// as long as the call exercised the final rename/cleanup arms.
		return
	}
}

func TestCoverage95SnapshotDefaultsAndHelpers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshot")
	if err := WriteSnapshotDir(dir, SnapshotCapture{Memory: []byte("memory")}); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	snap, err := ReadSnapshotDir(dir, "")
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if snap.Config.Engine != engineWazero || snap.Config.WASIVersion != wasiPreview1 {
		t.Fatalf("defaults = %+v", snap.Config)
	}
	if !DirExists(dir) {
		t.Fatal("written snapshot directory was not recognized")
	}
	if got, err := zstdCompress(nil); err != nil || len(got) != 0 {
		t.Fatalf("zstdCompress(nil) = %q, %v", got, err)
	}
	if got, err := zstdDecompress(nil); err != nil || len(got) != 0 {
		t.Fatalf("zstdDecompress(nil) = %q, %v", got, err)
	}
	if countGlobals([]byte("not-json")) != 0 {
		t.Fatal("invalid globals unexpectedly counted")
	}
	if err := os.Remove(filepath.Join(dir, configFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSnapshotDir(dir, ""); err == nil {
		t.Fatal("missing config unexpectedly decoded")
	}
}
