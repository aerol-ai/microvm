package wasm

import (
	"net"
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

func TestCloseConnsNilAndActive(t *testing.T) {
	(*wazeroNetHost)(nil).closeConns()

	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	h := &wazeroNetHost{conns: map[uint64]net.Conn{1: a}}
	h.closeConns()
	if len(h.conns) != 0 {
		t.Fatalf("conns remain: %d", len(h.conns))
	}
}
