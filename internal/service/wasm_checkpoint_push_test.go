package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestWasmCheckpointPusherDestRefFor(t *testing.T) {
	p, err := NewWasmCheckpointPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.example.com",
		ClusterID: "cluster-1",
		PATPath:   t.TempDir() + "/pat",
	}, nil)
	if err != nil {
		t.Fatalf("NewWasmCheckpointPusher: %v", err)
	}
	got := p.DestRefFor("SB-ABC")
	want := wasmmod.WasmCheckpointRef("aocr.example.com", "cluster-1", "SB-ABC")
	if got != want {
		t.Fatalf("DestRefFor = %q, want %q", got, want)
	}
}

func TestWasmCheckpointPusherPushOnceRequiresPaths(t *testing.T) {
	p, err := NewWasmCheckpointPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.example.com",
		ClusterID: "c1",
		PATPath:   filepath.Join(t.TempDir(), "pat"),
	}, nil)
	if err != nil {
		t.Fatalf("NewWasmCheckpointPusher: %v", err)
	}
	if _, err := p.PushOnce(context.Background(), "", "/tmp/x"); err == nil {
		t.Fatal("expected error for empty sandbox id")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.PushOnce(context.Background(), "sb-1", dir); err == nil {
		t.Fatal("expected push error without PAT file")
	}
}
