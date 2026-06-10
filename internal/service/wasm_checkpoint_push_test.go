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

func TestWasmCheckpointPusherPullOnce(t *testing.T) {
	p, err := NewWasmCheckpointPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.example.com",
		ClusterID: "c1",
		PATPath:   filepath.Join(t.TempDir(), "nonexistent-pat"),
	}, nil)
	if err != nil {
		t.Fatalf("NewWasmCheckpointPusher: %v", err)
	}

	err = p.PullOnce(context.Background(), "", "/tmp")
	if err == nil || err.Error() != "wasm checkpoint pull: registry ref and destination dir required" {
		t.Fatalf("expected required params error, got %v", err)
	}

	err = p.PullOnce(context.Background(), "test://ref", "/tmp/x")
	if err == nil {
		t.Fatal("expected pull error without PAT file")
	}
}

func TestWasmCheckpointPusherDeleteRef(t *testing.T) {
	p, err := NewWasmCheckpointPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.example.com",
		ClusterID: "c1",
		PATPath:   filepath.Join(t.TempDir(), "nonexistent-pat"),
	}, nil)
	if err != nil {
		t.Fatalf("NewWasmCheckpointPusher: %v", err)
	}

	err = p.DeleteRef(context.Background(), "test://ref")
	if err == nil {
		t.Fatal("expected delete error without PAT file")
	}
}
