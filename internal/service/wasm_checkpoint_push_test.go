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

func TestWasmCheckpointPusherEdgeBranches(t *testing.T) {
	ctx := context.Background()

	if _, err := NewWasmCheckpointPusher(SnapshotPushConfig{Enabled: true}, nil); err == nil {
		t.Fatal("invalid config should fail NewWasmCheckpointPusher")
	}
	if p, err := NewWasmCheckpointPusher(SnapshotPushConfig{Enabled: false}, nil); err != nil || p != nil {
		t.Fatalf("disabled config = (%v, %v), want (nil, nil)", p, err)
	}

	var nilPusher *WasmCheckpointPusher
	if _, err := nilPusher.PushOnce(ctx, "sb", "/tmp"); err == nil {
		t.Fatal("nil pusher should reject PushOnce")
	}
	if _, err := nilPusher.PushOnceTo(ctx, "sb", "/tmp", "dest"); err == nil {
		t.Fatal("nil pusher should reject PushOnceTo")
	}
	if err := nilPusher.PullOnce(ctx, "ref", "/tmp"); err == nil {
		t.Fatal("nil pusher should reject PullOnce")
	}
	if err := nilPusher.DeleteRef(ctx, "ref"); err == nil {
		t.Fatal("nil pusher should reject DeleteRef")
	}

	p, err := NewWasmCheckpointPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.example.com",
		ClusterID: "c1",
		PATPath:   filepath.Join(t.TempDir(), "pat"),
	}, nil)
	if err != nil {
		t.Fatalf("NewWasmCheckpointPusher: %v", err)
	}
	if _, err := p.PushOnceTo(ctx, "sb", filepath.Join(t.TempDir(), "missing"), "dest"); err == nil {
		t.Fatal("PushOnceTo should fail on missing checkpoint dir")
	}
}
