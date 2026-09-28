package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// A checkpoint ref names the sandbox LIFETIME, not just the id: the id-wide
// :latest that every lifetime shared is gone.
func TestWasmCheckpointRefsAreLifetimeScoped(t *testing.T) {
	p, err := NewWasmCheckpointPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.example.com",
		ClusterID: "cluster-1",
		PATPath:   t.TempDir() + "/pat",
	}, nil)
	if err != nil {
		t.Fatalf("NewWasmCheckpointPusher: %v", err)
	}
	svc := &Service{wasmCheckpointPusher: p}
	got := svc.wasmCheckpointLatestRef("SB-ABC", "inc-1")
	want := wasmmod.WasmCheckpointRefTagged("aocr.example.com", "cluster-1", "SB-ABC", wasmmod.WasmCheckpointLatestTag("inc-1"))
	if got != want {
		t.Fatalf("latest ref = %q, want %q", got, want)
	}
	if got == wasmmod.WasmCheckpointRef("aocr.example.com", "cluster-1", "SB-ABC") {
		t.Fatal("the lifetime's rolling ref is still the id-wide :latest")
	}
	if svc.wasmCheckpointLatestRef("SB-ABC", "inc-2") == got {
		t.Fatal("two lifetimes of one sandbox share a rolling ref")
	}
	if svc.wasmCheckpointLatestRef("SB-ABC", "") != "" || svc.wasmCheckpointDigestRef("SB-ABC", "", "sha256:x") != "" {
		t.Fatal("a ref was produced with no lifetime to scope it to")
	}
	if (&Service{}).wasmCheckpointLatestRef("SB-ABC", "inc-1") != "" {
		t.Fatal("a ref was produced with checkpoint push disabled")
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
	dest := (&Service{wasmCheckpointPusher: p}).wasmCheckpointLatestRef("sb-1", "inc-1")
	if _, err := p.PushOnceTo(context.Background(), "", "inc-1", "/tmp/x", dest); err == nil {
		t.Fatal("expected error for empty sandbox id")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.PushOnceTo(context.Background(), "sb-1", "inc-1", dir, dest); err == nil {
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

	err = p.PullOnce(context.Background(), "", "inc-1", "/tmp")
	if err == nil || err.Error() != "wasm checkpoint pull: registry ref and destination dir required" {
		t.Fatalf("expected required params error, got %v", err)
	}

	err = p.PullOnce(context.Background(), "test://ref", "inc-1", "/tmp/x")
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
	if _, err := nilPusher.PushOnceTo(ctx, "sb", "inc", "/tmp", "dest"); err == nil {
		t.Fatal("nil pusher should reject PushOnceTo")
	}
	if err := nilPusher.PullOnce(ctx, "ref", "inc", "/tmp"); err == nil {
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
	if _, err := p.PushOnceTo(ctx, "sb", "inc-1", filepath.Join(t.TempDir(), "missing"), "dest"); err == nil {
		t.Fatal("PushOnceTo should fail on missing checkpoint dir")
	}
}
