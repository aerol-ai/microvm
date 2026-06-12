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

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Missing directory
	_, err = PushSnapshotArtifact(t.Context(), ORASPushConfig{
		Host: "h", ClusterID: "c", PATPath: patFile,
	}, t.TempDir()+"/missing_dir", "reg/ref:tag")
	if err == nil {
		t.Fatal("expected err for missing dir")
	}

	// Missing config.json
	emptyDir := t.TempDir()
	_, err = PushSnapshotArtifact(t.Context(), ORASPushConfig{
		Host: "h", ClusterID: "c", PATPath: patFile,
	}, emptyDir, "reg/ref:tag")
	if err == nil {
		t.Fatal("expected err for missing config.json")
	}

	// Bad registry ref
	_, err = PushSnapshotArtifact(t.Context(), ORASPushConfig{
		Host: "h", ClusterID: "c", PATPath: patFile,
	}, dir, "http://\x00invalid")
	if err == nil {
		t.Fatal("expected err for bad registry ref")
	}
}

func TestWasmCheckpointRefTagged(t *testing.T) {
	got := WasmCheckpointRefTagged("aocr.example.com", "c1", "sb1", "mytag")
	if got != "aocr.example.com/cluster/c1/wasm-checkpoints/sb1:mytag" {
		t.Fatalf("got %q", got)
	}
	got = WasmCheckpointRefTagged("aocr.example.com", "c1", "sb1", "")
	if got != "aocr.example.com/cluster/c1/wasm-checkpoints/sb1:latest" {
		t.Fatalf("got %q", got)
	}
}

func TestWasmCheckpointDigestTag(t *testing.T) {
	got := WasmCheckpointDigestTag("sha256:1234567890abcdef")
	if got != "1234567890abcdef" {
		t.Fatalf("got %q", got)
	}
	got = WasmCheckpointDigestTag("1234567890abcdef")
	if got != "1234567890abcdef" {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryHelpers(t *testing.T) {
	if registryHost("host/path") != "host" {
		t.Fatal("registryHost failed")
	}
	if registryTag("host/path:tag") != "tag" {
		t.Fatal("registryTag failed")
	}
	if registryTag("host/path") != "latest" {
		t.Fatal("registryTag failed")
	}
	// codex P2: a :port on the host must not be parsed as the tag, and an
	// @sha256:<digest> pin must resolve to the digest reference.
	cases := map[string]string{
		"host:5000/repo:v1":           "v1",
		"host:5000/repo":              "latest",
		"host/repo@sha256:abc123":     "sha256:abc123",
		"host:5000/ns/repo@sha256:de": "sha256:de",
		"host:5000/ns/repo":           "latest",
	}
	for ref, want := range cases {
		if got := registryTag(ref); got != want {
			t.Fatalf("registryTag(%q) = %q, want %q", ref, got, want)
		}
	}
	if registryHost("host:5000/repo:v1") != "host:5000" {
		t.Fatal("registryHost should preserve :port")
	}
}

func TestORASPushConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  ORASPushConfig
		err  bool
	}{
		{"empty", ORASPushConfig{}, true},
		{"no cluster", ORASPushConfig{Host: "host"}, true},
		{"no pat", ORASPushConfig{Host: "host", ClusterID: "c1"}, true},
		{"valid", ORASPushConfig{Host: "host", ClusterID: "c1", PATPath: "pat"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.err {
				t.Fatalf("expected err %v, got %v", tc.err, err)
			}
		})
	}
}
