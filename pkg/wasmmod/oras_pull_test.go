package wasmmod

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPullSnapshotArtifactRequiresInputs(t *testing.T) {
	ctx := t.Context()
	cfg := ORASPullConfig{}

	if err := PullSnapshotArtifact(ctx, cfg, "", ""); err == nil {
		t.Fatal("expected err for empty registryRef and dstDir")
	}
	if err := PullSnapshotArtifact(ctx, cfg, "registry", "dir"); err == nil {
		t.Fatal("expected err from validation")
	}

	cfg = ORASPullConfig{Host: "host", ClusterID: "c1", PATPath: filepath.Join(t.TempDir(), "missing")}
	if err := PullSnapshotArtifact(ctx, cfg, "registry", "dir"); err == nil {
		t.Fatal("expected err from missing PAT")
	}

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.PATPath = patFile

	// bad registry ref causes NewRepository to fail
	if err := PullSnapshotArtifact(ctx, cfg, "http://\x00invalid", t.TempDir()); err == nil {
		t.Fatal("expected err from bad registry ref")
	}
}

func TestORASPullConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  ORASPullConfig
		err  bool
	}{
		{"empty", ORASPullConfig{}, true},
		{"no cluster", ORASPullConfig{Host: "host"}, true},
		{"no pat", ORASPullConfig{Host: "host", ClusterID: "c1"}, true},
		{"valid", ORASPullConfig{Host: "host", ClusterID: "c1", PATPath: "pat"}, false},
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
