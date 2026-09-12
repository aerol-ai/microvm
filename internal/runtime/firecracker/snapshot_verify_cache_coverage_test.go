package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSnapshotVerifyKeyFor_Errors(t *testing.T) {
	dir := t.TempDir()
	memPath := filepath.Join(dir, "mem")
	statePath := filepath.Join(dir, "state")
	if err := os.WriteFile(statePath, []byte("state"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	if _, err := snapshotVerifyKeyFor(memPath, statePath, "sha256:a|sha256:b"); err == nil || !strings.Contains(err.Error(), "stat memory") {
		t.Fatalf("missing memory: got %v", err)
	}
	if err := os.WriteFile(memPath, []byte("mem"), 0o600); err != nil {
		t.Fatalf("write mem: %v", err)
	}
	if _, err := snapshotVerifyKeyFor(memPath, filepath.Join(dir, "missing-state"), "sha256:a|sha256:b"); err == nil || !strings.Contains(err.Error(), "stat state") {
		t.Fatalf("missing state: got %v", err)
	}
}

func TestSnapshotFileIdentityFor_HappyAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, []byte("bytes"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	id, err := snapshotFileIdentityFor(path)
	if err != nil {
		t.Fatalf("snapshotFileIdentityFor: %v", err)
	}
	if id.path != path || id.size != 5 {
		t.Fatalf("identity = %+v", id)
	}
	if _, err := snapshotFileIdentityFor(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected stat error for missing file")
	}
}

func TestVerifySnapshotForLoad_KeyBuildFailureFallsThrough(t *testing.T) {
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	if err := d.verifySnapshotForLoad("tpl", "/no/mem", "/no/state", "sum"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("verifier calls = %d, want 1 on stat failure fallback", calls)
	}
}

func TestInvalidateSnapshotVerifyCacheForTemplate(t *testing.T) {
	d := New(Config{}, nil)
	d.invalidateSnapshotVerifyCacheForTemplate("")
	memPath, statePath, sum := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	key, err := snapshotVerifyKeyFor(memPath, statePath, sum)
	if err != nil {
		t.Fatal(err)
	}
	d.verifiedTemplates = map[string]snapshotVerifyKey{"tpl": key}
	d.verifiedSnapshots = map[snapshotVerifyKey]*snapshotVerifyEntry{key: {done: make(chan struct{})}}
	d.invalidateSnapshotVerifyCacheForTemplate("tpl")
	if len(d.verifiedTemplates) != 0 || len(d.verifiedSnapshots) != 0 {
		t.Fatalf("cache not cleared: templates=%d snapshots=%d", len(d.verifiedTemplates), len(d.verifiedSnapshots))
	}
}
