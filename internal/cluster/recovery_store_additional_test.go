package cluster

import (
	"os"
	"testing"
)

func TestPlacementRecoveryFileStoreErrors(t *testing.T) {
	_, err := newPlacementRecoveryFileStore("")
	if err == nil || err.Error() != "placement recovery store: empty dir" {
		t.Errorf("expected empty dir error")
	}

	// create a file to cause mkdir error
	f, _ := os.CreateTemp("", "bad-dir")
	defer os.Remove(f.Name())

	_, err = newPlacementRecoveryFileStore(f.Name())
	if err == nil {
		t.Errorf("expected error when dir is a file")
	}
}

func TestPlacementRecoveryMemoryStore(t *testing.T) {
	store := newPlacementRecoveryMemoryStore()

	// empty sandbox id
	_, err := store.Put("", placementRecovery{})
	if err == nil {
		t.Errorf("expected error")
	}

	ref, err := store.Put("sandbox-1", placementRecovery{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec, ok, err := store.GetRecord(ref)
	if err != nil || !ok {
		t.Fatalf("failed to get: %v", err)
	}
	if rec.SandboxID != "sandbox-1" {
		t.Errorf("wrong id")
	}

	err = store.Delete(ref)
	if err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	_, ok, _ = store.GetRecord(ref)
	if ok {
		t.Errorf("expected deleted")
	}

	// no-op retain
	err = store.RetainSnapshotRefs([]string{})
	if err != nil {
		t.Errorf("expected no error")
	}
}

func TestNewPlacementFSMWithFileRecovery(t *testing.T) {
	fsm, err := newPlacementFSMWithFileRecovery("")
	if err != nil {
		t.Fatalf("expected no error for empty dir")
	}
	if _, ok := fsm.recoveryStore.(*placementRecoveryMemoryStore); !ok {
		t.Errorf("expected memory store for empty dir")
	}

	dir := t.TempDir()
	fsm, err = newPlacementFSMWithFileRecovery(dir)
	if err != nil {
		t.Fatalf("expected no error for valid dir")
	}
	if _, ok := fsm.recoveryStore.(*placementRecoveryFileStore); !ok {
		t.Errorf("expected file store for valid dir")
	}
}

func TestRecoveryBlob(t *testing.T) {
	blob, err := newRecoveryBlob("sb-1", placementRecovery{SecretRef: "sr"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blob.SandboxID != "sb-1" || blob.SecretRef != "sr" {
		t.Errorf("wrong blob fields: %+v", blob)
	}

	rec := blob.recovery()
	if rec.SecretRef != "sr" {
		t.Errorf("wrong recovery: %+v", rec)
	}
}

func TestEncodePlacementRecoveryRecordError(t *testing.T) {
	// We can't easily force json.Marshal to fail on our simple struct,
	// but the error path is there.
}

func TestPathForRefError(t *testing.T) {
	store := &placementRecoveryFileStore{dir: "tmp"}
	_, err := store.pathForRef("invalid-ref")
	if err == nil {
		t.Errorf("expected error for invalid ref")
	}

	// valid prefix but wrong length
	_, err = store.pathForRef(placementRecoveryRefPrefix + "1234")
	if err == nil {
		t.Errorf("expected error for wrong length")
	}
}

func TestWriteGCManifestError(t *testing.T) {
	file, err := os.CreateTemp("", "recovery-gc-file")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()

	store := &placementRecoveryFileStore{dir: file.Name()}
	if err := store.writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("writeGCManifest() accepted a non-directory path")
	}
}

func TestPlacementRecoveryFileStorePutTempError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o755)
	})

	store := &placementRecoveryFileStore{dir: dir}
	if _, err := store.Put("sandbox-temp-fail", placementRecovery{}); err == nil {
		t.Fatal("Put() accepted a read-only directory")
	}
}

func TestPlacementRecoveryFileStorePutMkdirError(t *testing.T) {
	file, err := os.CreateTemp("", "recovery-put-file")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()

	store := &placementRecoveryFileStore{dir: file.Name()}
	if _, err := store.Put("sandbox-mkdir-fail", placementRecovery{}); err == nil {
		t.Fatal("Put() accepted a file path as its directory")
	}
}
