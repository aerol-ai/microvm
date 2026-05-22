package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPlacementRecoveryFileStoreDeleteRemovesBlobAndIgnoresMissing(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}

	ref, err := store.Put("sb-delete", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"}})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, ok, err := store.GetRecord(ref); err != nil || ok {
		t.Fatalf("GetRecord() after delete = ok:%v err:%v, want ok:false err:nil", ok, err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("Delete() missing ref error = %v, want nil", err)
	}
}

func TestPlacementRecoveryFileStoreDeleteRejectsInvalidRef(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}

	err = store.Delete("bad-ref")
	if err == nil || !strings.Contains(err.Error(), "invalid ref") {
		t.Fatalf("Delete() error = %v, want invalid ref", err)
	}
}

func TestPlacementRecoveryMemoryStoreDeleteRemovesBlob(t *testing.T) {
	store := newPlacementRecoveryMemoryStore()
	ref, err := store.Put("sb-memory-delete", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"}})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, ok, err := store.Get(ref); err != nil || ok {
		t.Fatalf("Get() after delete = ok:%v err:%v, want ok:false err:nil", ok, err)
	}
	if err := store.Delete(""); err != nil && !errors.Is(err, nil) {
		t.Fatalf("Delete() empty ref error = %v, want nil", err)
	}
}

func TestPlacementRecoveryFileStoreGetRecordRejectsCorruptBlob(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}

	ref := placementRecoveryRefPrefix + strings.Repeat("0", 64)
	path, err := store.pathForRef(ref)
	if err != nil {
		t.Fatalf("pathForRef() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, ok, err := store.GetRecord(ref)
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("GetRecord() error = %v, want decode error", err)
	}
	if ok {
		t.Fatal("GetRecord() ok = true, want false for corrupt blob")
	}
}

func TestPlacementRecoveryFileStoreRetainSnapshotRefsGCsUnreferencedBlobs(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}

	keepRef, err := store.Put("sb-keep", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"}})
	if err != nil {
		t.Fatalf("Put(keep) error = %v", err)
	}
	dropRef, err := store.Put("sb-drop", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "busybox:latest"}})
	if err != nil {
		t.Fatalf("Put(drop) error = %v", err)
	}

	if err := store.RetainSnapshotRefs([]string{"", keepRef, keepRef}); err != nil {
		t.Fatalf("RetainSnapshotRefs() error = %v", err)
	}
	if _, ok, err := store.GetRecord(keepRef); err != nil || !ok {
		t.Fatalf("GetRecord(keep) = ok:%v err:%v, want ok:true err:nil", ok, err)
	}
	if _, ok, err := store.GetRecord(dropRef); err != nil || ok {
		t.Fatalf("GetRecord(drop) = ok:%v err:%v, want ok:false err:nil", ok, err)
	}
	manifest, err := store.readGCManifest()
	if err != nil {
		t.Fatalf("readGCManifest() error = %v", err)
	}
	if len(manifest.Snapshots) != 1 {
		t.Fatalf("len(manifest.Snapshots) = %d, want 1", len(manifest.Snapshots))
	}
	if refs := manifest.Snapshots[0].Refs; len(refs) != 1 || refs[0] != keepRef {
		t.Fatalf("manifest refs = %v, want [%s]", refs, keepRef)
	}
}

func TestPlacementRecoveryFileStoreRetainSnapshotRefsRejectsCorruptManifest(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}
	if err := os.WriteFile(store.gcManifestPath(), []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err = store.RetainSnapshotRefs([]string{placementRecoveryRefPrefix + strings.Repeat("0", 64)})
	if err == nil || !strings.Contains(err.Error(), "decode gc manifest") {
		t.Fatalf("RetainSnapshotRefs() error = %v, want decode gc manifest", err)
	}
}
