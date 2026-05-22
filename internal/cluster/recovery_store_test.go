package cluster

import (
	"errors"
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
