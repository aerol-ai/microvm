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

func TestPlacementRecoveryFileStorePutAndGetRecordRoundTrip(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}

	ref, err := store.Put("sb-roundtrip", placementRecovery{
		Spec:          &models.CreateSandboxRequest{Image: "alpine:3.20", Env: map[string]string{"A": "1"}},
		SecretRef:     "cluster-secret:demo",
		SecretVersion: 7,
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if !strings.HasPrefix(ref, placementRecoveryRefPrefix) {
		t.Fatalf("Put() ref = %q, want %q prefix", ref, placementRecoveryRefPrefix)
	}

	record, ok, err := store.GetRecord(ref)
	if err != nil || !ok {
		t.Fatalf("GetRecord() = ok:%v err:%v, want ok:true err:nil", ok, err)
	}
	if record.SandboxID != "sb-roundtrip" {
		t.Fatalf("GetRecord() sandbox id = %q, want sb-roundtrip", record.SandboxID)
	}
	if record.Recovery.Spec == nil || record.Recovery.Spec.Image != "alpine:3.20" {
		t.Fatalf("GetRecord() spec = %+v, want alpine spec", record.Recovery.Spec)
	}
	if record.Recovery.SecretRef != "cluster-secret:demo" || record.Recovery.SecretVersion != 7 {
		t.Fatalf("GetRecord() secrets = %+v, want ref/version preserved", record.Recovery)
	}

	record.Recovery.Spec.Image = "mutated"
	record.Recovery.Spec.Env["A"] = "mutated"
	again, ok, err := store.GetRecord(ref)
	if err != nil || !ok {
		t.Fatalf("GetRecord() second read = ok:%v err:%v, want ok:true err:nil", ok, err)
	}
	if again.Recovery.Spec == nil || again.Recovery.Spec.Image != "alpine:3.20" || again.Recovery.Spec.Env["A"] != "1" {
		t.Fatalf("GetRecord() second read spec = %+v, want original alpine spec", again.Recovery.Spec)
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

func TestPlacementRecoveryFileStoreRetainSnapshotRefsKeepsLastThreeWindows(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(filepath.Join(t.TempDir(), "recovery"))
	if err != nil {
		t.Fatalf("newPlacementRecoveryFileStore() error = %v", err)
	}

	refs := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		ref, err := store.Put("sb-window-"+string(rune('a'+i)), placementRecovery{Spec: &models.CreateSandboxRequest{Image: "image:" + string(rune('a'+i))}})
		if err != nil {
			t.Fatalf("Put(%d) error = %v", i, err)
		}
		refs = append(refs, ref)
		if err := store.RetainSnapshotRefs([]string{ref}); err != nil {
			t.Fatalf("RetainSnapshotRefs(%q) error = %v", ref, err)
		}
	}

	manifest, err := store.readGCManifest()
	if err != nil {
		t.Fatalf("readGCManifest() error = %v", err)
	}
	if len(manifest.Snapshots) != placementRecoverySnapshotRefSets {
		t.Fatalf("len(manifest.Snapshots) = %d, want %d", len(manifest.Snapshots), placementRecoverySnapshotRefSets)
	}
	for i, want := range refs[1:] {
		if got := manifest.Snapshots[i].Refs; len(got) != 1 || got[0] != want {
			t.Fatalf("manifest window %d refs = %v, want [%s]", i, got, want)
		}
	}
	if _, ok, err := store.GetRecord(refs[0]); err != nil || ok {
		t.Fatalf("GetRecord(oldest) = ok:%v err:%v, want ok:false err:nil", ok, err)
	}
	for _, ref := range refs[1:] {
		if _, ok, err := store.GetRecord(ref); err != nil || !ok {
			t.Fatalf("GetRecord(%q) = ok:%v err:%v, want ok:true err:nil", ref, ok, err)
		}
	}
}
