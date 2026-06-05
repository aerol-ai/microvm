package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadWriteSandboxSnapshotManifest_Extra(t *testing.T) {
	d := &Driver{
		cfg: Config{RunDir: t.TempDir()},
	}

	sbID := "test-manifest"
	_, _, _, _, _, manifestPath := d.sandboxSnapshotPaths(sbID)
	os.MkdirAll(filepath.Dir(manifestPath), 0755)

	// read error (invalid JSON)
	os.WriteFile(manifestPath, []byte("not-json"), 0644)
	if _, err := d.readSandboxSnapshotManifest(sbID); err == nil || !strings.Contains(err.Error(), "decode sandbox") {
		t.Errorf("expected decode error, got %v", err)
	}

	// writeSandboxSnapshot: directory doesn't exist? Wait, it creates the dir.
	// But if the client fails to CreateSnapshot, it fails. I'll test CreateSnapshot failure in writeSandboxSnapshot.
	client := newFakeClient()
	client.snapshotCreateErr = os.ErrPermission
	err := d.writeSandboxSnapshot(context.Background(), sbID, &warmDestroyHandle{}, client, 3)
	if err == nil || !strings.Contains(err.Error(), "permission") {
		t.Errorf("expected permission error, got %v", err)
	}
}

func TestConfigureSandboxSnapshotRestore_Extra(t *testing.T) {
	d := &Driver{}
	client := newFakeClient()
	client.snapshotLoadErr = os.ErrPermission

	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{}, "", "", "", &TapSlot{}, "")
	if err == nil || !strings.Contains(err.Error(), "LoadSnapshot") {
		t.Errorf("expected LoadSnapshot error, got %v", err)
	}

	client.snapshotLoadErr = nil
	client.drivePatchErr = os.ErrPermission
	err = d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{}, "", "", "", &TapSlot{}, "")
	if err == nil || !strings.Contains(err.Error(), "PatchDrive rootfs") {
		t.Errorf("expected PatchDrive error, got %v", err)
	}

	client.drivePatchErr = nil
	client.networkPatchErr = os.ErrPermission
	err = d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{}, "", "", "", &TapSlot{}, "")
	if err == nil || !strings.Contains(err.Error(), "PatchNetworkInterface") {
		t.Errorf("expected PatchNetworkInterface error, got %v", err)
	}
}
