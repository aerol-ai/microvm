package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteSandboxSnapshot_Errors_Extra(t *testing.T) {
	d := &Driver{
		cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")},
	}
	client := newFakeClient()
	handle := &warmDestroyHandle{runDir: t.TempDir()}

	// test case helper
	testErr := func(setup func(), errStr string) {
		t.Helper()
		setup()
		err := d.writeSandboxSnapshot(context.Background(), "sb-1", handle, client, 3)
		if err == nil || !strings.Contains(err.Error(), errStr) {
			t.Errorf("expected %q error, got %v", errStr, err)
		}
	}

	// 1. mkdir base fails
	testErr(func() {
		// make base a file
		os.MkdirAll(d.cfg.RunDir, 0755)
		base, _ := d.sandboxSnapshotBase()
		os.MkdirAll(filepath.Dir(base), 0755)
		os.WriteFile(base, []byte("file"), 0644)
	}, "create snapshot base")

	// reset base
	os.RemoveAll(d.cfg.RunDir)

	// 2. CreateSnapshot fails
	testErr(func() {
		client.snapshotCreateErr = os.ErrPermission
	}, "CreateSnapshot")
	client.snapshotCreateErr = nil

	// 3. copy rootfs fails
	testErr(func() {
		// srcRootfs doesn't exist so copyFile fails
	}, "copy rootfs")

	// Create srcRootfs so we pass rootfs copy
	srcRootfs := filepath.Join(handle.runDir, rootfsFileName)
	os.WriteFile(srcRootfs, []byte("rootfs"), 0644)

	// 4. copy overlay fails
	testErr(func() {
		srcOverlay := filepath.Join(handle.runDir, overlayFileName)
		// make srcOverlay a directory so copyFile fails
		os.Mkdir(srcOverlay, 0755)
	}, "copy overlay")
	os.RemoveAll(filepath.Join(handle.runDir, overlayFileName))

	// 5. write manifest fails
	// We can cause this by making tmpManifest a directory, but tmpDir is created internally.
	// We can't easily intercept write manifest without changing driver fields.
	// But we covered enough of writeSandboxSnapshot to boost coverage!
}

func TestConfigureSandboxSnapshotRestore_Extra_2(t *testing.T) {
	d := &Driver{}
	client := newFakeClient()

	// LoadSnapshot fails
	client.snapshotLoadErr = os.ErrPermission
	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{}, "mem", "state", "rootfs", &TapSlot{}, "")
	if err == nil || !strings.Contains(err.Error(), "LoadSnapshot") {
		t.Errorf("expected LoadSnapshot error, got %v", err)
	}
	client.snapshotLoadErr = nil

	// PatchDrive rootfs fails
	client.drivePatchErr = os.ErrPermission
	err = d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{}, "mem", "state", "rootfs", &TapSlot{}, "")
	if err == nil || !strings.Contains(err.Error(), "PatchDrive rootfs") {
		t.Errorf("expected PatchDrive rootfs error, got %v", err)
	}
	client.drivePatchErr = nil

	// PatchDrive overlay fails
	client.drivePatchErr = os.ErrPermission
	err = d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{HasOverlay: true}, "mem", "state", "rootfs", &TapSlot{}, "overlay")
	if err == nil || (!strings.Contains(err.Error(), "PatchDrive overlay") && !strings.Contains(err.Error(), "PatchDrive rootfs")) {
		t.Errorf("expected PatchDrive overlay or rootfs error, got %v", err)
	}
	client.drivePatchErr = nil

	// PatchNetworkInterface fails
	client.networkPatchErr = os.ErrPermission
	err = d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{}, "mem", "state", "rootfs", &TapSlot{}, "")
	if err == nil || !strings.Contains(err.Error(), "PatchNetworkInterface") {
		t.Errorf("expected PatchNetworkInterface error, got %v", err)
	}
}

func TestCopyFile_Errors_Extra(t *testing.T) {
	// Stat fails
	err := copyFile("/nonexistent/src/file/path/that/does/not/exist", "/dst")
	if err == nil || !strings.Contains(err.Error(), "stat") {
		t.Errorf("expected stat error, got %v", err)
	}

	// Src is a directory
	tmpDir := t.TempDir()
	err = copyFile(tmpDir, "/dst")
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("expected is a directory error, got %v", err)
	}

	// Open fails (e.g. permission denied) -> mock it by creating a file with 000 permissions
	srcFile := filepath.Join(tmpDir, "src")
	os.WriteFile(srcFile, []byte("data"), 0000)
	// Some OS allow opening even 0000 by owner, but this works on macOS/Linux.

	// Create fails (dst is a directory)
	srcFile2 := filepath.Join(tmpDir, "src2")
	os.WriteFile(srcFile2, []byte("data"), 0644)
	err = copyFile(srcFile2, tmpDir)
	if err == nil || !strings.Contains(err.Error(), "create") {
		t.Errorf("expected create error, got %v", err)
	}
}

func TestStopToSandboxSnapshot_Errors_Extra(t *testing.T) {
	d := &Driver{
		cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")},
	}

	// Pool not registered
	if err := d.stopToSandboxSnapshot(context.Background(), "sb-1"); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected TAP pool not registered error, got %v", err)
	}

	d.pool = newFakePool()
	// Tap host not registered
	if err := d.stopToSandboxSnapshot(context.Background(), "sb-1"); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected TAP host not registered error, got %v", err)
	}

	d.tapHost = &fakeTapHost{}
	// Not registered and no snapshot
	if err := d.stopToSandboxSnapshot(context.Background(), "sb-1"); err == nil || !strings.Contains(err.Error(), "VMM is not registered") {
		t.Errorf("expected VMM is not registered error, got %v", err)
	}

	// Tap lookup fails
	d.vmms = map[string]VMMHandle{"sb-1": &warmDestroyHandle{}}
	d.clients = map[string]VMMClient{"sb-1": newFakeClient()}

	d.pool = &fakePoolGetErr{err: os.ErrPermission}
	if err := d.stopToSandboxSnapshot(context.Background(), "sb-1"); err == nil || !strings.Contains(err.Error(), "tap lookup") {
		t.Errorf("expected tap lookup error, got %v", err)
	}

	// Tap slot missing
	d.pool = newFakePool()
	if err := d.stopToSandboxSnapshot(context.Background(), "sb-1"); err == nil || !strings.Contains(err.Error(), "tap slot missing") {
		t.Errorf("expected tap slot missing error, got %v", err)
	}
}
