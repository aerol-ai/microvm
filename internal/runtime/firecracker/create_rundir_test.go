package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreate_CreatesRunDirBeforeStaging is the regression guard for the
// firecracker cold-boot mkfs failure (cluster-hetero UC-24):
//
//	oci: mkfs.ext4 -d <bundle> -F <runDir>/rootfs.ext4 ...:
//	  mkfs.ext4: No such file or directory while trying to determine
//	  filesystem size
//
// In jailer mode handle.RunDir() is the chroot root
// (<chroot-base>/firecracker/<id>/root), which the jailer binary only
// materializes when it execs firecracker — i.e. at Start, AFTER the driver
// stages the rootfs into it. The driver must MkdirAll(handle.RunDir()) before
// staging or the OCI build writes into a directory that doesn't exist.
//
// The default fixture spawner pre-creates the runDir, which would mask the
// bug; this test overrides it with a jailer-shaped spawner that returns a
// runDir it deliberately does NOT create, then asserts Create still succeeds
// (the fakeRootfs writes its output into the runDir, so a missing dir fails
// Build exactly like real mkfs).
func TestCreate_CreatesRunDirBeforeStaging(t *testing.T) {
	f := newDriverFixture(t)

	chrootRoot := filepath.Join(t.TempDir(), "jailer", "firecracker", "sb-jailer", "root")
	f.driver.SetSpawner(func(_ Config, sandboxID string) (VMMHandle, error) {
		f.vmm.id = sandboxID
		f.vmm.runDir = chrootRoot // intentionally not created — mimics the jailer chroot
		f.vmm.apiSocket = filepath.Join(chrootRoot, "api.sock")
		return f.vmm, nil
	})

	if _, err := os.Stat(chrootRoot); !os.IsNotExist(err) {
		t.Fatalf("precondition: chrootRoot must not exist yet, stat err = %v", err)
	}

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   1,
	}, "sb-jailer", "tok", nil); err != nil {
		t.Fatalf("Create with non-existent runDir: %v (regression: driver must MkdirAll runDir before staging)", err)
	}

	if f.rootfs.builds != 1 {
		t.Fatalf("rootfs builds = %d, want 1", f.rootfs.builds)
	}
	if _, err := os.Stat(chrootRoot); err != nil {
		t.Fatalf("runDir not created by driver before staging: %v", err)
	}
}

func TestSnapshotTemplate_CreatesRunDirBeforeStaging(t *testing.T) {
	f := newDriverFixture(t)

	chrootRoot := filepath.Join(t.TempDir(), "jailer", "firecracker", "tpl-snap-tpl-rundir", "root")
	f.driver.SetSpawner(func(_ Config, sandboxID string) (VMMHandle, error) {
		f.vmm.id = sandboxID
		f.vmm.runDir = chrootRoot // intentionally not created — mimics the jailer chroot
		f.vmm.apiSocket = filepath.Join(chrootRoot, "api.sock")
		return f.vmm, nil
	})

	if _, err := os.Stat(chrootRoot); !os.IsNotExist(err) {
		t.Fatalf("precondition: chrootRoot must not exist yet, stat err = %v", err)
	}

	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}

	_, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl-rundir",
		RootfsPath:    rootfs,
		OutMemoryPath: filepath.Join(tplDir, "snapshot.memory"),
		OutStatePath:  filepath.Join(tplDir, "snapshot.state"),
		GuestCID:      200,
		MemoryMB:      512,
		VCPU:          1,
	})
	if err != nil {
		t.Fatalf("SnapshotTemplate with non-existent runDir: %v (regression: driver must MkdirAll runDir before staging)", err)
	}

	if _, err := os.Stat(chrootRoot); err != nil {
		t.Fatalf("runDir not created by driver before staging: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(chrootRoot, rootfsFileName)); err != nil || string(got) != "rootfs" {
		t.Fatalf("staged rootfs = %q, %v", got, err)
	}
}

func TestSnapshotTemplate_JailerStagesAPIPaths(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.ToolboxBinaryPath = "/opt/aerolvm/toolboxd"

	chrootRoot := filepath.Join(t.TempDir(), "jailer", "firecracker", "tpl-snap-tpl-jail", "root")
	f.driver.SetSpawner(func(_ Config, sandboxID string) (VMMHandle, error) {
		f.vmm.id = sandboxID
		f.vmm.runDir = chrootRoot
		f.vmm.apiSocket = filepath.Join(chrootRoot, "api.sock")
		f.client.snapshotBase = chrootRoot
		return f.vmm, nil
	})

	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}

	memOut := filepath.Join(tplDir, "snapshot.memory")
	stateOut := filepath.Join(tplDir, "snapshot.state")
	_, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl-jail",
		RootfsPath:    rootfs,
		OutMemoryPath: memOut,
		OutStatePath:  stateOut,
		GuestCID:      200,
		MemoryMB:      512,
		VCPU:          1,
	})
	if err != nil {
		t.Fatalf("SnapshotTemplate (jailer): %v", err)
	}

	if _, err := os.Stat(filepath.Join(chrootRoot, kernelFileName)); err != nil {
		t.Fatalf("kernel not staged into chroot: %v", err)
	}
	if f.client.bs == nil || f.client.bs.KernelImagePath != kernelFileName {
		t.Fatalf("boot source kernel path = %+v, want %q", f.client.bs, kernelFileName)
	}
	if !strings.Contains(f.client.bs.BootArgs, "init="+guestInitPath) {
		t.Fatalf("snapshot boot args missing toolbox init: %q", f.client.bs.BootArgs)
	}
	if !strings.Contains(f.client.bs.BootArgs, "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off") {
		t.Fatalf("snapshot boot args missing TAP ip config: %q", f.client.bs.BootArgs)
	}
	if root := f.client.drives[rootDriveID]; root.PathOnHost != rootfsFileName {
		t.Fatalf("root drive path = %q, want %q", root.PathOnHost, rootfsFileName)
	}
	if overlay := f.client.drives[overlayDriveID]; overlay.PathOnHost != overlayFileName {
		t.Fatalf("overlay drive path = %q, want %q", overlay.PathOnHost, overlayFileName)
	}
	if f.client.snapshotCreate == nil {
		t.Fatal("CreateSnapshot was not called")
	}
	if f.client.snapshotCreate.MemFilePath != sandboxSnapshotMemoryFileName ||
		f.client.snapshotCreate.SnapshotPath != sandboxSnapshotStateFileName {
		t.Fatalf("snapshot create paths = %+v, want chroot-relative snapshot files", f.client.snapshotCreate)
	}
	for _, path := range []string{memOut, stateOut} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("snapshot artifact %s was not copied out of chroot: %v", path, err)
		}
	}
}

func TestCreate_SnapshotLoadPath_JailerStagesAPIPaths(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true

	chrootRoot := filepath.Join(t.TempDir(), "jailer", "firecracker", "sb-snap-load-jail", "root")
	f.driver.SetSpawner(func(_ Config, sandboxID string) (VMMHandle, error) {
		f.vmm.id = sandboxID
		f.vmm.runDir = chrootRoot
		f.vmm.apiSocket = filepath.Join(chrootRoot, "api.sock")
		return f.vmm, nil
	})

	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, rootfsFileName)
	if err := os.WriteFile(templateRootfs, []byte("template-rootfs"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, sandboxSnapshotMemoryFileName)
	snapState := filepath.Join(tplDir, sandboxSnapshotStateFileName)
	for _, path := range []string{snapMem, snapState} {
		if err := os.WriteFile(path, []byte("snapshot-"+filepath.Base(path)), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotVsockCID:   200,
	})

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		TemplateID: "tpl-snap-jail",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
	}, "sb-snap-load-jail", "tok", nil); err != nil {
		t.Fatalf("Create snapshot-load (jailer): %v", err)
	}

	if f.client.snapshotLoad == nil {
		t.Fatal("LoadSnapshot was not called")
	}
	if f.client.snapshotLoad.SnapshotPath != sandboxSnapshotStateFileName {
		t.Fatalf("LoadSnapshot.SnapshotPath = %q, want %q", f.client.snapshotLoad.SnapshotPath, sandboxSnapshotStateFileName)
	}
	if f.client.snapshotLoad.MemBackend == nil ||
		f.client.snapshotLoad.MemBackend.BackendPath != sandboxSnapshotMemoryFileName {
		t.Fatalf("LoadSnapshot.MemBackend = %+v, want chroot-relative snapshot memory", f.client.snapshotLoad.MemBackend)
	}
	if patch := f.client.drivePatches[rootDriveID]; patch.PathOnHost != rootfsFileName {
		t.Fatalf("root drive patch path = %q, want %q", patch.PathOnHost, rootfsFileName)
	}
	for _, name := range []string{rootfsFileName, sandboxSnapshotMemoryFileName, sandboxSnapshotStateFileName} {
		if _, err := os.Stat(filepath.Join(chrootRoot, name)); err != nil {
			t.Fatalf("%s not staged into chroot: %v", name, err)
		}
	}
}

func TestConfigureVMMForLoad_JailerStagesOverlayBeforeLoadSnapshot(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true

	runDir := t.TempDir()
	rootfsPath := filepath.Join(runDir, rootfsFileName)
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	tplDir := t.TempDir()
	snapMem := filepath.Join(tplDir, sandboxSnapshotMemoryFileName)
	snapState := filepath.Join(tplDir, sandboxSnapshotStateFileName)
	overlayPath := filepath.Join(tplDir, overlayFileName)
	for _, path := range []string{snapMem, snapState, overlayPath} {
		if err := os.WriteFile(path, []byte("artifact-"+filepath.Base(path)), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	client := newFakeClient()
	client.loadSnapshotHook = func() error {
		_, err := os.Stat(filepath.Join(runDir, overlayFileName))
		return err
	}
	err := f.driver.configureVMMForLoad(context.Background(), client, &TemplateResolution{
		SnapshotMemoryPath: snapMem,
		SnapshotStatePath:  snapState,
	}, rootfsPath, &TapSlot{TapName: "fctap0"}, overlayPath)
	if err != nil {
		t.Fatalf("configureVMMForLoad: %v", err)
	}
	if patch := client.drivePatches[overlayDriveID]; patch.PathOnHost != overlayFileName {
		t.Fatalf("overlay drive patch path = %q, want %q", patch.PathOnHost, overlayFileName)
	}
}
