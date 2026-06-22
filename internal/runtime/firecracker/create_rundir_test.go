package firecracker

import (
	"context"
	"os"
	"path/filepath"
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
