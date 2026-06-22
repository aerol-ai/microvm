package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreate_JailerStagesKernelAndUsesRelativePaths is the regression guard for
// the firecracker cold-boot failure that surfaced once the OCI rootfs build
// started succeeding (cluster-hetero UC-24/UC-88):
//
//	PUT /boot-source -> 400: Boot source error: The kernel file cannot be
//	opened: No such file or directory
//
// In jailer mode firecracker is chrooted into the runDir, so the kernel must be
// staged inside it and every path handed to the firecracker API must be
// chroot-relative. The driver previously passed the absolute host kernel path
// (and absolute rootfs/overlay paths), which the jailed firecracker cannot
// open. This test drives the cold-boot path with UseJailer=true and asserts the
// kernel is hardlinked into the chroot and the API receives bare relative names.
func TestCreate_JailerStagesKernelAndUsesRelativePaths(t *testing.T) {
	tmp := t.TempDir()
	// A real kernel file the driver stat-checks and then stages into the chroot.
	hostKernel := filepath.Join(tmp, "vmlinux-host")
	if err := os.WriteFile(hostKernel, []byte("fake-kernel"), 0o644); err != nil {
		t.Fatalf("write kernel: %v", err)
	}
	// The chroot root the fake spawner reports as the VMM runDir. Not created
	// here on purpose — the driver's MkdirAll(runDir) (the UC-24 mkfs fix) makes
	// it, then the kernel/rootfs land inside it.
	chroot := filepath.Join(tmp, "jailer", "firecracker", "sb-jail", "root")

	pool := newFakePool()
	rootfs := &fakeRootfs{}
	tap := &fakeTapHost{}
	vsock := newFakeVsockDialer()
	client := newFakeClient()
	vmm := &fakeVMM{}

	d := New(Config{
		KernelImage:    hostKernel,
		RunDir:         tmp,
		UseJailer:      true,
		OverlayEnabled: true, // exercise the overlay PutDrive path too
	}, nil)
	d.SetPool(pool)
	d.SetRootfsBuilder(rootfs)
	d.SetTapHost(tap)
	d.SetVsockDialer(vsock)
	d.SetSpawner(func(_ Config, id string) (VMMHandle, error) {
		vmm.id = id
		vmm.runDir = chroot
		vmm.apiSocket = filepath.Join(chroot, "api.sock")
		return vmm, nil
	})
	d.SetClientFactory(func(_ string) VMMClient { return client })

	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		CPU:           1,
		MemoryMB:      256,
		DiskGB:        1,
		OverlaySizeGB: 1,
	}, "sb-jail", "tok", nil); err != nil {
		t.Fatalf("Create (jailer): %v", err)
	}

	// The kernel must now exist inside the chroot under its relative name.
	if _, err := os.Stat(filepath.Join(chroot, kernelFileName)); err != nil {
		t.Fatalf("kernel not staged into chroot: %v", err)
	}
	// The firecracker API must have received chroot-relative paths, never the
	// absolute host paths the jailed process cannot open.
	if client.bs == nil {
		t.Fatal("PutBootSource never called")
	}
	if client.bs.KernelImagePath != kernelFileName {
		t.Errorf("boot source kernel path = %q, want relative %q", client.bs.KernelImagePath, kernelFileName)
	}
	if dr, ok := client.drives[rootDriveID]; !ok {
		t.Error("root drive never set")
	} else if dr.PathOnHost != rootfsFileName {
		t.Errorf("root drive path = %q, want relative %q", dr.PathOnHost, rootfsFileName)
	}
	if dr, ok := client.drives[overlayDriveID]; !ok {
		t.Error("overlay drive never set")
	} else if dr.PathOnHost != overlayFileName {
		t.Errorf("overlay drive path = %q, want relative %q", dr.PathOnHost, overlayFileName)
	}
}
