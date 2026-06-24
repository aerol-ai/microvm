package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestStopStartSnapshotLifecycle(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()

	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		CPU:           1,
		MemoryMB:      128,
		DiskGB:        1,
		OverlaySizeGB: 1,
	}, "sb-snap-life", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := f.driver.Stop(ctx, "sb-snap-life"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !f.vmm.shutdown || !f.vmm.cleaned {
		t.Fatalf("Stop did not shut down and clean up VMM: shutdown=%v cleaned=%v", f.vmm.shutdown, f.vmm.cleaned)
	}
	if f.pool.release != 0 {
		t.Fatalf("Stop released TAP/vsock slot; release=%d, want 0 so restore keeps identity", f.pool.release)
	}
	if f.tapHost.removeCalls != 1 {
		t.Fatalf("Stop tap removes = %d, want 1", f.tapHost.removeCalls)
	}
	if len(f.driver.clients) != 0 || len(f.driver.vmms) != 0 {
		t.Fatalf("driver maps still contain stopped sandbox: clients=%d vmms=%d", len(f.driver.clients), len(f.driver.vmms))
	}

	dir, memPath, statePath, rootfsPath, overlayPath, manifestPath := f.driver.sandboxSnapshotPaths("sb-snap-life")
	for _, path := range []string{memPath, statePath, rootfsPath, overlayPath, manifestPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("snapshot artifact %s missing: %v", path, err)
		}
	}
	manifest, err := f.driver.readSandboxSnapshotManifest("sb-snap-life")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if manifest.VsockCID != 3 || !manifest.HasOverlay || manifest.SnapshotChecksum == "" {
		t.Fatalf("manifest = %+v, want cid=3 overlay=true checksum", manifest)
	}

	started, err := f.driver.Start(ctx, "sb-snap-life")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if started.Status != models.SandboxStatusStarted || started.ContainerIP != "172.16.0.2" {
		t.Fatalf("started state = %+v, want started with original guest IP", started)
	}
	if f.client.snapshotLoad == nil {
		t.Fatal("Start did not LoadSnapshot")
	}
	if f.client.snapshotLoad.SnapshotPath != filepath.Join(dir, sandboxSnapshotStateFileName) {
		t.Fatalf("LoadSnapshot path = %q, want snapshot state in %s", f.client.snapshotLoad.SnapshotPath, dir)
	}
	if f.client.snapshotLoad.VsockOverride == nil ||
		f.client.snapshotLoad.VsockOverride.UDSPath != hostVsockUDSName {
		t.Fatalf("LoadSnapshot.VsockOverride = %+v, want uds_path=%q",
			f.client.snapshotLoad.VsockOverride, hostVsockUDSName)
	}
	if patch, ok := f.client.drivePatches[rootDriveID]; !ok || patch.PathOnHost == "" {
		t.Fatalf("Start did not patch rootfs drive: %+v", f.client.drivePatches)
	}
	if patch, ok := f.client.drivePatches[overlayDriveID]; !ok || patch.PathOnHost == "" {
		t.Fatalf("Start did not patch overlay drive: %+v", f.client.drivePatches)
	}
	if patch, ok := f.client.networkPatches[primaryIfaceID]; !ok || patch.HostDevName != "fctap-test" {
		t.Fatalf("Start network patch = %+v, want fctap-test", f.client.networkPatches)
	}
	if got := f.client.actions[len(f.client.actions)-1]; got != firecracker.ActionResume {
		t.Fatalf("last action = %q, want Resume", got)
	}
}

func TestStopSnapshotFailureResumesRunningVMM(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 128,
		DiskGB:   1,
	}, "sb-snap-fail", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.client.snapshotCreateErr = os.ErrPermission

	if err := f.driver.Stop(ctx, "sb-snap-fail"); err == nil {
		t.Fatal("Stop returned nil despite snapshot failure")
	}
	if f.vmm.shutdown {
		t.Fatal("Stop shut down VMM after failed snapshot")
	}
	if got := f.client.actions[len(f.client.actions)-1]; got != firecracker.ActionResume {
		t.Fatalf("last action after failed Stop = %q, want Resume rollback", got)
	}
}
