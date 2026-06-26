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
	if patch, ok := f.client.drivePatches[rootDriveID]; !ok || patch.PathOnHost == "" {
		t.Fatalf("Start did not patch rootfs drive: %+v", f.client.drivePatches)
	}
	if patch, ok := f.client.drivePatches[overlayDriveID]; !ok || patch.PathOnHost == "" {
		t.Fatalf("Start did not patch overlay drive: %+v", f.client.drivePatches)
	}
	if got := f.client.snapshotLoad.NetworkOverrides; len(got) != 1 ||
		got[0].IfaceID != primaryIfaceID ||
		got[0].HostDevName != "fctap-test" {
		t.Fatalf("Start network overrides = %+v, want eth0 -> fctap-test", got)
	}
	if len(f.client.networkPatches) != 0 {
		t.Fatalf("Start patched network interface on snapshot restore: %+v", f.client.networkPatches)
	}
	if got := f.client.vmStates[len(f.client.vmStates)-1]; got != firecracker.VMStateResumed {
		t.Fatalf("last VM state = %q, want Resumed", got)
	}
}

func TestConfigureSandboxSnapshotRestore_JailerStagesAPIPaths(t *testing.T) {
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	runDir := t.TempDir()

	srcDir := t.TempDir()
	memPath := filepath.Join(srcDir, sandboxSnapshotMemoryFileName)
	statePath := filepath.Join(srcDir, sandboxSnapshotStateFileName)
	for _, path := range []string{memPath, statePath} {
		if err := os.WriteFile(path, []byte("snapshot-"+filepath.Base(path)), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	rootfsPath := filepath.Join(runDir, rootfsFileName)
	overlayPath := filepath.Join(t.TempDir(), overlayFileName)
	for _, path := range []string{rootfsPath, overlayPath} {
		if err := os.WriteFile(path, []byte("drive-"+filepath.Base(path)), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	client.loadSnapshotHook = func() error {
		_, err := os.Stat(filepath.Join(runDir, overlayFileName))
		return err
	}

	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{
		HasOverlay: true,
	}, memPath, statePath, rootfsPath, &TapSlot{TapName: "fctap0"}, overlayPath)
	if err != nil {
		t.Fatalf("configureSandboxSnapshotRestore: %v", err)
	}

	if client.snapshotLoad == nil {
		t.Fatal("LoadSnapshot was not called")
	}
	if client.snapshotLoad.SnapshotPath != sandboxSnapshotStateFileName {
		t.Fatalf("LoadSnapshot.SnapshotPath = %q, want %q", client.snapshotLoad.SnapshotPath, sandboxSnapshotStateFileName)
	}
	if client.snapshotLoad.MemBackend == nil ||
		client.snapshotLoad.MemBackend.BackendPath != sandboxSnapshotMemoryFileName {
		t.Fatalf("LoadSnapshot.MemBackend = %+v, want chroot-relative snapshot memory", client.snapshotLoad.MemBackend)
	}
	if patch := client.drivePatches[rootDriveID]; patch.PathOnHost != rootfsFileName {
		t.Fatalf("root drive patch path = %q, want %q", patch.PathOnHost, rootfsFileName)
	}
	if patch := client.drivePatches[overlayDriveID]; patch.PathOnHost != overlayFileName {
		t.Fatalf("overlay drive patch path = %q, want %q", patch.PathOnHost, overlayFileName)
	}
	if got := client.snapshotLoad.NetworkOverrides; len(got) != 1 ||
		got[0].IfaceID != primaryIfaceID ||
		got[0].HostDevName != "fctap0" {
		t.Fatalf("network overrides = %+v, want eth0 -> fctap0", got)
	}
	for _, name := range []string{sandboxSnapshotMemoryFileName, sandboxSnapshotStateFileName, overlayFileName} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("%s not staged into restore chroot: %v", name, err)
		}
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
	if got := f.client.vmStates[len(f.client.vmStates)-1]; got != firecracker.VMStateResumed {
		t.Fatalf("last VM state after failed Stop = %q, want Resumed rollback", got)
	}
}
