package firecracker

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWarmHandle_ShutdownWarnPaths(t *testing.T) {
	base := &stubWarmBaseHandle{}
	driver := New(Config{}, slog.Default())
	driver.SetPool(newFakePool())
	driver.tapHost = &fakeTapHost{removeErr: os.ErrPermission}
	pool := &fakeWarmPool{}
	driver.SetWarmPool(pool)
	pool.releaseErr = os.ErrPermission

	wh := &warmHandle{
		driver:  driver,
		handle:  base,
		slotID:  "slot-warn",
		tapName: "tap-warn",
	}
	wh.setTapOwner("sb-warn")
	if err := wh.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestWarmSpawn_ValidationAndRollbackWarns(t *testing.T) {
	d := New(Config{}, nil)
	if _, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{}); err == nil {
		t.Fatal("expected validation error")
	}

	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = ""
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{SlotID: "slot-1", RootfsPath: "r", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 3}); err == nil {
		t.Fatal("expected missing kernel error")
	}

	f.driver.cfg.KernelImage = f.kernel
	f.pool.nextErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-bad", RootfsPath: "r", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 3,
	}); err == nil {
		t.Fatal("expected tap allocate error")
	}
}

func TestWarmSpawn_TapEnsureFailureReleasesSlot(t *testing.T) {
	f := newDriverFixture(t)
	f.tapHost.ensureErr = os.ErrPermission
	tplDir := t.TempDir()
	mem, state, sum := writeVerifyCacheFiles(t, tplDir, "m", "s")
	rootfs := writeTemplateRootfs(t, tplDir)
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-tap-err", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state,
		SnapshotChecksum: sum, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Fatalf("tap ensure: got %v", err)
	}
}

func TestWarmSpawn_OverlayAndFailurePaths(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	mem, state, sum := writeVerifyCacheFiles(t, tplDir, "m", "s")
	rootfs := writeTemplateRootfs(t, tplDir)
	f.driver.cfg.SnapshotVerifyOnLoad = true
	notifier := &recordingHealthNotifier{}
	f.driver.SetTemplateHealthNotifier(notifier)
	f.driver.snapshotVerifier = func(_, _, _ string) error { return models.ErrSnapshotCorrupt }
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-corrupt", TemplateID: "tpl-bad",
		RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, SnapshotChecksum: sum, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "snapshot integrity") {
		t.Fatalf("corrupt verify: got %v", err)
	}
	if notifier.called.Load() != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.called.Load())
	}

	f.driver.snapshotVerifier = nil
	f.vmm.startErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-start", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "vmm start") {
		t.Fatalf("start error: got %v", err)
	}

	f.vmm.startErr = nil
	f.vmm.waitErr = os.ErrDeadlineExceeded
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-wait", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 11,
	}); err == nil || !strings.Contains(err.Error(), "wait api socket") {
		t.Fatalf("wait error: got %v", err)
	}

	f.vmm.waitErr = nil
	f.client.snapshotLoadErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-load", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 12, HasOverlay: true,
	}); err == nil || !strings.Contains(err.Error(), "LoadSnapshot") {
		t.Fatalf("load error: got %v", err)
	}
}

func TestWarmSpawn_TapRemoveOnErrorWarn(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	mem, state, _ := writeVerifyCacheFiles(t, tplDir, "m", "s")
	rootfs := writeTemplateRootfs(t, tplDir)
	f.tapHost.removeErr = os.ErrPermission
	f.vmm.startErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-tap-rm", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 20,
	}); err == nil {
		t.Fatal("expected start failure")
	}
}

func TestWarmSpawn_MissingPoolAndTapHost(t *testing.T) {
	d := New(Config{KernelImage: "/k"}, nil)
	req := WarmSpawnRequest{SlotID: "slot-miss", RootfsPath: "r", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 10}
	if _, err := d.WarmSpawn(context.Background(), req); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Fatalf("missing pool: got %v", err)
	}
	d.SetPool(newFakePool())
	if _, err := d.WarmSpawn(context.Background(), req); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Fatalf("missing tap host: got %v", err)
	}
}

func TestWarmSpawn_SpawnFailureCleansUp(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	mem, state, _ := writeVerifyCacheFiles(t, tplDir, "m", "s")
	rootfs := writeTemplateRootfs(t, tplDir)
	f.driver.SetSpawner(func(Config, string) (VMMHandle, error) {
		return nil, os.ErrPermission
	})
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-spawn-fail", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "spawn handle") {
		t.Fatalf("spawn fail: got %v", err)
	}
	if f.pool.release != 1 || f.tapHost.removeCalls != 1 {
		t.Fatalf("cleanup release/remove = %d/%d, want 1/1", f.pool.release, f.tapHost.removeCalls)
	}
}

func TestWarmHandle_ShutdownTapAndPoolWarn(t *testing.T) {
	base := &stubWarmBaseHandle{}
	driver := New(Config{}, nil)
	pool := newFakePool()
	pool.relErr = os.ErrPermission
	driver.SetPool(pool)
	driver.SetTapHost(&fakeTapHost{removeErr: os.ErrPermission})
	wh := &warmHandle{
		driver:  driver,
		handle:  base,
		slotID:  "slot-warn2",
		tapName: "tap-warn2",
	}
	wh.setTapOwner("slot-warn2")
	if err := wh.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestWarmSpawn_TapEnsureFailurePoolReleaseWarn(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	mem, state, _ := writeVerifyCacheFiles(t, tplDir, "m", "s")
	rootfs := writeTemplateRootfs(t, tplDir)
	f.tapHost.ensureErr = os.ErrPermission
	f.pool.relErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-rel-warn", RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 21,
	}); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Fatalf("tap ensure: got %v", err)
	}
}
