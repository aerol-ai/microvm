package firecracker

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSnapshotTemplate_Preconditions_Extra(t *testing.T) {
	d := &Driver{}

	// Pool nil
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected pool error, got %v", err)
	}

	d.pool = newFakePool()

	// TapHost nil
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected tap host error, got %v", err)
	}

	d.tapHost = &fakeTapHost{}

	// VsockDial nil
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "vsock dialer not registered") {
		t.Errorf("expected vsock dialer error, got %v", err)
	}

	d.vsockDial = newFakeVsockDialer()

	// KernelImage empty
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "KernelImage not configured") {
		t.Errorf("expected kernel image error, got %v", err)
	}

	d.cfg.KernelImage = "/kernel"

	// TemplateID empty
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "template id is empty") {
		t.Errorf("expected template ID error, got %v", err)
	}

	// Paths missing
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "tpl1",
	}); err == nil || !strings.Contains(err.Error(), "rootfs/out paths are required") {
		t.Errorf("expected paths error, got %v", err)
	}

	// GuestCID < 3
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "tpl1", RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 2,
	}); err == nil || !strings.Contains(err.Error(), "GuestCID=2 is reserved") {
		t.Errorf("expected GuestCID error, got %v", err)
	}

	// Invalid Sandbox ID
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "bad/id", RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 3,
	}); err == nil || !strings.Contains(err.Error(), "invalid character '/'") {
		t.Errorf("expected invalid sandbox ID error, got %v", err)
	}

	// Tap allocate fails
	fakePool := newFakePool()
	fakePool.nextErr = os.ErrPermission
	d.pool = fakePool
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "tpl1", RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 3,
	}); err == nil || !strings.Contains(err.Error(), "tap allocate") {
		t.Errorf("expected tap allocate error, got %v", err)
	}

	// Spawn fails
	d.pool = newFakePool()
	d.cfg.RunDir = "\x00" // invalidate run dir so spawn fails or similar, wait.
	// We can inject a spawner using SetSpawner. Wait, snapshot calls d.spawn().
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return nil, os.ErrPermission
	})
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "tpl1", RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 3,
	}); err == nil || !strings.Contains(err.Error(), "spawn handle") {
		t.Errorf("expected spawn handle error, got %v", err)
	}
}
