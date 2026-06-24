package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/firecracker"
)

func TestSnapshotTemplate_Errors_Extra(t *testing.T) {
	d := &Driver{
		cfg: Config{
			RunDir:      filepath.Join(t.TempDir(), "run"),
			KernelImage: "vmlinux",
		},
	}
	reqBase := func() TemplateSnapshotRequest {
		return TemplateSnapshotRequest{
			TemplateID:    "tpl",
			RootfsPath:    "/non/existent/file",
			OutMemoryPath: "/tmp/mem",
			OutStatePath:  "/tmp/state",
			GuestCID:      3,
		}
	}

	// Missing pool
	if _, err := d.SnapshotTemplate(context.Background(), reqBase()); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected TAP pool not registered error, got %v", err)
	}

	d.pool = newFakePool()
	// Missing tap host
	if _, err := d.SnapshotTemplate(context.Background(), reqBase()); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected TAP host not registered error, got %v", err)
	}

	d.tapHost = &fakeTapHost{}
	// Missing vsock
	if _, err := d.SnapshotTemplate(context.Background(), reqBase()); err == nil || !strings.Contains(err.Error(), "vsock dialer not registered") {
		t.Errorf("expected vsock dialer not registered error, got %v", err)
	}

	d.vsockDial = newFakeVsockDialer()

	// Tap allocate error
	fakePoolErr := newFakePool()
	fakePoolErr.nextErr = os.ErrPermission
	d.pool = fakePoolErr
	if _, err := d.SnapshotTemplate(context.Background(), reqBase()); err == nil || !strings.Contains(err.Error(), "tap allocate") {
		t.Errorf("expected tap allocate error, got %v", err)
	}

	// Spawn error
	d.pool = newFakePool()
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return nil, os.ErrPermission
	})
	if _, err := d.SnapshotTemplate(context.Background(), reqBase()); err == nil || !strings.Contains(err.Error(), "spawn handle") {
		t.Errorf("expected spawn handle error, got %v", err)
	}

	// Rootfs stage error
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: t.TempDir()}, nil
	})
	reqRootfs := reqBase()
	if _, err := d.SnapshotTemplate(context.Background(), reqRootfs); err == nil || !strings.Contains(err.Error(), "rootfs stage") {
		t.Errorf("expected rootfs stage error, got %v", err)
	}

	rootfsPath := filepath.Join(t.TempDir(), "rootfs")
	os.WriteFile(rootfsPath, []byte("rootfs"), 0644)
	reqValid := reqBase()
	reqValid.RootfsPath = rootfsPath

	// Tap ensure error
	fakeTap := &fakeTapHost{ensureErr: os.ErrPermission}
	d.tapHost = fakeTap
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "tap ensure") {
		t.Errorf("expected tap ensure error, got %v", err)
	}
	d.tapHost = &fakeTapHost{}

	// VMM Start error
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: t.TempDir(), startErr: os.ErrPermission}, nil
	})
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "vmm start") {
		t.Errorf("expected vmm start error, got %v", err)
	}

	// VMM WaitSocket error
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: t.TempDir(), waitErr: os.ErrPermission}, nil
	})
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "wait api socket") {
		t.Errorf("expected wait api socket error, got %v", err)
	}

	// Create client factory
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: t.TempDir()}, nil
	})

	// PutMachineConfig fails
	client := newFakeClient()
	client.machineErr = os.ErrPermission
	d.SetClientFactory(func(_ string) VMMClient { return client })
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "PutMachineConfig") {
		t.Errorf("expected PutMachineConfig error, got %v", err)
	}
	client.machineErr = nil

	// PutBootSource fails
	client.bootErr = os.ErrPermission
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "PutBootSource") {
		t.Errorf("expected PutBootSource error, got %v", err)
	}
	client.bootErr = nil

	// PutDrive root fails
	client.driveErr = os.ErrPermission
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "PutDrive root") {
		t.Errorf("expected PutDrive root error, got %v", err)
	}
	client.driveErr = nil

	// PutNetworkInterface fails
	client.nicErr = os.ErrPermission
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "PutNetworkInterface") {
		t.Errorf("expected PutNetworkInterface error, got %v", err)
	}
	client.nicErr = nil

	// PutVsock fails
	client.vsockErr = os.ErrPermission
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "PutVsock") {
		t.Errorf("expected PutVsock error, got %v", err)
	}
	client.vsockErr = nil

	// InstanceStart fails
	client.actionErr = os.ErrPermission
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "action InstanceStart") {
		t.Errorf("expected action InstanceStart error, got %v", err)
	}
	client.actionErr = nil

	// vsockHandshake fails
	fakeVsock := newFakeVsockDialer()
	fakeVsock.err = os.ErrPermission
	d.vsockDial = fakeVsock
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "vsock handshake") {
		t.Errorf("expected vsock handshake error, got %v", err)
	}
	d.vsockDial = newFakeVsockDialer()

	// CreateSnapshot fails
	client.actionErr = nil // so Pause works

	client.snapshotCreateErr = os.ErrPermission
	if _, err := d.SnapshotTemplate(context.Background(), reqValid); err == nil || !strings.Contains(err.Error(), "CreateSnapshot") {
		t.Errorf("expected CreateSnapshot error, got %v", err)
	}
	client.snapshotCreateErr = nil

	// CreateSnapshot succeeds but Hash fails
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: t.TempDir()}, nil
	})

	clientNoOp := &fakeNoOpClient{fakeClient: newFakeClient()}
	d.SetClientFactory(func(_ string) VMMClient { return clientNoOp })

	reqMem := reqValid
	reqMem.OutMemoryPath = filepath.Join(t.TempDir(), "nonexistent_mem")
	reqMem.OutStatePath = filepath.Join(t.TempDir(), "nonexistent_state")
	if _, err := d.SnapshotTemplate(context.Background(), reqMem); err == nil || !strings.Contains(err.Error(), "hash memory") {
		t.Errorf("expected hash memory error, got %v", err)
	}

	os.WriteFile(reqMem.OutMemoryPath, []byte("mem"), 0644)
	if _, err := d.SnapshotTemplate(context.Background(), reqMem); err == nil || !strings.Contains(err.Error(), "hash state") {
		t.Errorf("expected hash state error, got %v", err)
	}
}

type fakeNoOpClient struct {
	*fakeClient
}

// Override CreateSnapshot to do nothing
func (c *fakeNoOpClient) CreateSnapshot(ctx context.Context, req firecracker.SnapshotCreate) error {
	return nil
}

func TestSendVsockOp_Errors_Extra(t *testing.T) {
	d := &Driver{}
	d.vsockDial = newFakeVsockDialer()

	// Dial fails
	fakeVsock := newFakeVsockDialer()
	fakeVsock.err = os.ErrPermission
	d.vsockDial = fakeVsock
	if err := d.sendVsockOp(context.Background(), "/tmp/vsock.sock", 3, "test", nil); err == nil || !strings.Contains(err.Error(), "dial cid=3") {
		t.Errorf("expected dial error, got %v", err)
	}

	// Unmarshalable data
	if err := d.sendVsockOp(context.Background(), "/tmp/vsock.sock", 3, "test", make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal data") {
		t.Errorf("expected marshal data error, got %v", err)
	}
}
