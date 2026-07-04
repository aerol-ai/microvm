package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakePoolGetErr struct {
	err error
}

func (p *fakePoolGetErr) Allocate(ctx context.Context, sandboxID string, now time.Time) (*TapSlot, error) {
	return nil, p.err
}
func (p *fakePoolGetErr) Transfer(ctx context.Context, fromID, toID string, now time.Time) (*TapSlot, error) {
	return nil, p.err
}
func (p *fakePoolGetErr) Release(ctx context.Context, sandboxID string) error {
	return p.err
}
func (p *fakePoolGetErr) Get(ctx context.Context, sandboxID string) (*TapSlot, error) {
	return nil, p.err
}

func TestStartFromSandboxSnapshot_ExtraErrors(t *testing.T) {
	d := &Driver{
		cfg: Config{RunDir: t.TempDir()},
	}

	sbID := "sb-errs"
	manifestDir, memPath, statePath, rootfsPath, overlayPath, manifestPath := d.sandboxSnapshotPaths(sbID)
	os.MkdirAll(manifestDir, 0755)

	// validateSandboxID fails
	if _, err := d.startFromSandboxSnapshot(context.Background(), "bad/id"); err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("expected invalid character error, got %v", err)
	}

	// pool nil
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected pool not registered error, got %v", err)
	}
	d.pool = newFakePool()

	// tapHost nil
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected tap host not registered error, got %v", err)
	}
	d.tapHost = &fakeTapHost{}

	// vsockDial nil
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "vsock dialer not registered") {
		t.Errorf("expected vsock dialer not registered error, got %v", err)
	}
	d.vsockDial = newFakeVsockDialer()

	// VMM already running but pool Get fails
	d.vmms = map[string]VMMHandle{sbID: &warmDestroyHandle{}}
	d.pool = &fakePoolGetErr{err: os.ErrPermission}
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap lookup") {
		t.Errorf("expected tap lookup error, got %v", err)
	}
	d.pool = newFakePool()

	// VMM already running but no slot
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "no tap slot") {
		t.Errorf("expected no tap slot error, got %v", err)
	}

	// Remove from vmms
	delete(d.vmms, sbID)

	// Manifest missing
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("expected manifest missing error, got %v", err)
	}

	// Write valid manifest
	os.WriteFile(manifestPath, []byte(`{"version":1,"sandbox_id":"sb-errs","has_overlay":true,"vsock_cid":3}`), 0644)

	// rootfs missing
	raw, _ := os.ReadFile(manifestPath)
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "snapshot rootfs missing") {
		t.Errorf("raw manifest: %q\nexpected rootfs missing error, got %v", string(raw), err)
	}
	os.WriteFile(rootfsPath, []byte("rootfs"), 0644)

	// overlay missing
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "snapshot overlay missing") {
		t.Errorf("expected overlay missing error, got %v", err)
	}
	os.WriteFile(overlayPath, []byte("overlay"), 0644)

	// tap lookup fails
	d.pool = &fakePoolGetErr{err: os.ErrPermission}
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap lookup") {
		t.Errorf("expected tap lookup error, got %v", err)
	}

	// tap slot missing
	d.pool = newFakePool()
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap slot missing") {
		t.Errorf("expected tap slot missing error, got %v", err)
	}

	// allocate slot so Get succeeds
	d.pool.Allocate(context.Background(), sbID, time.Now())

	// spawn fails
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return nil, os.ErrPermission
	})
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "spawn handle") {
		t.Errorf("expected spawn handle error, got %v", err)
	}

	// Handle setup for copy errors
	runDir := filepath.Join(t.TempDir(), "run")
	os.MkdirAll(runDir, 0755)
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: runDir}, nil
	})

	// copy rootfs fails -> we can't easily mock copyFile directly, but we can make the destination unwriteable
	os.MkdirAll(filepath.Join(runDir, rootfsFileName), 0755) // make dst a directory
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "stage rootfs") {
		t.Errorf("expected stage rootfs error, got %v", err)
	}
	os.RemoveAll(filepath.Join(runDir, rootfsFileName))

	// copy overlay fails
	os.MkdirAll(filepath.Join(runDir, overlayFileName), 0755)
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "stage overlay") {
		t.Errorf("expected stage overlay error, got %v", err)
	}
	os.RemoveAll(filepath.Join(runDir, overlayFileName))

	// tapHost Ensure fails
	fakeTap := &fakeTapHost{ensureErr: os.ErrPermission}
	d.tapHost = fakeTap
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Errorf("expected tap host ensure error, got %v", err)
	}
	d.tapHost = &fakeTapHost{}

	// handle Start fails
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		h := &fakeVMM{runDir: runDir, startErr: os.ErrPermission}
		return h, nil
	})
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "vmm start") {
		t.Errorf("expected vmm start error, got %v", err)
	}

	// handle WaitSocket fails
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		h := &fakeVMM{runDir: runDir, waitErr: os.ErrPermission}
		return h, nil
	})
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "wait api socket") {
		t.Errorf("expected wait api socket error, got %v", err)
	}

	// configureSandboxSnapshotRestore fails
	client := newFakeClient()
	client.snapshotLoadErr = os.ErrPermission
	d.SetClientFactory(func(_ string) VMMClient { return client })
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &fakeVMM{runDir: runDir}, nil
	})
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "LoadSnapshot") {
		t.Errorf("expected LoadSnapshot error, got %v", err)
	}

	// Patch VM Resumed fails
	client = newFakeClient()
	client.patchVMErr = os.ErrPermission
	d.SetClientFactory(func(_ string) VMMClient { return client })
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "patch VM Resumed") {
		t.Errorf("expected patch VM Resumed error, got %v", err)
	}

	// vsockHandshake fails
	client = newFakeClient()
	d.SetClientFactory(func(_ string) VMMClient { return client })
	fakeVsock := newFakeVsockDialer()
	fakeVsock.err = os.ErrPermission
	d.vsockDial = fakeVsock
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "vsock handshake") {
		t.Errorf("expected vsock handshake error, got %v", err)
	}

	_ = memPath
	_ = statePath
}
