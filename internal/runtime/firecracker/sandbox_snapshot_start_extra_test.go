package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStartFromSandboxSnapshot_ExtraCoverage(t *testing.T) {
	d := &Driver{
		cfg: Config{
			RunDir:               t.TempDir(),
			SnapshotVerifyOnLoad: true,
		},
	}
	d.pool = newFakePool()
	d.tapHost = &fakeTapHost{}
	d.vsockDial = newFakeVsockDialer()
	base, _ := d.sandboxSnapshotBase()
	os.MkdirAll(base, 0755)

	sbID := "test-start-errs"
	dir, memPath, statePath, rootfsPath, overlayPath, manifestPath := d.sandboxSnapshotPaths(sbID)
	os.MkdirAll(dir, 0755)

	// Manifest missing
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "read sandbox snapshot manifest") {
		t.Errorf("expected manifest missing error, got %v", err)
	}

	manifest := sandboxSnapshotManifest{
		Version:          1,
		SandboxID:        sbID,
		VsockCID:         3,
		SnapshotChecksum: formatSnapshotChecksum("bad", "bad"),
		HasOverlay:       true,
		CreatedAt:        time.Now(),
	}
	b, _ := json.Marshal(manifest)
	os.WriteFile(manifestPath, b, 0644)

	// Verify fail (missing mem/state)
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "snapshot integrity") {
		t.Errorf("expected verify fail error, got %v", err)
	}

	// Fix checksum
	os.WriteFile(memPath, []byte("mem"), 0644)
	os.WriteFile(statePath, []byte("state"), 0644)
	memD, _, _ := hashFile(memPath)
	stateD, _, _ := hashFile(statePath)
	manifest.SnapshotChecksum = formatSnapshotChecksum(memD, stateD)
	b, _ = json.Marshal(manifest)
	os.WriteFile(manifestPath, b, 0644)

	// Rootfs missing
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "snapshot rootfs missing") {
		t.Errorf("expected rootfs missing error, got %v", err)
	}

	os.WriteFile(rootfsPath, []byte("rootfs"), 0644)

	// Overlay missing
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "snapshot overlay missing") {
		t.Errorf("expected overlay missing error, got %v", err)
	}

	os.WriteFile(overlayPath, []byte("overlay"), 0644)

	// Tap slot missing (fakePool doesn't have it allocated)
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap slot missing") {
		t.Errorf("expected tap slot missing error, got %v", err)
	}

	// Allocate tap slot
	d.pool.Allocate(context.Background(), sbID, time.Now())

	// Spawn fail
	d.SetSpawner(func(cfg Config, sandboxID string) (VMMHandle, error) {
		return nil, errors.New("spawn error")
	})
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "spawn error") {
		t.Errorf("expected spawn error, got %v", err)
	}

	// Tap host ensure fail
	d.SetSpawner(func(cfg Config, sandboxID string) (VMMHandle, error) {
		return &warmDestroyHandle{spawned: &fakeSpawnedHandle{}, runDir: t.TempDir()}, nil
	})
	fakeTap := &fakeTapHost{ensureErr: errors.New("ensure error")}
	d.tapHost = fakeTap

	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Errorf("expected tap ensure error, got %v", err)
	}

	// Patch VM Resumed fail
	fakeTap.ensureErr = nil
	client := newFakeClient()
	client.patchVMErr = errors.New("resume error")
	d.SetClientFactory(func(socketPath string) VMMClient {
		return client
	})
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "patch VM Resumed") {
		t.Errorf("expected patch VM Resumed error, got %v", err)
	}
}

func TestStopToSandboxSnapshot_ExtraCoverage(t *testing.T) {
	d := &Driver{
		cfg:      Config{RunDir: t.TempDir()},
		clients:  make(map[string]VMMClient),
		vmms:     make(map[string]VMMHandle),
		guestCID: make(map[string]uint32),
	}
	d.pool = newFakePool()
	d.tapHost = &fakeTapHost{}
	d.vsockDial = newFakeVsockDialer()

	sbID := "test-stop-errs"
	client := newFakeClient()
	handle := &warmDestroyHandle{runDir: t.TempDir()}

	d.clients[sbID] = client
	d.vmms[sbID] = handle
	d.guestCID[sbID] = 3

	// Tap slot missing
	if err := d.stopToSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "tap slot missing") {
		t.Errorf("expected tap slot missing error, got %v", err)
	}

	d.pool.Allocate(context.Background(), sbID, time.Now())

	// Patch VM Paused fail
	client.patchVMErr = errors.New("pause error")
	if err := d.stopToSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "patch VM Paused") {
		t.Errorf("expected patch VM Paused error, got %v", err)
	}

	// writeSandboxSnapshot fail (CreateSnapshot error)
	client.patchVMErr = nil
	client.snapshotCreateErr = errors.New("snapshot create error")
	if err := d.stopToSandboxSnapshot(context.Background(), sbID); err == nil || !strings.Contains(err.Error(), "CreateSnapshot") {
		t.Errorf("expected snapshot create error, got %v", err)
	}
}
