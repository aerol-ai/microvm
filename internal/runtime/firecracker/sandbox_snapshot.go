package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	sandboxSnapshotsDirName        = "_sandboxes"
	sandboxSnapshotManifestName    = "manifest.json"
	sandboxSnapshotMemoryFileName  = "snapshot.memory"
	sandboxSnapshotStateFileName   = "snapshot.state"
	sandboxSnapshotRootfsFileName  = rootfsFileName
	sandboxSnapshotOverlayFileName = overlayFileName
)

type sandboxSnapshotManifest struct {
	Version          int       `json:"version"`
	SandboxID        string    `json:"sandbox_id"`
	VsockCID         uint32    `json:"vsock_cid"`
	SnapshotChecksum string    `json:"snapshot_checksum"`
	HasOverlay       bool      `json:"has_overlay"`
	CreatedAt        time.Time `json:"created_at"`
}

func (d *Driver) sandboxSnapshotDir(sandboxID string) string {
	base := strings.TrimSpace(d.cfg.TemplatesDir)
	if base == "" {
		base = strings.TrimSpace(d.cfg.RunDir)
	}
	return filepath.Join(base, sandboxSnapshotsDirName, sandboxID)
}

func (d *Driver) sandboxSnapshotBase() (string, error) {
	base := strings.TrimSpace(d.cfg.TemplatesDir)
	if base == "" {
		base = strings.TrimSpace(d.cfg.RunDir)
	}
	if base == "" {
		return "", fmt.Errorf("firecracker runtime: TemplatesDir or RunDir must be configured for sandbox snapshots: %w",
			models.ErrRuntimeNotImplemented)
	}
	return filepath.Join(base, sandboxSnapshotsDirName), nil
}

func (d *Driver) sandboxSnapshotPaths(sandboxID string) (dir, memPath, statePath, rootfsPath, overlayPath, manifestPath string) {
	dir = d.sandboxSnapshotDir(sandboxID)
	memPath = filepath.Join(dir, sandboxSnapshotMemoryFileName)
	statePath = filepath.Join(dir, sandboxSnapshotStateFileName)
	rootfsPath = filepath.Join(dir, sandboxSnapshotRootfsFileName)
	overlayPath = filepath.Join(dir, sandboxSnapshotOverlayFileName)
	manifestPath = filepath.Join(dir, sandboxSnapshotManifestName)
	return dir, memPath, statePath, rootfsPath, overlayPath, manifestPath
}

func (d *Driver) readSandboxSnapshotManifest(sandboxID string) (*sandboxSnapshotManifest, error) {
	dir, _, _, _, _, manifestPath := d.sandboxSnapshotPaths(sandboxID)
	raw, err := os.ReadFile(manifestPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		oldDir := dir + ".old"
		oldManifest := filepath.Join(oldDir, sandboxSnapshotManifestName)
		if _, statErr := os.Stat(oldManifest); statErr == nil {
			if _, finalErr := os.Stat(dir); errors.Is(finalErr, os.ErrNotExist) {
				_ = os.Rename(oldDir, dir)
			}
			raw, err = os.ReadFile(manifestPath)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read sandbox snapshot manifest: %w", err)
	}
	var manifest sandboxSnapshotManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode sandbox snapshot manifest: %w", err)
	}
	if manifest.Version != 1 {
		return nil, fmt.Errorf("sandbox snapshot manifest version=%d is unsupported", manifest.Version)
	}
	if manifest.SandboxID != sandboxID {
		return nil, fmt.Errorf("sandbox snapshot manifest belongs to %q, want %q", manifest.SandboxID, sandboxID)
	}
	if manifest.VsockCID < 3 {
		return nil, fmt.Errorf("sandbox snapshot manifest has reserved vsock CID %d", manifest.VsockCID)
	}
	return &manifest, nil
}

func (d *Driver) stopToSandboxSnapshot(ctx context.Context, sandboxID string) error {
	if err := validateSandboxID(sandboxID); err != nil {
		return fmt.Errorf("firecracker runtime: stop: %w", err)
	}
	if _, err := d.sandboxSnapshotBase(); err != nil {
		return err
	}
	if d.pool == nil {
		return fmt.Errorf("firecracker runtime: stop: TAP pool not registered (main.go must call SetPool): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.tapHost == nil {
		return fmt.Errorf("firecracker runtime: stop: TAP host manager not registered (main.go must call SetTapHost): %w",
			models.ErrRuntimeNotImplemented)
	}

	d.mu.Lock()
	client, hasClient := d.clients[sandboxID]
	handle, hasHandle := d.vmms[sandboxID]
	guestCID := d.guestCID[sandboxID]
	d.mu.Unlock()
	if !hasClient || !hasHandle {
		if _, err := d.readSandboxSnapshotManifest(sandboxID); err == nil {
			return nil
		}
		return fmt.Errorf("firecracker runtime: stop %s: VMM is not registered and no stopped snapshot exists", sandboxID)
	}

	slot, err := d.pool.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: tap lookup: %w", sandboxID, err)
	}
	if slot == nil {
		return fmt.Errorf("firecracker runtime: stop %s: tap slot missing; refusing to create an unrestorable snapshot", sandboxID)
	}
	if guestCID < 3 {
		guestCID = slot.VsockCID
	}

	if err := d.sendVsockOp(ctx, filepath.Join(handle.RunDir(), hostVsockUDSName), guestCID, "pre_snapshot", nil); err != nil {
		d.logger.Warn("firecracker stop: pre_snapshot send failed (continuing)",
			"sandbox_id", sandboxID, "error", err)
	}

	paused := false
	vmmStopped := false
	if err := client.PatchVM(ctx, firecracker.VM{State: firecracker.VMStatePaused}); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: patch VM Paused: %w", sandboxID, err)
	}
	paused = true
	defer func() {
		if paused && !vmmStopped {
			if err := client.PatchVM(context.Background(), firecracker.VM{State: firecracker.VMStateResumed}); err != nil {
				d.logger.Warn("firecracker stop: resume after failed snapshot failed",
					"sandbox_id", sandboxID, "error", err)
			}
		}
	}()

	if err := d.writeSandboxSnapshot(ctx, sandboxID, handle, client, guestCID); err != nil {
		return err
	}
	if err := handle.Shutdown(ctx, 3*time.Second); err != nil {
		d.logger.Warn("firecracker stop: shutdown after snapshot failed",
			"sandbox_id", sandboxID, "error", err)
		if killErr := handle.Kill(); killErr != nil {
			return fmt.Errorf("firecracker runtime: stop %s: shutdown failed: %w; kill failed: %v", sandboxID, err, killErr)
		}
	}
	vmmStopped = true

	d.mu.Lock()
	delete(d.clients, sandboxID)
	delete(d.vmms, sandboxID)
	delete(d.guestCID, sandboxID)
	d.mu.Unlock()
	d.rssUnregister(sandboxID)

	if err := d.tapHost.Remove(ctx, slot.TapName); err != nil {
		d.logger.Warn("firecracker stop: tap remove failed",
			"sandbox_id", sandboxID, "tap", slot.TapName, "error", err)
	}
	if err := handle.Cleanup(); err != nil {
		d.logger.Warn("firecracker stop: vmm cleanup failed",
			"sandbox_id", sandboxID, "error", err)
	}
	return nil
}

func (d *Driver) writeSandboxSnapshot(ctx context.Context, sandboxID string, handle VMMHandle, client VMMClient, guestCID uint32) error {
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: create snapshot base: %w", sandboxID, err)
	}

	finalDir, _, _, _, _, _ := d.sandboxSnapshotPaths(sandboxID)
	tmpDir := finalDir + ".tmp"
	oldDir := finalDir + ".old"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: remove stale tmp snapshot: %w", sandboxID, err)
	}
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: create tmp snapshot dir: %w", sandboxID, err)
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	tmpMem := filepath.Join(tmpDir, sandboxSnapshotMemoryFileName)
	tmpState := filepath.Join(tmpDir, sandboxSnapshotStateFileName)
	if err := d.createSnapshotArtifacts(ctx, client, handle.RunDir(), tmpMem, tmpState); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: %w", sandboxID, err)
	}

	srcRootfs := filepath.Join(handle.RunDir(), rootfsFileName)
	tmpRootfs := filepath.Join(tmpDir, sandboxSnapshotRootfsFileName)
	if err := copyFile(srcRootfs, tmpRootfs); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: copy rootfs: %w", sandboxID, err)
	}

	hasOverlay := false
	srcOverlay := filepath.Join(handle.RunDir(), overlayFileName)
	tmpOverlay := filepath.Join(tmpDir, sandboxSnapshotOverlayFileName)
	if _, err := os.Stat(srcOverlay); err == nil {
		hasOverlay = true
		if err := copyFile(srcOverlay, tmpOverlay); err != nil {
			return fmt.Errorf("firecracker runtime: stop %s: copy overlay: %w", sandboxID, err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("firecracker runtime: stop %s: stat overlay: %w", sandboxID, err)
	}

	memDigest, _, err := hashFile(tmpMem)
	if err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: hash memory: %w", sandboxID, err)
	}
	stateDigest, _, err := hashFile(tmpState)
	if err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: hash state: %w", sandboxID, err)
	}
	manifest := sandboxSnapshotManifest{
		Version:          1,
		SandboxID:        sandboxID,
		VsockCID:         guestCID,
		SnapshotChecksum: formatSnapshotChecksum(memDigest, stateDigest),
		HasOverlay:       hasOverlay,
		CreatedAt:        time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: marshal manifest: %w", sandboxID, err)
	}
	tmpManifest := filepath.Join(tmpDir, sandboxSnapshotManifestName)
	if err := os.WriteFile(tmpManifest, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: write manifest: %w", sandboxID, err)
	}
	syncPaths := []string{tmpMem, tmpState, tmpRootfs, tmpManifest}
	if hasOverlay {
		syncPaths = append(syncPaths, tmpOverlay)
	}
	for _, path := range syncPaths {
		if err := syncFile(path); err != nil {
			return fmt.Errorf("firecracker runtime: stop %s: sync %s: %w", sandboxID, path, err)
		}
	}
	syncDir(tmpDir)

	if err := os.RemoveAll(oldDir); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: remove old backup snapshot: %w", sandboxID, err)
	}
	if _, err := os.Stat(finalDir); err == nil {
		if err := os.Rename(finalDir, oldDir); err != nil {
			return fmt.Errorf("firecracker runtime: stop %s: rotate previous snapshot: %w", sandboxID, err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("firecracker runtime: stop %s: stat previous snapshot: %w", sandboxID, err)
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		if _, statErr := os.Stat(oldDir); statErr == nil {
			_ = os.Rename(oldDir, finalDir)
		}
		return fmt.Errorf("firecracker runtime: stop %s: promote snapshot: %w", sandboxID, err)
	}
	cleanupTmp = false
	syncDir(base)
	if err := os.RemoveAll(oldDir); err != nil {
		d.logger.Warn("firecracker stop: remove previous snapshot backup failed",
			"sandbox_id", sandboxID, "error", err)
	}
	return nil
}

func (d *Driver) startFromSandboxSnapshot(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	if err := validateSandboxID(sandboxID); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start: %w", err)
	}
	if d.pool == nil {
		return nil, fmt.Errorf("firecracker runtime: start: TAP pool not registered (main.go must call SetPool): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.tapHost == nil {
		return nil, fmt.Errorf("firecracker runtime: start: TAP host manager not registered (main.go must call SetTapHost): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.vsockDial == nil {
		return nil, fmt.Errorf("firecracker runtime: start: vsock dialer not registered (main.go must call SetVsockDialer): %w",
			models.ErrRuntimeNotImplemented)
	}
	d.mu.Lock()
	if handle, ok := d.vmms[sandboxID]; ok {
		d.mu.Unlock()
		slot, err := d.pool.Get(ctx, sandboxID)
		if err != nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: tap lookup: %w", sandboxID, err)
		}
		if slot == nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: running VMM has no tap slot", sandboxID)
		}
		return &models.SandboxRuntimeState{
			SandboxID:   sandboxID,
			ContainerID: handle.APISocket(),
			ContainerIP: slot.GuestIP,
			Status:      models.SandboxStatusStarted,
		}, nil
	}
	d.mu.Unlock()

	manifest, err := d.readSandboxSnapshotManifest(sandboxID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: %w", sandboxID, err)
	}
	dir, memPath, statePath, snapshotRootfs, snapshotOverlay, _ := d.sandboxSnapshotPaths(sandboxID)
	if d.cfg.SnapshotVerifyOnLoad && manifest.SnapshotChecksum != "" {
		if err := verifySnapshotChecksum(memPath, statePath, manifest.SnapshotChecksum); err != nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: snapshot integrity: %w", sandboxID, err)
		}
	}
	if _, err := os.Stat(snapshotRootfs); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: snapshot rootfs missing: %w", sandboxID, err)
	}
	if manifest.HasOverlay {
		if _, err := os.Stat(snapshotOverlay); err != nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: snapshot overlay missing: %w", sandboxID, err)
		}
	}

	slot, err := d.pool.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: tap lookup: %w", sandboxID, err)
	}
	if slot == nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: tap slot missing; cannot restore stable network identity", sandboxID)
	}

	handle, err := d.spawn(d.cfg, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: spawn handle: %w", sandboxID, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = handle.Shutdown(context.Background(), 3*time.Second)
		if err := handle.Cleanup(); err != nil {
			d.logger.Warn("firecracker start: vmm cleanup after error failed",
				"sandbox_id", sandboxID, "error", err)
		}
	}()

	if err := os.MkdirAll(handle.RunDir(), 0o755); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: create runDir %s: %w", sandboxID, handle.RunDir(), err)
	}

	rootfsPath := filepath.Join(handle.RunDir(), rootfsFileName)
	if err := copyFile(snapshotRootfs, rootfsPath); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: stage rootfs from %s: %w", sandboxID, dir, err)
	}
	var overlayPath string
	if manifest.HasOverlay {
		overlayPath = filepath.Join(handle.RunDir(), overlayFileName)
		if err := copyFile(snapshotOverlay, overlayPath); err != nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: stage overlay from %s: %w", sandboxID, dir, err)
		}
	}

	if err := d.tapHost.Ensure(ctx, *slot); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: tap host ensure %s: %w", sandboxID, slot.TapName, err)
	}
	tapCommitted := false
	defer func() {
		if tapCommitted {
			return
		}
		if err := d.tapHost.Remove(context.Background(), slot.TapName); err != nil {
			d.logger.Warn("firecracker start: tap remove after error failed",
				"sandbox_id", sandboxID, "tap", slot.TapName, "error", err)
		}
	}()

	if err := handle.Start(ctx); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: vmm start: %w", sandboxID, err)
	}
	if err := handle.WaitSocket(ctx, 5*time.Second); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: wait api socket: %w (stderr: %s)",
			sandboxID, err, handle.StderrTail())
	}
	client := d.newClient(handle.APISocket())
	if err := d.configureSandboxSnapshotRestore(ctx, client, manifest, memPath, statePath, rootfsPath, slot, overlayPath); err != nil {
		return nil, err
	}
	if err := client.PatchVM(ctx, firecracker.VM{State: firecracker.VMStateResumed}); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: patch VM Resumed: %w", sandboxID, err)
	}
	vsockPath := filepath.Join(handle.RunDir(), hostVsockUDSName)
	if err := d.vsockHandshake(ctx, vsockPath, manifest.VsockCID); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: vsock handshake: %w", sandboxID, err)
	}
	d.logger.Info("firecracker start: vsock handshake complete",
		"sandbox_id", sandboxID,
		"vsock_cid", manifest.VsockCID,
		"guest_ip", slot.GuestIP,
		"tap", slot.TapName)
	postCtx, cancel := context.WithTimeout(ctx, d.cfg.PostResumeTimeout)
	if err := d.sendVsockOp(postCtx, vsockPath, manifest.VsockCID, "post_resume", postResumeData(slot)); err != nil {
		d.logger.Warn("firecracker start: post_resume send failed (continuing)",
			"sandbox_id", sandboxID, "error", err)
	} else {
		d.logger.Info("firecracker start: post_resume acked",
			"sandbox_id", sandboxID,
			"vsock_cid", manifest.VsockCID,
			"guest_ip", slot.GuestIP,
			"gateway_ip", slot.HostIP,
			"tap", slot.TapName)
	}
	cancel()
	d.probeToolboxTCP(ctx, "start", sandboxID, slot, true)

	d.mu.Lock()
	d.clients[sandboxID] = client
	d.vmms[sandboxID] = handle
	d.guestCID[sandboxID] = manifest.VsockCID
	d.mu.Unlock()
	d.rssRegister(sandboxID, handle.Pid())

	tapCommitted = true
	committed = true
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: handle.APISocket(),
		ContainerIP: slot.GuestIP,
		Status:      models.SandboxStatusStarted,
	}, nil
}

func (d *Driver) configureSandboxSnapshotRestore(ctx context.Context, client VMMClient, manifest *sandboxSnapshotManifest, memPath, statePath, rootfsPath string, slot *TapSlot, overlayPath string) error {
	runDir := filepath.Dir(rootfsPath)
	snapshotMemoryPath, snapshotStatePath, err := d.stageSnapshotLoadPaths(runDir, memPath, statePath)
	if err != nil {
		return fmt.Errorf("firecracker runtime: stage snapshot load artifacts: %w", err)
	}
	if err := client.LoadSnapshot(ctx, firecracker.SnapshotLoad{
		SnapshotPath: snapshotStatePath,
		MemBackend: &firecracker.MemoryBackend{
			BackendType: "File",
			BackendPath: snapshotMemoryPath,
		},
		EnableDiffSnapshots: true,
		ResumeVM:            false,
	}); err != nil {
		return fmt.Errorf("firecracker runtime: LoadSnapshot: %w", err)
	}
	rootfsAPIPath, err := d.chrootFilePath(runDir, rootfsPath, rootfsFileName)
	if err != nil {
		return fmt.Errorf("firecracker runtime: stage snapshot rootfs: %w", err)
	}
	if err := client.PatchDrive(ctx, rootDriveID, firecracker.DrivePatch{
		DriveID:    rootDriveID,
		PathOnHost: rootfsAPIPath,
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PatchDrive rootfs: %w", err)
	}
	if manifest.HasOverlay {
		overlayAPIPath, err := d.chrootFilePath(runDir, overlayPath, overlayFileName)
		if err != nil {
			return fmt.Errorf("firecracker runtime: stage snapshot overlay: %w", err)
		}
		if err := client.PatchDrive(ctx, overlayDriveID, firecracker.DrivePatch{
			DriveID:    overlayDriveID,
			PathOnHost: overlayAPIPath,
		}); err != nil {
			return fmt.Errorf("firecracker runtime: PatchDrive overlay: %w", err)
		}
	}
	if err := client.PatchNetworkInterface(ctx, primaryIfaceID, firecracker.NetworkInterfacePatch{
		IfaceID:     primaryIfaceID,
		HostDevName: slot.TapName,
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PatchNetworkInterface: %w", err)
	}
	return nil
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if info.IsDir() {
		return fmt.Errorf("source %s is a directory", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("sync %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}
