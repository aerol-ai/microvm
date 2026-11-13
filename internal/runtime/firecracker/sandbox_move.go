package firecracker

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Moving a stopped sandbox to another worker with its memory (plans/
// kubernetes-v2-architecture.md §10.5, "Firecracker snapshot moves"). Stop
// already writes the VM's memory and state, its root disk and its overlay
// into the sandbox's snapshot folder; Start restores them. A move carries
// that folder: the source exports it, the target imports it under its own
// snapshot folder and gives the sandbox a network slot of its own, and
// Start restores the VM there exactly as it would here. After the resume
// the guest takes the new slot's address (post_resume), as a VM from the
// warm pool does; its vsock CID and MAC stay the snapshot's, which the
// point-to-point TAP link lets two VMs share, as warm-pool clones of one
// template do.

// errSandboxRunning: a running VM's snapshot folder is not a whole snapshot.
var errSandboxRunning = errors.New("the sandbox is running: stop it before moving it")

// sandboxMoveFiles lists a snapshot folder's files in the order a move
// sends them: the manifest first, so the target checks it before it reads
// gigabytes.
func sandboxMoveFiles(m *sandboxSnapshotManifest) []string {
	files := []string{sandboxSnapshotManifestName, sandboxSnapshotStateFileName, sandboxSnapshotMemoryFileName, sandboxSnapshotRootfsFileName}
	if m.HasOverlay {
		files = append(files, sandboxSnapshotOverlayFileName)
	}
	return files
}

// ExportSandboxSnapshot writes a stopped sandbox's snapshot to w as a tar
// stream, for ImportSandboxSnapshot on another worker.
func (d *Driver) ExportSandboxSnapshot(ctx context.Context, sandboxID string, w io.Writer) error {
	if err := validateSandboxID(sandboxID); err != nil {
		return fmt.Errorf("firecracker runtime: export %s: %w", sandboxID, err)
	}
	d.mu.Lock()
	_, running := d.vmms[sandboxID]
	d.mu.Unlock()
	if running {
		return fmt.Errorf("firecracker runtime: export %s: %w", sandboxID, errSandboxRunning)
	}
	manifest, err := d.readSandboxSnapshotManifest(sandboxID)
	if err != nil {
		return fmt.Errorf("firecracker runtime: export %s: %w", sandboxID, err)
	}
	dir := d.sandboxSnapshotDir(sandboxID)
	tw := tar.NewWriter(w)
	for _, name := range sandboxMoveFiles(manifest) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tarFile(tw, filepath.Join(dir, name), name); err != nil {
			return fmt.Errorf("firecracker runtime: export %s: %w", sandboxID, err)
		}
	}
	return tw.Close()
}

func tarFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), Typeflag: tar.TypeReg, ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// ImportSandboxSnapshot installs, under this worker's snapshot folder, a
// snapshot another worker exported, and gives the sandbox a network slot
// here, so StartWithIdentity restores it. It checks the manifest names the
// sandbox and the memory and state match their checksum before anything is
// in place; a failed import leaves nothing behind. A sandbox running here is
// refused.
func (d *Driver) ImportSandboxSnapshot(ctx context.Context, sandboxID string, r io.Reader) error {
	if err := validateSandboxID(sandboxID); err != nil {
		return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
	}
	if d.pool == nil {
		return fmt.Errorf("firecracker runtime: import %s: TAP pool not registered: %w", sandboxID, models.ErrRuntimeNotImplemented)
	}
	d.mu.Lock()
	_, running := d.vmms[sandboxID]
	d.mu.Unlock()
	if running {
		return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, errSandboxRunning)
	}
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(base, "."+sandboxID+".import-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()

	var manifest *sandboxSnapshotManifest
	got := map[string]bool{}
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
		}
		if manifest == nil && h.Name != sandboxSnapshotManifestName {
			return fmt.Errorf("firecracker runtime: import %s: the manifest must come first, got %q", sandboxID, h.Name)
		}
		if err := checkMoveEntry(h, manifest, got); err != nil {
			return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
		}
		if err := writeMoveEntry(filepath.Join(staging, h.Name), tr); err != nil {
			return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
		}
		got[h.Name] = true
		if h.Name == sandboxSnapshotManifestName {
			if manifest, err = readMoveManifest(filepath.Join(staging, h.Name), sandboxID); err != nil {
				return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
			}
		}
	}
	if manifest == nil {
		return fmt.Errorf("firecracker runtime: import %s: no manifest", sandboxID)
	}
	for _, name := range sandboxMoveFiles(manifest) {
		if !got[name] {
			return fmt.Errorf("firecracker runtime: import %s: %s missing", sandboxID, name)
		}
	}
	if manifest.SnapshotChecksum != "" {
		if err := verifySnapshotChecksum(filepath.Join(staging, sandboxSnapshotMemoryFileName),
			filepath.Join(staging, sandboxSnapshotStateFileName), manifest.SnapshotChecksum); err != nil {
			return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
		}
	}

	// In place: what an earlier, unfinished import of this sandbox left goes.
	final := d.sandboxSnapshotDir(sandboxID)
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		return err
	}
	if slot, err := d.pool.Get(ctx, sandboxID); err == nil && slot != nil {
		return nil
	}
	if _, err := d.pool.Allocate(ctx, sandboxID, time.Now()); err != nil {
		_ = os.RemoveAll(final)
		return fmt.Errorf("firecracker runtime: import %s: tap allocate: %w", sandboxID, err)
	}
	return nil
}

// checkMoveEntry refuses an entry a move never sends: a name outside the
// snapshot's files, a second copy, a link, a device.
func checkMoveEntry(h *tar.Header, manifest *sandboxSnapshotManifest, got map[string]bool) error {
	if h.Typeflag != tar.TypeReg {
		return fmt.Errorf("%q is not a regular file", h.Name)
	}
	if got[h.Name] {
		return fmt.Errorf("%q sent twice", h.Name)
	}
	allowed := []string{sandboxSnapshotManifestName}
	if manifest != nil {
		allowed = sandboxMoveFiles(manifest)
	}
	for _, name := range allowed {
		if h.Name == name {
			return nil
		}
	}
	return fmt.Errorf("%q is not part of a sandbox snapshot", h.Name)
}

func writeMoveEntry(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readMoveManifest(path, sandboxID string) (*sandboxSnapshotManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m sandboxSnapshotManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode the manifest: %w", err)
	}
	switch {
	case m.Version != 1:
		return nil, fmt.Errorf("manifest version %d is unsupported", m.Version)
	case m.SandboxID != sandboxID:
		return nil, fmt.Errorf("the manifest belongs to %q", m.SandboxID)
	case m.VsockCID < 3:
		return nil, fmt.Errorf("the manifest has reserved vsock CID %d", m.VsockCID)
	}
	return &m, nil
}

// DropImportedSnapshot undoes ImportSandboxSnapshot when the move does not
// happen: the snapshot folder and the network slot go. A sandbox running
// here is refused.
func (d *Driver) DropImportedSnapshot(ctx context.Context, sandboxID string) error {
	if err := validateSandboxID(sandboxID); err != nil {
		return err
	}
	d.mu.Lock()
	_, running := d.vmms[sandboxID]
	d.mu.Unlock()
	if running {
		return fmt.Errorf("firecracker runtime: drop %s: %w", sandboxID, errSandboxRunning)
	}
	if err := os.RemoveAll(d.sandboxSnapshotDir(sandboxID)); err != nil {
		return err
	}
	if d.pool != nil {
		return d.pool.Release(ctx, sandboxID)
	}
	return nil
}
