package firecracker

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// A VM's disk is a 10 GiB image of mostly holes and its memory file is
// mostly holes too (p5-move-6: 50 MiB and 73 MiB used). Sent whole, a move
// carried 10.5 GiB of zeros and the target wrote every one, so its disk
// was no longer sparse and the start's copy into the jailer took longer
// than the move's start step. A file with holes therefore goes as its
// data ranges only: sparseSizeKey (PAX) gives its full size, and the entry
// is a table of ranges (sparseTable) followed by their bytes. The target
// writes no zero block, so its copy stays sparse either way.

const (
	// sparseSizeKey marks a sparse entry and gives the file's full size.
	sparseSizeKey = "AEROLVM.sparse.size"
	// maxMoveFileSize and maxMoveRanges bound what an import accepts.
	maxMoveFileSize = int64(1) << 40
	maxMoveRanges   = 1 << 20
)

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
	size := st.Size()
	ranges := dataRanges(f, size)
	if size == 0 || (len(ranges) == 1 && ranges[0] == byteRange{0, size}) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, Typeflag: tar.TypeReg, ModTime: st.ModTime()}); err != nil {
			return err
		}
		_, err = io.Copy(tw, io.NewSectionReader(f, 0, size))
		return err
	}
	table := sparseTable(ranges)
	entry := int64(len(table))
	for _, r := range ranges {
		entry += r.end - r.start
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: entry, Typeflag: tar.TypeReg, ModTime: st.ModTime(),
		Format: tar.FormatPAX, PAXRecords: map[string]string{sparseSizeKey: strconv.FormatInt(size, 10)}}); err != nil {
		return err
	}
	if _, err := tw.Write(table); err != nil {
		return err
	}
	for _, r := range ranges {
		if _, err := io.Copy(tw, io.NewSectionReader(f, r.start, r.end-r.start)); err != nil {
			return err
		}
	}
	return nil
}

// sparseTable is a sparse entry's head: the range count, then each range's
// start and end, big-endian.
func sparseTable(ranges []byteRange) []byte {
	out := make([]byte, 4, 4+16*len(ranges))
	binary.BigEndian.PutUint32(out, uint32(len(ranges)))
	for _, r := range ranges {
		out = binary.BigEndian.AppendUint64(out, uint64(r.start))
		out = binary.BigEndian.AppendUint64(out, uint64(r.end))
	}
	return out
}

// readSparseTable reads and checks a sparse entry's table: ranges in
// order, apart, inside size, and their bytes exactly the rest of the entry.
func readSparseTable(r io.Reader, size, entry int64) ([]byteRange, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, fmt.Errorf("sparse table: %w", err)
	}
	count := int64(binary.BigEndian.Uint32(n[:]))
	if count > maxMoveRanges || 4+16*count > entry {
		return nil, fmt.Errorf("sparse table: %d ranges", count)
	}
	raw := make([]byte, 16*count)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, fmt.Errorf("sparse table: %w", err)
	}
	ranges := make([]byteRange, count)
	data, prev := int64(0), int64(0)
	for i := range ranges {
		start, end := int64(binary.BigEndian.Uint64(raw[16*i:])), int64(binary.BigEndian.Uint64(raw[16*i+8:]))
		if start < prev || end <= start || end > size {
			return nil, fmt.Errorf("sparse table: range %d is [%d, %d) in a %d-byte file", i, start, end, size)
		}
		ranges[i], prev, data = byteRange{start, end}, end, data+end-start
	}
	if 4+16*count+data != entry {
		return nil, fmt.Errorf("sparse table: %d bytes of ranges in a %d-byte entry", data, entry)
	}
	return ranges, nil
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
	staging, err := os.MkdirTemp(base, ".import-")
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
		path, err := inside(staging, h.Name)
		if err != nil {
			return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
		}
		if err := writeMoveEntry(path, h, tr); err != nil {
			return fmt.Errorf("firecracker runtime: import %s: %w", sandboxID, err)
		}
		got[h.Name] = true
		if h.Name == sandboxSnapshotManifestName {
			if manifest, err = readMoveManifest(path, sandboxID); err != nil {
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
	final, err := inside(base, sandboxID)
	if err != nil {
		return err
	}
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

// inside is dir's child name, refusing a name that would leave dir. The
// sandbox ID and the entry names are checked already (validateSandboxID,
// checkMoveEntry), but they arrive from another worker, and this is the
// check code scanning recognizes (go/path-injection, go/zipslip).
func inside(dir, name string) (string, error) {
	// The checked value is the one returned: code scanning trusts only it.
	p := filepath.Clean(filepath.Join(dir, name))
	if !strings.HasPrefix(p, filepath.Clean(dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is not a name inside %s", name, dir)
	}
	return p, nil
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

// writeMoveEntry writes the entry h, read from r, to a new file at path,
// leaving every zero block a hole.
func writeMoveEntry(path string, h *tar.Header, r io.Reader) error {
	size, ranges := h.Size, []byteRange{{0, h.Size}}
	if v, ok := h.PAXRecords[sparseSizeKey]; ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 || n > maxMoveFileSize {
			return fmt.Errorf("%s: sparse size %q", h.Name, v)
		}
		size = n
		if ranges, err = readSparseTable(r, size, h.Size); err != nil {
			return fmt.Errorf("%s: %w", h.Name, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, sparseBufSize)
	for _, rg := range ranges {
		for off := rg.start; off < rg.end; {
			chunk := buf[:min(int64(len(buf)), rg.end-off)]
			if _, err := io.ReadFull(r, chunk); err != nil {
				_ = f.Close()
				return err
			}
			if err := writeDataBlocks(f, chunk, off); err != nil {
				_ = f.Close()
				return err
			}
			off += int64(len(chunk))
		}
	}
	if err := f.Truncate(size); err != nil {
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
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		return err
	}
	dir, err := inside(base, sandboxID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if d.pool != nil {
		return d.pool.Release(ctx, sandboxID)
	}
	return nil
}
