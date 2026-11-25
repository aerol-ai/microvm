package rootswap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// The floor: root never runs a helper older than the one it ran (CheckNewer).
// The supervisor knows the helper it runs while it runs, but a restart of
// its container starts it with nothing in memory, and the agent can stage
// any helper a release ever signed. So the supervisor writes the manifest of
// each helper it runs to FloorName in its own folder of copies before that
// helper starts, and reads it back when it starts. The folder is root's
// alone (rootfolder.OpenFolder), so the agent can neither write the floor
// nor put an older one in its place. On Kubernetes it sits on a volume only
// the runtime container mounts, which outlives a restart of that container
// and ends with the pod.
//
// The manifest is kept as root wrote it, not with its signature: it is
// root's own record, in root's own folder, and a runtime image whose release
// keys changed must still read the floor its last helper left.

// FloorName is the floor's file in the supervisor's folder of copies. Sweep
// keeps it: it is no copy.
const FloorName = BinaryName + ".floor"

// WriteFloor records m as the floor in binDir: written whole under a new
// name, synced, then renamed over the last one and the folder synced, so a
// crash leaves the old floor or the new one, never half of either.
func WriteFloor(binDir string, m Manifest) error {
	if err := m.check(); err != nil {
		return err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	tmp, err := rootfolder.TmpName(FloorName)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(bfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(append(raw, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(bfd, tmp, bfd, FloorName)
	}
	if err != nil {
		_ = unix.Unlinkat(bfd, tmp, 0)
		return fmt.Errorf("root helper floor: %w", err)
	}
	return syncFolder(bfd)
}

// syncFolder syncs the folder dfd names, so a rename in it outlives a crash.
// The handle may be O_PATH, which cannot sync; "." through it is the same
// folder, opened to read.
func syncFolder(dfd int) error {
	fd, err := unix.Openat(dfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	return nil
}

// ReadFloor is the floor in binDir: the manifest of the helper root ran
// last, or nil when it has run none there yet. A floor that is there but
// cannot be read, or is not a whole manifest, is an error: the caller then
// runs no staged helper, as it cannot tell which ones are older.
func ReadFloor(binDir string) (*Manifest, error) {
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return nil, fmt.Errorf("root helper floor: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	fd, err := unix.Openat(bfd, FloorName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("root helper floor %s: %w", filepath.Join(binDir, FloorName), err)
	}
	f := os.NewFile(uintptr(fd), FloorName)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("root helper floor: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("root helper floor %s is not a regular file (mode %o)", filepath.Join(binDir, FloorName), st.Mode)
	case st.Uid != uint32(os.Geteuid()):
		return nil, fmt.Errorf("root helper floor %s belongs to uid %d", filepath.Join(binDir, FloorName), st.Uid)
	case st.Size > maxManifestSize:
		return nil, fmt.Errorf("root helper floor %s is %d bytes; at most %d", filepath.Join(binDir, FloorName), st.Size, maxManifestSize)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxManifestSize))
	if err != nil {
		return nil, fmt.Errorf("root helper floor: %w", err)
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("root helper floor %s: %w", filepath.Join(binDir, FloorName), err)
	}
	return &m, nil
}
