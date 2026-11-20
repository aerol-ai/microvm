package rootd

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

// listen makes the helper's socket at path, mode 0660, group gid.
//
// The socket is bound in a fresh folder only this process can enter, given
// its group and mode there, then renamed into place. So nobody can connect
// while it still has the default mode, and no umask is touched (umask is
// process-wide, and other goroutines create files). The rename also
// replaces a socket left by a run that died, in one step.
func listen(path string, gid int) (*net.UnixListener, os.FileInfo, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("root helper: socket folder: %w", err)
	}
	switch fi, err := os.Lstat(path); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, nil, fmt.Errorf("root helper: socket: %w", err)
	case fi.Mode().Type() != fs.ModeSocket:
		// Never replace a file someone put there; it may not be ours.
		return nil, nil, fmt.Errorf("root helper: %s exists and is not a socket", path)
	}
	tmpDir, err := os.MkdirTemp(dir, ".rootd-")
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: socket folder: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmp := filepath.Join(tmpDir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: listen: %w", err)
	}
	// The name it was bound under is gone after the rename; Shutdown
	// removes the real one.
	ln.SetUnlinkOnClose(false)
	fail := func(err error) (*net.UnixListener, os.FileInfo, error) {
		_ = ln.Close()
		return nil, nil, fmt.Errorf("root helper: socket: %w", err)
	}
	if err := os.Chown(tmp, -1, gid); err != nil {
		return fail(err)
	}
	if err := os.Chmod(tmp, 0o660); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	return ln, fi, nil
}
