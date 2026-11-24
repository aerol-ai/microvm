//go:build unix

package wasm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Checkpoints in privilege mode split (plans/security-gaps-m1-m4.md, M1
// PR 15). In single mode sandboxd is root: it takes the folder a worker
// wrote a checkpoint into, and each file in it, back to itself by owner
// (promoteCheckpoint). In split it is not root and cannot take a file back
// from the worker user. So it copies the checkpoint out, and no root
// process opens a checkpoint file at any step. Who owns what:
//
//   - the staging folder, ModulesDir/<id>/.mem.snap-stage: sandboxd's,
//     setgid to the worker's group and 2770, for the one checkpoint
//     (handToWorker). The worker reaches it only as the folder sandboxd
//     passes it; sandboxd removes it after the copy;
//   - what the worker writes in it (a folder renamed to mem.snap and the
//     snapshot's files): the worker user's, 0770 and 0660, so sandboxd
//     reads them as a member of its group (pkg/wasm WriteSnapshotDir);
//   - the published mem.snap: a copy, in a new folder of sandboxd's
//     (0700) with files of its own (0600), made from each of the
//     snapshot's known files after a check through the open file: a
//     regular file with one name, the worker's or sandboxd's, no larger
//     than a snapshot file may be. A descriptor the worker kept reaches
//     only its own copy, which is removed.
//
// A worker reads a checkpoint only to restore it, through one descriptor
// per file that sandboxd opens and passes (Client.Restore): no worker can
// open any checkpoint by name, as ModulesDir and each sandbox's folder in
// it are sandboxd's alone.

// copyOutCheckpoint publishes the worker's staged mem.snap at final as a
// copy of sandboxd's own. The staging folder is removed either way.
func (d *Driver) copyOutCheckpoint(staged, final string) error {
	// Both are sandboxd's own paths, ModulesDir/<id>/...: cleaned and seen
	// to stay in the modules folder, the check code scanning counts
	// (go/path-injection).
	modules := filepath.Clean(d.cfg.ModulesDir) + string(filepath.Separator)
	staged, final = filepath.Clean(staged), filepath.Clean(final)
	if !strings.HasPrefix(staged, modules) || !strings.HasPrefix(final, modules) {
		return fmt.Errorf("%w: a checkpoint outside the modules folder", errStagedSnapshot)
	}
	stage := filepath.Dir(staged)
	defer os.RemoveAll(stage)
	// The staging folder is sandboxd's, in a folder no worker reaches, so
	// its name is what sandboxd made. mem.snap in it is the worker's: it
	// is opened once, with no link followed, and read only through that
	// handle, whatever the worker renames in the folder meanwhile.
	snapFD, err := unix.Open(staged, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// A link (ELOOP), a file (ENOTDIR), or nothing written.
		return fmt.Errorf("%w: %v", errStagedSnapshot, err)
	}
	snap := os.NewFile(uintptr(snapFD), staged)
	defer snap.Close()
	euid := os.Geteuid()
	var st unix.Stat_t
	if err := unix.Fstat(snapFD, &st); err != nil {
		return err
	}
	if !d.checkpointOwner(st.Uid, euid) {
		return fmt.Errorf("%w: mem.snap belongs to uid %d", errStagedSnapshot, st.Uid)
	}
	names, err := snap.Readdirnames(-1)
	if err != nil {
		return err
	}
	// Only a snapshot's own files, by the names sandboxd knows: what is
	// opened and made below is never a name the worker chose.
	have := map[string]bool{}
	for _, name := range names {
		have[name] = true
	}
	var files []string
	for _, p := range wasmengine.SnapshotFiles("") {
		if have[p] {
			files = append(files, p)
			delete(have, p)
		}
	}
	if len(have) > 0 {
		return fmt.Errorf("%w: %d names that are not a snapshot's", errStagedSnapshot, len(have))
	}
	// The copy is made beside the staging folder, in the sandbox's own
	// folder, which no worker ever had.
	out, err := os.MkdirTemp(filepath.Dir(stage), ".mem.snap-copy-*")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(out)
		}
	}()
	for _, name := range files {
		if err := d.copyCheckpointFile(snapFD, name, filepath.Join(out, name), euid); err != nil {
			return err
		}
	}
	// A snapshot is a snapshot by its config (pkg/wasm DirExists).
	if !wasmengine.DirExists(out) {
		return fmt.Errorf("%w: no config", errStagedSnapshot)
	}
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(out, final); err != nil {
		return err
	}
	published = true
	return nil
}

// checkpointOwner reports whether uid may own what a worker staged: the
// worker user, or sandboxd itself.
func (d *Driver) checkpointOwner(uid uint32, euid int) bool {
	return int64(uid) == int64(d.cfg.Worker.UID) || int64(uid) == int64(euid)
}

// copyCheckpointFile copies name, in the worker's folder dirFD, to a new
// file of sandboxd's at dst, checked through the open file first: never a
// link, never a FIFO's wait, never a file with another name somewhere else
// (a hard link may name a file outside the checkpoint), never one larger
// than a snapshot file may be. The copy is bounded too: the worker may
// still hold a descriptor that grows the file.
func (d *Driver) copyCheckpointFile(dirFD int, name, dst string, euid int) error {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", errStagedSnapshot, name, err)
	}
	in := os.NewFile(uintptr(fd), name)
	defer in.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: %s is not a regular file", errStagedSnapshot, name)
	case uint64(st.Nlink) != 1:
		return fmt.Errorf("%w: %s has %d names", errStagedSnapshot, name, st.Nlink)
	case !d.checkpointOwner(st.Uid, euid):
		return fmt.Errorf("%w: %s belongs to uid %d", errStagedSnapshot, name, st.Uid)
	case st.Size < 0 || st.Size > wasmengine.MaxSnapshotFileBytes:
		return fmt.Errorf("%w: %s is %d bytes, over %d", errCheckpointTooLarge, name, st.Size, int64(wasmengine.MaxSnapshotFileBytes))
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(in, wasmengine.MaxSnapshotFileBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > wasmengine.MaxSnapshotFileBytes {
		err = fmt.Errorf("%w: %s grew past %d bytes", errCheckpointTooLarge, name, int64(wasmengine.MaxSnapshotFileBytes))
	}
	return err
}

// errCheckpointTooLarge refuses a staged file larger than a snapshot file
// may be.
var errCheckpointTooLarge = errors.New("checkpoint file too large")
