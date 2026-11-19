package mounts

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// A sandbox's mount folder (rootDir/<id>) holds its mount points. Removing
// it with os.RemoveAll while one of them is still mounted walks into the
// mount and deletes the storage's own files: a bucket's objects, an NFS
// export's files. That happens for a mount this process does not track (a
// helper's mount a previous sandboxd left, which a stop or destroy can
// reach before the reconcile adopts it), for one whose unmount failed, and
// for a mount the set's rollback had not reached. So the folder goes only
// through clearMountDir: everything still mounted under it is unmounted
// first, and the removal never crosses into a mount.

// errStillMounted: a sandbox's mount folder still has a mount under it, so
// it is left in place; the next Sweep tries again.
var errStillMounted = errors.New("still mounted")

// mountInfoPath lists this process's mounts. A var so tests can stand one in.
var mountInfoPath = "/proc/self/mountinfo"

// clearMountDir removes dir, one sandbox's mount folder, once nothing is
// mounted under it. Anything that still is gets its helpers stopped and is
// unmounted, deepest first; one that will not go keeps dir in place. A dir
// that does not exist costs one stat, so the stop and destroy of a sandbox
// without mounts read no mount table.
func (m *Manager) clearMountDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if points := mountPointsUnder(dir); len(points) > 0 {
		killFUSEProcessesFor(m.logger, dir)
		unmountPoints(m.logger, points)
		if left := mountPointsUnder(dir); len(left) > 0 {
			err := fmt.Errorf("mount folder %s: %w at %s; left in place", dir, errStillMounted, strings.Join(left, ", "))
			m.logger.Warn("mounts: not removing a mount folder with a mount under it", "path", dir, "mounts", left)
			return err
		}
	}
	return removeOnDevice(dir)
}

// mountPointsUnder lists the mount points at or under dir, deepest first:
// the ones the mount table names (every kind, a bind of a folder on the
// same device too), and the folders whose device differs from dir's
// parent's (the only test where there is no mount table). It never walks
// into a mount point it finds.
func mountPointsUnder(dir string) []string {
	found := map[string]bool{}
	for _, p := range mountTablePointsUnder(dir) {
		found[p] = true
	}
	parentDev := pathDevOf(filepath.Dir(dir))
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if found[path] {
			return fs.SkipDir
		}
		if dev := pathDevOf(path); dev != 0 && dev != parentDev {
			found[path] = true
			return fs.SkipDir
		}
		return nil
	})
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	// Deepest first, so a parent is free to unmount after its children.
	slices.SortFunc(out, func(a, b string) int {
		if d := strings.Count(b, string(filepath.Separator)) - strings.Count(a, string(filepath.Separator)); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	return out
}

// mountTablePointsUnder reads the mount table for mount points at or under
// dir, matched both as given and with its symlinks resolved (the table
// names resolved paths). The paths are returned as dir spells them.
func mountTablePointsUnder(dir string) []string {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	dir = filepath.Clean(dir)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		resolved = dir
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		point := unescapeMountInfo(fields[4])
		for _, base := range []string{dir, resolved} {
			if rel, ok := underDir(base, point); ok {
				out = append(out, filepath.Join(dir, rel))
				break
			}
		}
	}
	return out
}

// underDir reports whether path is base or below it, and the rest of path.
func underDir(base, path string) (string, bool) {
	if path == base {
		return ".", true
	}
	if rest, ok := strings.CutPrefix(path, base+string(filepath.Separator)); ok {
		return rest, true
	}
	return "", false
}

// unescapeMountInfo undoes the table's octal escapes (\040 for a space).
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unmountPoints unmounts each of points in order, with a lazy umount as
// the fallback.
func unmountPoints(logger *slog.Logger, points []string) {
	for _, path := range points {
		if err := sweepUmount(path); err == nil {
			continue
		}
		if err := sweepLazyUmount(path); err != nil {
			logger.Warn("mounts: umount failed", "path", path, "error", err)
		}
	}
}

// removeOnDevice removes dir and everything under it that is on dir's own
// device. It does not follow a symlink, and refuses to walk into a folder
// on another device: that is a mount, and what is under it is the
// storage's, not this folder's.
func removeOnDevice(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return os.Remove(dir)
	}
	return removeDirOnDevice(dir, pathDevOf(dir))
}

func removeDirOnDevice(dir string, dev uint64) error {
	if d := pathDevOf(dir); d != dev {
		return fmt.Errorf("mount folder %s: %w (another device under it); left in place", dir, errStillMounted)
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var firstErr error
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() { // a symlink to a folder is not IsDir: it is removed, not followed
			err = removeDirOnDevice(path, dev)
		} else {
			err = os.Remove(path)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
