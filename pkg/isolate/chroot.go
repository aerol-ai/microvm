package isolate

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Per-group chroots. A group's root holds exactly what workerd needs to
// start and nothing it could use to get out: the binary at JailWorkerdPath,
// the shared libraries its ELF headers name (at their host paths, so the
// dynamic loader finds them without a cache), the handful of /dev nodes a
// runtime expects, and one writable run directory for the group's sockets.
// No /proc, no /sys, no shell, no other binary.
//
// The daemon builds that tree once at start (PrepareJailBase → <base>/.base)
// so a missing library or an unreadable workerd fails boot, not the first
// tenant's create. Each group then gets its own directory populated by hard
// links from .base: O(files) and no bytes copied, and because links share
// inodes, upgrading workerd is "rebuild .base, restart", never a per-group
// copy job.

// jailBaseName is the shared read-only tree under the chroot base.
const jailBaseName = ".base"

// lddCommand runs ldd; tests replace it with canned output.
var lddCommand = func(binary string) ([]byte, error) {
	return exec.Command("ldd", binary).CombinedOutput()
}

// PrepareJailBase builds <chrootBase>/.base for the workerd binary at
// workerdPath. Idempotent: an existing tree is rebuilt in place so an
// upgraded binary or a changed library set takes effect on the next spawn.
// Must run before any jailed spawn; the daemon calls it at start when
// SB_ISOLATE_USE_JAIL is on and fails boot on error.
func PrepareJailBase(chrootBase, workerdPath string) error {
	if chrootBase == "" || !filepath.IsAbs(chrootBase) {
		return fmt.Errorf("isolate jail: chroot base %q must be absolute", chrootBase)
	}
	if workerdPath == "" || !filepath.IsAbs(workerdPath) {
		return fmt.Errorf("isolate jail: workerd path %q must be absolute", workerdPath)
	}
	if _, err := os.Stat(workerdPath); err != nil {
		return fmt.Errorf("isolate jail: workerd binary: %w", err)
	}
	libs, err := resolveSharedLibs(workerdPath)
	if err != nil {
		return err
	}
	base := filepath.Join(chrootBase, jailBaseName)
	staging := base + ".next"
	_ = os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return fmt.Errorf("isolate jail: mkdir base: %w", err)
	}
	if err := copyFileMode(workerdPath, filepath.Join(staging, JailWorkerdPath), 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("isolate jail: stage workerd: %w", err)
	}
	for _, lib := range libs {
		dst := filepath.Join(staging, lib)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("isolate jail: stage lib dir: %w", err)
		}
		if err := copyFileMode(lib, dst, 0o755); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("isolate jail: stage %s: %w", lib, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(staging, "dev"), 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	if err := os.MkdirAll(filepath.Join(staging, "tmp"), 0o1777); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	_ = os.Chmod(filepath.Join(staging, "tmp"), 0o1777)
	if err := makeDevNodes(filepath.Join(staging, "dev")); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	// Swap atomically: readers of the old base (in-flight linkGroupJail) see
	// either tree, never a half-built one.
	old := base + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(base); err == nil {
		if err := os.Rename(base, old); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("isolate jail: retire old base: %w", err)
		}
	}
	if err := os.Rename(staging, base); err != nil {
		_ = os.Rename(old, base)
		_ = os.RemoveAll(staging)
		return fmt.Errorf("isolate jail: install base: %w", err)
	}
	_ = os.RemoveAll(old)
	return nil
}

// JailBasePrepared reports whether PrepareJailBase has produced a usable
// tree under chrootBase.
func JailBasePrepared(chrootBase string) bool {
	st, err := os.Stat(filepath.Join(chrootBase, jailBaseName, JailWorkerdPath))
	return err == nil && st.Mode().IsRegular()
}

// linkGroupJail populates groupDir (a direct child of chrootBase) from the
// prepared base by hard-linking every regular file and recreating every
// directory and device node. runUID/runGID own the run directory, the only
// place the jailed process may write.
func linkGroupJail(chrootBase, groupDir string, runUID, runGID int) error {
	base := filepath.Join(chrootBase, jailBaseName)
	if !JailBasePrepared(chrootBase) {
		return fmt.Errorf("isolate jail: base %s is not prepared (PrepareJailBase runs at daemon start)", base)
	}
	if filepath.Dir(groupDir) != filepath.Clean(chrootBase) || filepath.Base(groupDir) == jailBaseName {
		return fmt.Errorf("isolate jail: group dir %q must be a direct child of %q", groupDir, chrootBase)
	}
	if err := os.MkdirAll(groupDir, 0o755); err != nil {
		return err
	}
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(groupDir, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(dst, info.Mode().Perm())
		case info.Mode().IsRegular():
			_ = os.Remove(dst)
			if err := os.Link(path, dst); err != nil {
				// Different filesystem or a link-restricted mount: fall back
				// to a copy so the jail still works, only slower.
				return copyFileMode(path, dst, info.Mode().Perm())
			}
			return nil
		case info.Mode()&os.ModeDevice != 0 || info.Mode()&os.ModeCharDevice != 0:
			return cloneDevNode(path, dst)
		default:
			return nil // sockets, symlinks: nothing in the base should be these
		}
	})
	if err != nil {
		return fmt.Errorf("isolate jail: populate %s: %w", groupDir, err)
	}
	run := filepath.Join(groupDir, JailRunDirName)
	if err := os.MkdirAll(run, 0o700); err != nil {
		return err
	}
	if err := os.Chown(run, runUID, runGID); err != nil {
		return fmt.Errorf("isolate jail: chown run dir: %w", err)
	}
	return nil
}

// removeGroupJail deletes a group's chroot. It refuses the base tree and
// anything outside chrootBase so a bad spec can never turn teardown into
// rm -rf of the wrong directory.
func removeGroupJail(chrootBase, groupDir string) error {
	if filepath.Dir(groupDir) != filepath.Clean(chrootBase) || filepath.Base(groupDir) == jailBaseName || filepath.Base(groupDir) == "" {
		return fmt.Errorf("isolate jail: refusing to remove %q", groupDir)
	}
	return os.RemoveAll(groupDir)
}

// resolveSharedLibs returns the absolute paths of every shared object the
// binary's dynamic loader will need, plus the loader itself. A statically
// linked binary needs nothing.
func resolveSharedLibs(binary string) ([]string, error) {
	f, err := elf.Open(binary)
	if err != nil {
		return nil, fmt.Errorf("isolate jail: %s is not an ELF binary: %w", binary, err)
	}
	defer f.Close()
	interp := ""
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			raw, err := io.ReadAll(io.LimitReader(p.Open(), 4096))
			if err != nil {
				return nil, err
			}
			interp = strings.TrimRight(string(raw), "\x00")
			break
		}
	}
	if interp == "" {
		return nil, nil // static
	}
	out, err := lddCommand(binary)
	if err != nil {
		return nil, fmt.Errorf("isolate jail: ldd %s: %w (%s)", binary, err, strings.TrimSpace(string(out)))
	}
	libs, err := parseLDD(out)
	if err != nil {
		return nil, err
	}
	if !contains(libs, interp) {
		libs = append(libs, interp)
	}
	for _, lib := range libs {
		if _, err := os.Stat(lib); err != nil {
			return nil, fmt.Errorf("isolate jail: shared library %s: %w", lib, err)
		}
	}
	return libs, nil
}

// parseLDD extracts resolved absolute paths from ldd output:
//
//	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
//	/lib64/ld-linux-x86-64.so.2 (0x00007f...)
//	linux-vdso.so.1 (0x00007ffd...)          (no path: kernel-provided, skipped)
//
// A "not found" library is an error: the jail would start a binary that
// cannot load.
func parseLDD(out []byte) ([]string, error) {
	var libs []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "statically linked") || strings.Contains(line, "not a dynamic executable") {
			return nil, nil
		}
		if strings.Contains(line, "not found") {
			return nil, fmt.Errorf("isolate jail: ldd: %s", line)
		}
		path := ""
		if i := strings.Index(line, "=>"); i >= 0 {
			path = strings.TrimSpace(line[i+2:])
		} else if strings.HasPrefix(line, "/") {
			path = line
		}
		if j := strings.Index(path, " ("); j >= 0 {
			path = path[:j]
		}
		path = strings.TrimSpace(path)
		if path == "" || !strings.HasPrefix(path, "/") {
			continue
		}
		if !contains(libs, path) {
			libs = append(libs, path)
		}
	}
	return libs, sc.Err()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

var errNotRoot = errors.New("isolate jail: realization needs root (chroot, cgroup, mknod, setuid)")
