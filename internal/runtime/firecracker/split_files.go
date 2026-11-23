package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// A VM's snapshot files in privilege mode split (M1 PR 14b). Who owns each
// file at each step:
//
//	file                         where                     owner:group mode
//	saved snapshot, template     sandboxd's folders        sandboxd's own
//	  shared into a VM           linked into the chroot    sandboxd : jailer's group, 0640
//	a VM's writable disk         the chroot                jailer's user : jailer's group, 0600
//	what firecracker writes      the chroot                jailer's user : sandboxd's group (setgid chroot)
//	  handed out                 the chroot                jailer's user : sandboxd's group, 0640
//	  copied out                 sandboxd's folders        sandboxd's own
//	the kernel                   the chroot                root : jailer's group, 0640
//
// No file changes owner. The jailer's user never writes a file sandboxd
// later loads into another VM: a saved snapshot is sandboxd's copy, and a
// shared file is read-only to the jailer's group. sandboxd reads a file of
// the jailer's user only through a handle opened with no link followed,
// and only a regular file with one name (copyFromChroot).

// sharedFile is a file shared into a VM read-only: its name in the chroot
// and the file sandboxd keeps it as.
type sharedFile struct{ name, src string }

// splitJailOf is the sandbox ID of the VM whose jail dir is in (its chroot
// or its stage folder), with that jail's chroot and stage folder, as the
// helper lays them out.
func (d *Driver) splitJailOf(dir string) (id, root, stage string, err error) {
	id = filepath.Base(filepath.Dir(dir))
	_, root, stage, err = rootpolicy.FirecrackerJail(d.cfg.JailerChrootBase, id)
	if err != nil || (dir != root && dir != stage) {
		return "", "", "", fmt.Errorf("firecracker runtime: %s is not a VM's chroot or stage folder", dir)
	}
	return id, root, stage, nil
}

// splitShare shares files into the VM whose jail runDir is in, read-only,
// in one helper call: each is linked into the stage folder (copied when
// it is on another filesystem, as single mode's linkOrCopyRootfs does) and
// the helper links that very file into the chroot. A file already shared
// (the chroot's name is that very file) is not sent again.
func (d *Driver) splitShare(ctx context.Context, runDir string, files ...sharedFile) error {
	id, root, stage, err := d.splitJailOf(runDir)
	if err != nil {
		return err
	}
	var names []string
	for _, f := range files {
		if err := rootpolicy.CheckFirecrackerShare(f.name); err != nil {
			return fmt.Errorf("firecracker runtime: %w", err)
		}
		dst, in := filepath.Join(stage, f.name), filepath.Join(root, f.name)
		if sameFileAs(f.src, in) || (f.src == dst && missing(dst) && agentsInChroot(in)) {
			continue
		}
		if f.src != dst {
			if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("firecracker runtime: clear %s in the stage folder: %w", f.name, err)
			}
			if err := linkOrCopyRootfs(f.src, dst); err != nil {
				return fmt.Errorf("firecracker runtime: stage %s: %w", f.name, err)
			}
		}
		names = append(names, f.name)
	}
	if len(names) == 0 {
		return nil
	}
	if err := d.split.ShareFirecrackerFiles(ctx, id, names...); err != nil {
		return fmt.Errorf("root helper: share %s: %w", strings.Join(names, ", "), err)
	}
	return nil
}

// missing: nothing has the name p.
func missing(p string) bool {
	_, err := os.Lstat(p)
	return errors.Is(err, os.ErrNotExist)
}

// agentsInChroot: p, in a VM's chroot, is a regular file of sandboxd's. Only
// the helper's share puts one there: sandboxd cannot write the chroot, and
// the jailer's user cannot make a file sandboxd owns. A file built in the
// stage folder and shared is gone from the stage folder, so this is how a
// second ask for it knows it is shared already.
func agentsInChroot(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(agentUID())
}

// sameFileAs: a and b name one file (b looked at with no link followed).
func sameFileAs(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Lstat(b)
	return err == nil && bi.Mode().IsRegular() && os.SameFile(ai, bi)
}

// chrootFile is a file to copy out of a VM's chroot: its name there and
// sandboxd's file to copy it to.
type chrootFile struct{ name, dst string }

// splitCopyOut has the helper let sandboxd's group read the named files in
// the chroot of the VM whose jail runDir is in, then copies each out
// (copyFromChroot). Single mode copies the same files as root.
func (d *Driver) splitCopyOut(ctx context.Context, runDir string, files ...chrootFile) error {
	id, root, _, err := d.splitJailOf(runDir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	dsts := make([]string, 0, len(files))
	for _, f := range files {
		dst, err := d.ownPath(f.dst)
		if err != nil {
			return err
		}
		names, dsts = append(names, f.name), append(dsts, dst)
	}
	if err := d.split.HandOutFirecrackerFiles(ctx, id, names...); err != nil {
		return fmt.Errorf("root helper: hand out %s: %w", strings.Join(names, ", "), err)
	}
	for i, name := range names {
		if err := copyFromChroot(filepath.Join(root, name), dsts[i]); err != nil {
			return err
		}
	}
	return nil
}

// ownPath is p, cleaned, when it lies in one of the driver's own folders
// (TemplatesDir, RunDir): sandboxd copies or moves a VM's file out only
// into them. The paths that reach here are built from a sandbox's or a
// template's ID, which the API checked already. The check sits next to
// the file calls so it holds for every caller, and in the form code
// scanning (go/path-injection) trusts: a cleaned path seen to keep a
// fixed folder as its prefix.
func (d *Driver) ownPath(p string) (string, error) {
	clean := filepath.Clean(p)
	for _, root := range []string{d.cfg.TemplatesDir, d.cfg.RunDir} {
		if root = strings.TrimSpace(root); root == "" {
			continue
		}
		root = filepath.Clean(root)
		if strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return clean, nil
		}
	}
	return "", fmt.Errorf("firecracker runtime: %s is not in sandboxd's own folders", p)
}

// copyFromChroot copies a file the helper handed out of a VM's chroot to
// dst, a new file of sandboxd's own, keeping it sparse. The chroot is the
// jailer's user's, so its names may change at any time: src is opened once,
// with no link followed and without waiting on a FIFO, and copied only when
// that handle is a regular file within the helper's cap that is either the
// jailer's user's with one name or sandboxd's own (a file the helper shared
// in, such as a template's root disk). Its content is the VM's, which only
// a VM loads and sandboxd hashes and copies.
func copyFromChroot(src, dst string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if err := checkChrootFile(info); err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	out, err := copyFileOpenDst(dst, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	size := info.Size()
	if err := copySparse(out, in, dataRanges(in, size), size); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("sync %s: %w", dst, err)
	}
	return out.Close()
}

// agentUID is sandboxd's own uid; tests stand in another.
var agentUID = os.Getuid

// checkChrootFile is copyFromChroot's check of the handle it opened.
func checkChrootFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if info.Size() < 0 || info.Size() > rootpolicy.MaxFirecrackerFileBytes {
		return fmt.Errorf("%d bytes; at most %d", info.Size(), rootpolicy.MaxFirecrackerFileBytes)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no owner to check")
	}
	if int64(st.Uid) != int64(agentUID()) && uint64(st.Nlink) != 1 {
		return fmt.Errorf("%d names; want the VM's own file", st.Nlink)
	}
	return nil
}

// SplitTemplateDisk builds a template's root disk in privilege mode split
// (pkg/daemon's template builder). The helper makes a filesystem only in a
// VM's stage folder (SplitMkfs), so the build gets the jail of the
// template's own snapshot VM (snapshotVMMIDPrefix): build writes the disk
// at the stage path it is given, the disk then moves to out, sandboxd's
// own file, and the jail goes. SnapshotTemplate makes that jail again,
// from nothing, for the snapshot.
func (d *Driver) SplitTemplateDisk(ctx context.Context, templateID, out string, build func(stageOut string) error) error {
	if d.split == nil {
		return errors.New("firecracker runtime: SplitTemplateDisk outside privilege mode split")
	}
	id := snapshotVMMIDPrefix + templateID
	if err := validateSandboxID(id); err != nil {
		return fmt.Errorf("firecracker template disk: %w", err)
	}
	out, err := d.ownPath(out)
	if err != nil {
		return fmt.Errorf("firecracker template disk: %w", err)
	}
	_, stage, err := d.split.PrepareFirecracker(ctx, id)
	if err != nil {
		return fmt.Errorf("root helper: template %s jail: %w", templateID, err)
	}
	defer func() {
		if sErr := d.split.StopFirecracker(context.WithoutCancel(ctx), id); sErr != nil {
			d.logger.Warn("firecracker template disk: remove the build's jail failed", "template_id", templateID, "error", sErr)
		}
	}()
	disk := filepath.Join(stage, rootfsFileName)
	if err := build(disk); err != nil {
		return err
	}
	if err := os.Rename(disk, out); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return fmt.Errorf("firecracker template disk: move to %s: %w", out, err)
	}
	// The templates folder is on another filesystem than the jails.
	return copyRootfsPrivate(disk, out)
}

// cidFromMAC is the guest CID macFromCID made mac from: ok is false for any
// other MAC.
func cidFromMAC(mac string) (uint32, bool) {
	rest, ok := strings.CutPrefix(mac, "02:00:00:")
	if !ok || len(rest) != 8 || rest[2] != ':' || rest[5] != ':' {
		return 0, false
	}
	v, err := strconv.ParseUint(rest[0:2]+rest[3:5]+rest[6:8], 16, 32)
	if err != nil || v < 3 {
		return 0, false
	}
	cid := uint32(v)
	if macFromCID(cid) != mac {
		return 0, false
	}
	return cid, true
}
