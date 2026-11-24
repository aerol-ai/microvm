package rootd

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// settingPath is a path the helper trusts, under the name of the setting
// that gave it.
type settingPath struct{ setting, path string }

// rootBinaries lists the programs c names that root runs, or reads and
// copies (workerd: ldd, then a copy into every V8 jail's base). The
// helper's own binary, the shim, is not a setting; the CNI plugins are
// checked where their folder is opened (openNetwork), and the Firecracker
// kernel at the first VM (kernelIsRoots).
func rootBinaries(c Config) []settingPath {
	var out []settingPath
	if w := c.Hosts.Workerd; w != nil {
		out = append(out, settingPath{"SB_ISOLATE_WORKERD_PATH", w.Jail.WorkerdPath})
	}
	if fc := c.Hosts.Firecracker; fc != nil {
		out = append(out, settingPath{"SB_JAILER_BINARY", fc.JailerBinary}, settingPath{"SB_FIRECRACKER_BINARY", fc.FirecrackerBinary},
			settingPath{"SB_FIRECRACKER_MKFS_BIN", fc.Mkfs4Bin})
		if fc.IPBinary != "" {
			out = append(out, settingPath{"SB_FIRECRACKER_IP_BINARY", fc.IPBinary})
		}
	}
	if m := c.Moves; m != nil {
		out = append(out, settingPath{"SB_ROOTD_RUNSC", m.Runsc})
	}
	return out
}

// checkRootBinaries refuses to start a helper that would run or copy as
// root a program someone else could change. The folders the helper makes
// are checked when it opens them; these are files it only names, so they
// are checked here, once, before the socket exists. check is
// checkRootBinaryFile, or a test's stand-in.
func checkRootBinaries(c Config, check func(path string) error) error {
	for _, b := range rootBinaries(c) {
		if err := check(b.path); err != nil {
			return fmt.Errorf("root helper: %s=%s: root runs this file, so it must be root's own plain file that no one else "+
				"can write, in folders only root can change, with no link anywhere on its path: %w", b.setting, b.path, err)
		}
	}
	return nil
}

// checkRootBinaryFile is the rule for one such file: the rule for root's
// own folders (rootfolder.OpenFolder), on every folder from / down to the
// file's, each opened with no link followed; then the file itself, by its
// name in the folder just checked, never followed through a link. A link
// on the way is refused even where only root could change it: the rule is
// the same one the helper's folders follow, and the path the operator
// wrote is then the file that runs.
//
// In production the helper is root, so "root's" means uid 0; a test's own
// user stands in for root, as in OpenFolder.
func checkRootBinaryFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s: want a clean absolute path", path)
	}
	owner := uint32(os.Geteuid())
	dfd, err := walkFolder(filepath.Dir(path), false, func(at string, st *unix.Stat_t, last bool) error {
		return rootfolder.CheckFolder(at, uint32(st.Mode), st.Uid, owner, !last)
	})
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%s is a link; name the file it points to", path)
	}
	return checkRootFile(&st, path, owner)
}

// checkRootFile: a plain file of root's (or the test's own user), which no
// one else can write.
func checkRootFile(st *unix.Stat_t, at string, owner uint32) error {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%s is not a plain file (mode %o)", at, st.Mode)
	case st.Uid != 0 && st.Uid != owner:
		return fmt.Errorf("%s belongs to uid %d", at, st.Uid)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%s can be written by others (mode %o)", at, st.Mode&0o7777)
	}
	return nil
}
