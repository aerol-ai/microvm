package rootd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

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

// RootPrograms is rootBinaries by setting: the programs c has root run or
// copy, for the deploy tools' tests, which check every path they render
// with CheckRootProgramPath.
func RootPrograms(c Config) map[string]string {
	out := map[string]string{}
	for _, b := range rootBinaries(c) {
		out[b.setting] = b.path
	}
	return out
}

// mergedUsrLinks are the top folders a merged /usr makes links into /usr:
// on Ubuntu 22.04 and 24.04, Debian 12 and Amazon Linux 2023, /sbin is a
// link to usr/sbin.
var mergedUsrLinks = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// MergedUsrLinks is mergedUsrLinks, for the deploy tools' tests: Terraform
// and Ansible refuse the same folders by name.
func MergedUsrLinks() []string { return slices.Clone(mergedUsrLinks) }

// CheckRootProgramPath is the part of the rule for a program root runs
// (checkRootBinaryFile) that the path alone shows: a clean absolute path,
// not at or inside a folder in agentDirs (the agent can rename anything
// below its own folders), and not under a folder a merged /usr makes a
// link, which the start check refuses on every current distribution.
// ConfigFromEnv applies it to each program it reads, and the deploy tools'
// tests apply it to each path they render for split (Terraform, Ansible,
// install.sh, the chart), so neither can name a path the other refuses.
// Terraform's split_problems and Ansible's split checks mirror it.
func CheckRootProgramPath(path string, agentDirs []string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("%q: want a clean absolute path", path)
	}
	for _, a := range agentDirs {
		if path == a || strings.HasPrefix(path, a+"/") {
			return fmt.Errorf("%s is inside %s, which the agent writes", path, a)
		}
	}
	for _, l := range mergedUsrLinks {
		if strings.HasPrefix(path, l+"/") {
			return fmt.Errorf("%s is under %s, which is a link to /usr%s on a host with a merged /usr "+
				"(Ubuntu, Debian 12, Amazon Linux 2023), and root runs nothing through a link: name it under /usr%s", path, l, l, l)
		}
	}
	return nil
}

// checkRootPrograms is CheckRootProgramPath on each program's path, naming
// its setting.
func checkRootPrograms(agentDirs []string, programs ...settingPath) error {
	for _, p := range programs {
		if err := CheckRootProgramPath(p.path, agentDirs); err != nil {
			return fmt.Errorf("%s: %w", p.setting, err)
		}
	}
	return nil
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
