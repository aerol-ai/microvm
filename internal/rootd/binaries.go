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
// on Ubuntu 22.04 and 24.04, Debian 12 and 13 and Amazon Linux 2023,
// /sbin is a link to usr/sbin.
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
			return fmt.Errorf("%s is under %s, which is a link into /usr on a host with a merged /usr "+
				"(Ubuntu, Debian, Amazon Linux 2023), and root follows no link in a folder: %s", path, l, nameItAdvice)
		}
	}
	return nil
}

// nameItAdvice is what every refusal of a program's path says to do. It
// names no path: the right one differs by distribution (ip is /usr/bin/ip
// on Ubuntu and Debian, /usr/sbin/ip on Amazon Linux 2023), and readlink
// -f prints one that passes on the node itself.
const nameItAdvice = "name the program by the path `readlink -f` prints for it on the node"

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
// checkRootBinaryFile, or a test's stand-in; it answers the file the path
// names, which, when the path ends in a link, must be outside the agent's
// folders too.
func checkRootBinaries(c Config, check func(path string) (string, error)) error {
	for _, b := range rootBinaries(c) {
		file, err := check(b.path)
		if err == nil && file != b.path {
			if perr := CheckRootProgramPath(file, c.AgentDirs); perr != nil {
				err = fmt.Errorf("it is a link to %s: %w", file, perr)
			}
		}
		if err != nil {
			return fmt.Errorf("root helper: %s=%s: root runs this file, so every folder on its path must be root's, closed to "+
				"others and no link, and the file root's and no one else's to write; its last name may be a link, of root's, "+
				"to such a file: %w", b.setting, b.path, err)
		}
	}
	return nil
}

// checkRootBinaryFile is the rule for one such file, and answers the file
// it names. Every folder from / down to the file's follows the rule for
// root's own folders (rootfolder.OpenFolder), each opened with no link
// followed. The file itself is root's plain file that no one else can
// write.
//
// Its last name may instead be a link, as distributions ship them
// (/usr/sbin/mkfs.ext4 is a link to mke2fs on Ubuntu and Debian): a link
// of root's, read through the folder just checked, to a file that passes
// the same rule, with no second link. A relative target is taken from
// the link's folder, whose path has no link, so the kernel resolves it to
// the same path. The helper still runs the path it was given: every step
// the kernel takes through the link is in folders only root can change,
// and some programs care what they are called (mke2fs makes ext4 as
// mkfs.ext4; the jailer names a VM's chroot after firecracker's file).
//
// In production the helper is root, so "root's" means uid 0; a test's own
// user stands in for root, as in OpenFolder.
func checkRootBinaryFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s: want a clean absolute path", path)
	}
	owner := uint32(os.Geteuid())
	st, link, err := statRoot(path, owner)
	if err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return path, checkRootFile(&st, path, owner)
	}
	if err := checkRootLink(&st, path, owner); err != nil {
		return "", err
	}
	file, err := linkTarget(path, link)
	if err != nil {
		return "", err
	}
	fst, _, err := statRoot(file, owner)
	if err != nil {
		return "", fmt.Errorf("%s is a link to %s: %w; %s", path, file, err, nameItAdvice)
	}
	if fst.Mode&unix.S_IFMT == unix.S_IFLNK {
		return "", fmt.Errorf("%s is a link to %s, itself a link; %s", path, file, nameItAdvice)
	}
	if err := checkRootFile(&fst, file, owner); err != nil {
		return "", fmt.Errorf("%s is a link to %s: %w", path, file, err)
	}
	return file, nil
}

// statRoot is statRootName; tests stand one in, to give a link an owner
// only root could give it.
var statRoot = statRootName

// checkRootLink: a link of root's (or the test's own user), which no one
// else could have made or can change in a folder only root writes.
func checkRootLink(st *unix.Stat_t, at string, owner uint32) error {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFLNK:
		return fmt.Errorf("%s is not a link (mode %o)", at, st.Mode)
	case st.Uid != 0 && st.Uid != owner:
		return fmt.Errorf("%s is a link of uid %d", at, st.Uid)
	}
	return nil
}

// linkTarget is the file the link at path names by its text, target,
// worked out as the kernel works it out. The target must be a clean path:
// clean, a ".." can only come first in a relative target, where it climbs
// the link's own folder path, which the walk to the link proved has no
// link, so the text and the kernel agree. A ".." after another name would
// go up from wherever that name leads, which may be a link the text does
// not show (bin/tool -> ../lnk/../evil/tool, with lnk -> q/r, runs
// q/evil/tool), so it is refused, as is "." and "//". Every name after the
// leading ".." parts is then walked from / with no link followed
// (statRootName).
func linkTarget(path, target string) (string, error) {
	if target == "" || filepath.Clean(target) != target {
		return "", fmt.Errorf("%s is a link to %q, which is not a clean path (a \"..\" may only come first in a relative "+
			"link); %s", path, target, nameItAdvice)
	}
	if filepath.IsAbs(target) {
		return target, nil
	}
	return filepath.Join(filepath.Dir(path), target), nil
}

// statRootName opens path's folder from / with no link followed, each
// folder checked as root's own (rootfolder.CheckFolder), and stats the last
// name in it without following it. For a link it answers the link's text,
// read through the same folder handle.
func statRootName(path string, owner uint32) (unix.Stat_t, string, error) {
	var st unix.Stat_t
	dfd, err := walkFolder(filepath.Dir(path), false, func(at string, st *unix.Stat_t, last bool) error {
		return rootfolder.CheckFolder(at, uint32(st.Mode), st.Uid, owner, !last)
	})
	if err != nil {
		return st, "", err
	}
	defer func() { _ = unix.Close(dfd) }()
	name := filepath.Base(path)
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return st, "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return st, "", nil
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dfd, name, buf)
	if err != nil {
		return st, "", fmt.Errorf("read the link %s: %w", path, err)
	}
	if n == 0 || n >= len(buf) {
		return st, "", fmt.Errorf("the link %s names no path", path)
	}
	return st, string(buf[:n]), nil
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
