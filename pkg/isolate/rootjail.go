package isolate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// RootJail realizes V8 group jails for the root helper (internal/rootd) in
// privilege mode split, where sandboxd has no rights
// (plans/security-gaps-m1-m4.md §3.3 "Host processes", M1 PR 9). It is the
// same jail single mode builds (prepareJailFS, applyJail), from the
// helper's own settings: the agent names only the group.
//
// One thing differs, because the agent is not root. A group's run folder,
// where the agent writes workerd's config and binds the sockets workerd
// dials, is the agent's: a noexec tmpfs owned by the agent's uid and the
// jail's group, mode 3770, so what the agent makes there is the jail
// group's too and workerd reads and dials it through its group. It is
// sticky: workerd can make names there but never rename or remove the
// agent's, so the agent never acts on a name workerd swapped. workerd runs
// with umask 0, so the agent reaches the control socket workerd binds
// there; no other user can enter the folder to reach it.
//
// A jail is made fresh for each start (the helper tears down one whose
// workerd is gone before it prepares it again): nothing an earlier workerd
// left in its run folder is there for the next.
type RootJail struct {
	// ChrootBase holds every group's chroot, <base>/<group>, and the shared
	// tree they are linked from, <base>/.base. A folder of the helper's.
	ChrootBase string
	// WorkerdPath is the workerd binary the base tree is built from.
	WorkerdPath string
	// UID and GID are the jail user workerd drops to.
	UID, GID int
	// AgentUID owns each group's run folder.
	AgentUID int
	// Jitless and SeccompMode pick the filter (SeccompAllowlist).
	Jitless     bool
	SeccompMode string
	// ShimPath is the binary run as the shim (JailShimFlag): the helper's
	// own.
	ShimPath string
}

// runFolderMode is a split group's run folder: setgid and sticky, 0770.
const runFolderMode = 0o3770

// workerdConfigPath is the config workerd serves, inside the jail: the run
// folder's config.capnp, which the agent writes (Host.writeConfig).
const workerdConfigPath = "/" + JailRunDirName + "/config.capnp"

// Validate checks the settings once, when the helper starts.
func (r RootJail) Validate() error {
	for name, p := range map[string]string{"chroot base": r.ChrootBase, "workerd": r.WorkerdPath, "shim": r.ShimPath} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return fmt.Errorf("isolate root jail: %s %q: want a clean absolute path other than /", name, p)
		}
	}
	if r.UID <= 0 || r.GID <= 0 {
		return fmt.Errorf("isolate root jail: the jail user must not be root (uid/gid %d/%d)", r.UID, r.GID)
	}
	if r.AgentUID <= 0 || r.AgentUID == r.UID {
		return fmt.Errorf("isolate root jail: agent uid %d must be a user of its own, not root and not the jail's", r.AgentUID)
	}
	if _, err := seccompDefaultAction(r.SeccompMode); err != nil && r.SeccompMode != SeccompOff {
		return err
	}
	return nil
}

// GroupDir is a group's chroot. group must be a checked group key.
func (r RootJail) GroupDir(group string) string { return filepath.Join(r.ChrootBase, group) }

// RunDir is a group's run folder on the host.
func (r RootJail) RunDir(group string) string {
	return filepath.Join(r.GroupDir(group), JailRunDirName)
}

// PrepareBase builds the shared tree every group is linked from.
func (r RootJail) PrepareBase() error { return PrepareJailBase(r.ChrootBase, r.WorkerdPath) }

// checkGroup refuses a group key that could name anything but one chroot.
func checkGroup(group string) error {
	if group == "" || group == jailBaseName || strings.ContainsAny(group, "/\x00") || strings.HasPrefix(group, ".") {
		return fmt.Errorf("isolate root jail: group %q is not one folder name", group)
	}
	return nil
}

// Prepare makes sure a group's chroot exists, with its two writable
// folders mounted, and answers with its run folder. A chroot already
// prepared is answered as it is; a half-made one is removed and made
// again.
func (r RootJail) Prepare(group string) (string, error) {
	if err := checkGroup(group); err != nil {
		return "", err
	}
	dir, run := r.GroupDir(group), r.RunDir(group)
	if prepared(dir) {
		return run, nil
	}
	if err := r.Teardown(group); err != nil {
		return "", err
	}
	if err := linkGroupJail(r.ChrootBase, dir, r.UID, r.GID); err != nil {
		_ = removeGroupJail(r.ChrootBase, dir)
		return "", err
	}
	if err := mountJailTmpfs(filepath.Join(dir, "tmp"), r.UID, r.GID, 0o700); err != nil {
		_ = r.Teardown(group)
		return "", err
	}
	if err := mountJailTmpfs(run, r.AgentUID, r.GID, runFolderMode); err != nil {
		_ = r.Teardown(group)
		return "", err
	}
	return run, nil
}

// Command is the shim that starts a prepared group's workerd. The caller
// starts it in the group's cgroup (UseCgroupFD).
func (r RootJail) Command(group string) (*exec.Cmd, error) {
	if err := checkGroup(group); err != nil {
		return nil, err
	}
	dir := r.GroupDir(group)
	if !prepared(dir) {
		return nil, fmt.Errorf("isolate root jail: group %s is not prepared", group)
	}
	var prog []bpfInsn
	if r.SeccompMode != SeccompOff {
		var err error
		if prog, _, err = buildSeccompProgram(hostproc.SeccompArch(), hostproc.SyscallTable(), SeccompAllowlist(r.Jitless),
			SeccompArgRules(r.Jitless), r.SeccompMode); err != nil {
			return nil, err
		}
	}
	umask := uint32(0)
	encoded, err := encodeJailShimSpec(jailShimSpec{
		Chroot:  dir,
		Cwd:     "/" + JailRunDirName,
		UID:     r.UID,
		GID:     r.GID,
		Argv:    []string{JailWorkerdPath, "serve", "--experimental", workerdConfigPath},
		Env:     []string{"HOME=/" + JailRunDirName, "TMPDIR=/tmp"},
		Seccomp: prog,
		Umask:   &umask,
	})
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(r.ShimPath, JailShimFlag)
	cmd.Env = []string{jailShimSpecEnv + "=" + encoded}
	setJailProcAttr(cmd)
	return cmd, nil
}

// Teardown makes sure a group's chroot is gone: its mounts, then its
// folder. Its process must be gone first.
func (r RootJail) Teardown(group string) error {
	if err := checkGroup(group); err != nil {
		return err
	}
	dir := r.GroupDir(group)
	unmountNoexecMounts([]string{filepath.Join(dir, "tmp"), r.RunDir(group)})
	if mounted(r.RunDir(group)) || mounted(filepath.Join(dir, "tmp")) {
		return fmt.Errorf("isolate root jail: group %s still has a mount; not removing its folder", group)
	}
	if err := removeGroupJail(r.ChrootBase, dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Groups lists the group chroots under the base, the base tree aside.
func (r RootJail) Groups() ([]string, error) {
	entries, err := os.ReadDir(r.ChrootBase)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && checkGroup(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// prepared reports whether a group's chroot is whole: its workerd linked
// in and both writable folders mounted.
func prepared(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, strings.TrimPrefix(JailWorkerdPath, "/")))
	return err == nil && st.Mode().IsRegular() && mounted(filepath.Join(dir, JailRunDirName)) && mounted(filepath.Join(dir, "tmp"))
}

// Prepared reports whether a group's chroot is whole: what Prepare makes.
func (r RootJail) Prepared(group string) bool {
	return checkGroup(group) == nil && prepared(r.GroupDir(group))
}
