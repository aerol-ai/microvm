package mounts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// Isolated mount tools (privilege mode split, plans/security-gaps-m1-m4.md
// §3.3 "Mounts", M1 PR 8). In split mode the root helper (internal/rootd)
// owns a Manager of its own, made with Config.Tools, and every FUSE tool
// (mount-s3, sshfs, rclone) runs as that normal user:
//
//   - The Manager opens /dev/fuse and makes the FUSE mount itself, as root,
//     with fixed options: nosuid, nodev, allow_other, the tool's user as
//     the mount's owner, read-only when the spec says so. The tool gets
//     the open device as /dev/fd/3 in place of its mount point. It never
//     mounts or unmounts anything, so it needs no setuid fusermount and
//     runs with no-new-privs.
//   - It starts as Tools.UID and Tools.GID with no other groups, no
//     capabilities and no-new-privs, as the leader of a session of its
//     own (toolProcAttr), in the helpers' cgroup, with an
//     environment of its own: PATH, a HOME that does not exist, its
//     mount's marker and what the adapter sets. Nothing of the helper's
//     environment reaches it, so no credential the node keeps there does.
//   - mount-s3 and rclone read their credentials once, at start, from
//     /dev/fd/4: a sealed memfd owned by the tool's user, mode 0400, that
//     no path names. ssh (under sshfs) closes every descriptor it did not
//     open and reads its key again on each reconnect, so its key is a
//     file, <CredDir>/<id>-<index>.id, the tool's, mode 0400, in a folder
//     only root writes, on /run, never on disk. No credential is ever on a
//     command line, in an environment value, or in a log.
//   - rclone keeps its write cache in <Tools.CacheDir>/<id>-<index>, the one
//     host folder it can write.
//
// The mount point is not on the tool's command line, so its environment
// carries the mount's marker (toolMarkEnv). Adoption after a restart and
// the sweep find a tool by it, as they find a single-mode tool by the last
// word of its command line.

// ToolUser is the normal user isolated tools run as (Config.Tools).
type ToolUser struct {
	UID, GID uint32
	// CacheDir holds each rclone mount's write cache. Root's, mode 0711: a
	// tool reaches its own folder by name and can list none.
	CacheDir string
}

const (
	// toolMarkEnv names the mount an isolated tool serves: its host path.
	toolMarkEnv = "AEROLVM_MOUNT"
	// toolFuseFD and toolCredFD are the tool's descriptors 3 and 4
	// (exec.Cmd.ExtraFiles), named the way each tool takes a path.
	toolFuseFD = "/dev/fd/3"
	toolCredFD = "/dev/fd/4"
	toolHome   = "/nonexistent"
	toolPath   = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// toolRun is what an isolated tool needs besides its plan.
type toolRun struct {
	// creds is what the tool reads as /dev/fd/4; nil when it reads none.
	creds []byte
	// cacheDir is rclone's write cache; "" for the other tools.
	cacheDir string
}

// Kernel and process hooks of the isolated tools: the Linux ones
// (tools_linux.go) outside tests.
var (
	// openToolFuse opens /dev/fuse and mounts it at hostPath for a tool of
	// subtype run by uid and gid.
	openToolFuse = openFuseFD
	// toolCredFile is a sealed memfd holding body, readable by uid alone.
	toolCredFile = newCredMemfd
	// startToolCmd starts cmd with no-new-privs.
	startToolCmd = startNoNewPrivs
	// waitForToolProbe waits for a tool to serve its mount.
	waitForToolProbe = waitForServed
	// toolFolderOwner owns the Manager's own folders: root. Tests that run
	// as someone else set their uid.
	toolFolderOwner = uint32(0)
)

// ErrToolFolder: a folder on a mount's path is not the Manager's own
// (a link, or someone else's), so nothing is mounted through it.
var ErrToolFolder = errors.New("not a folder of the mount manager's own")

// toolSubtype is the FUSE subtype of a type's tool, as the mount table
// shows it (fuse.<subtype>).
func toolSubtype(t models.MountType) string {
	if bin, ok := toolBinary(t); ok {
		return bin
	}
	return string(t)
}

// toolBinary is the program a type's isolated tool runs, from this fixed
// set: the command a tool starts is never taken from a plan, which also
// carries the request's values (go/command-injection).
func toolBinary(t models.MountType) (string, bool) {
	switch t {
	case models.MountTypeS3:
		return "mount-s3", true
	case models.MountTypeSSHFS:
		return "sshfs", true
	case models.MountTypeRclone:
		return "rclone", true
	}
	return "", false
}

// toolCacheFolder is rclone's write cache for mount index of sandboxID,
// <Tools.CacheDir>/<id>-<index>, or false for an id mountSet would refuse:
// the id's pattern, then the path cleaned and seen to stay in the cache
// folder, the check code scanning counts (go/path-injection).
func (m *Manager) toolCacheFolder(sandboxID string, index int) (string, bool) {
	if models.ValidateSandboxID(sandboxID) != nil {
		return "", false
	}
	root := filepath.Clean(m.tools.CacheDir)
	dir := filepath.Clean(filepath.Join(root, fmt.Sprintf("%s-%d", sandboxID, index)))
	if !strings.HasPrefix(dir, root+string(filepath.Separator)) {
		return "", false
	}
	return dir, true
}

// toolPlan turns an adapter's plan for a FUSE tool into the one an isolated
// tool runs: its mount point is the FUSE descriptor, its credentials a
// memfd (s3, rclone) or a file of its own (sshfs), its environment its own.
// It is pure, so adoption builds the same plan to find a running tool by.
func (m *Manager) toolPlan(sandboxID string, index int, t models.MountType, plan adapters.Plan, hostPath string) (adapters.Plan, toolRun, error) {
	var run toolRun
	argv := slices.Clone(plan.Argv)
	n := len(argv)
	if n < 2 || argv[n-1] != hostPath || !slices.Contains(argv, "--") {
		return adapters.Plan{}, run, fmt.Errorf("%s: the tool's command does not end with its mount point", argvName(argv))
	}
	if bin, ok := toolBinary(t); ok && argv[0] != bin {
		return adapters.Plan{}, run, fmt.Errorf("%s: a %s mount runs %s", argvName(argv), t, bin)
	}
	argv[n-1] = toolFuseFD
	out := adapters.Plan{CredFile: plan.CredFile, CredBody: plan.CredBody}
	credPath := plan.CredFile
	switch t {
	case models.MountTypeS3, models.MountTypeRclone:
		if plan.CredFile != "" {
			run.creds = slices.Clone(plan.CredBody)
			credPath = toolCredFD
			out.CredFile, out.CredBody = "", nil
		}
	case models.MountTypeSSHFS:
		// The key stays a file (see above), in CredDir as the adapter put it.
	default:
		return adapters.Plan{}, run, fmt.Errorf("mount type %q runs no FUSE tool", t)
	}
	swap := func(s string) string {
		if plan.CredFile == "" {
			return s
		}
		return strings.ReplaceAll(s, plan.CredFile, credPath)
	}
	for i := range argv {
		argv[i] = swap(argv[i])
	}
	env := []string{toolPath, "HOME=" + toolHome, toolMarkEnv + "=" + hostPath}
	for _, e := range plan.Env {
		env = append(env, swap(e))
	}
	switch t {
	case models.MountTypeS3:
		// mount-s3 answers only its own user unless told otherwise, in
		// userspace, whatever the mount's allow_other says.
		if !slices.Contains(argv, "--allow-other") && !slices.Contains(argv, "--allow-root") {
			argv = beforeOptionsEnd(argv, "--allow-other")
		}
	case models.MountTypeRclone:
		// rclone's mount2 takes a FUSE descriptor for its mount point;
		// mount runs fusermount, which needs the setuid bit no-new-privs
		// takes away. --allow-non-empty: the "is it empty" check would
		// open the descriptor's device as a folder.
		if len(argv) < 2 || argv[1] != "mount" {
			return adapters.Plan{}, run, errors.New("rclone: the tool's command is not rclone mount")
		}
		argv[1] = "mount2"
		cache, ok := m.toolCacheFolder(sandboxID, index)
		if !ok {
			return adapters.Plan{}, run, fmt.Errorf("rclone: no cache folder for sandbox %q", sandboxID)
		}
		run.cacheDir = cache
		argv = beforeOptionsEnd(argv, "--allow-non-empty", "--cache-dir="+run.cacheDir)
	}
	out.Argv, out.Env = argv, env
	return out, run, nil
}

// beforeOptionsEnd puts words ahead of the "--" that ends a tool's options.
func beforeOptionsEnd(argv []string, words ...string) []string {
	i := slices.Index(argv, "--")
	if i < 0 {
		return append(argv, words...)
	}
	return slices.Insert(argv, i, words...)
}

func argvName(argv []string) string {
	if len(argv) == 0 {
		return "mount tool"
	}
	return argv[0]
}

// mountTool is mountOne for a FUSE tool in isolated mode.
func (m *Manager) mountTool(ctx context.Context, sandboxID string, index int, spec models.MountSpec, hostPath string, plan adapters.Plan) (*mountState, ContainerBind, error) {
	if _, ok := consumerFrom(ctx); ok {
		return nil, ContainerBind{}, errors.New("isolated mount tools serve no WASM consumer")
	}
	tplan, run, err := m.toolPlan(sandboxID, index, spec.Type, plan, hostPath)
	if err != nil {
		return nil, ContainerBind{}, err
	}
	state := &mountState{
		sandboxID: sandboxID,
		index:     index,
		spec:      spec,
		hostPath:  hostPath,
		plan:      tplan,
		tool:      &run,
		startedAt: time.Now().UTC(),
	}
	cmd, out, exit, err := m.startTool(state)
	if err != nil {
		m.cleanupTool(state)
		return nil, ContainerBind{}, fmt.Errorf("spawn mount tool: %w", err)
	}
	state.cmd, state.output, state.exit = cmd, out, exit
	if err := waitForToolProbe(hostPath, m.waitTimeout, exit.done); err != nil {
		err = mountWaitError(err, exit, out) // before killMount, so the exit status is the tool's own
		_ = killMount(cmd)
		_ = unmountPath(hostPath)
		m.cleanupTool(state)
		return nil, ContainerBind{}, err
	}
	state.supervised = true
	go m.superviseExit(state)
	return state, ContainerBind{HostPath: hostPath, ContainerPath: spec.Target, ReadOnly: spec.ReadOnly}, nil
}

// startTool mounts s's FUSE descriptor and starts its tool as the tools'
// user. The tool's descriptors are its own copies: the Manager closes its
// FUSE descriptor once the tool runs, so the mount's connection ends with
// the tool, and a stat of a mount whose tool died fails instead of waiting.
func (m *Manager) startTool(s *mountState) (*exec.Cmd, *helperOutput, *procExit, error) {
	t := m.tools
	bin, ok := toolBinary(s.spec.Type)
	if !ok {
		return nil, nil, nil, fmt.Errorf("mount type %q runs no FUSE tool", s.spec.Type)
	}
	if s.tool.cacheDir != "" {
		if err := ensureToolCache(s.tool.cacheDir, t.UID, t.GID); err != nil {
			return nil, nil, nil, err
		}
	}
	if s.plan.CredFile != "" {
		if err := writeToolCred(s.plan.CredFile, s.plan.CredBody, t.UID, t.GID); err != nil {
			return nil, nil, nil, err
		}
	}
	fuse, err := openToolFuse(s.hostPath, toolSubtype(s.spec.Type), t.UID, t.GID, s.spec.ReadOnly)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mount the FUSE device at %s: %w", s.hostPath, err)
	}
	defer fuse.Close()
	files := []*os.File{fuse}
	if s.tool.creds != nil {
		cf, err := toolCredFile(s.tool.creds, t.UID, t.GID)
		if err != nil {
			_ = unmountPath(s.hostPath)
			return nil, nil, nil, fmt.Errorf("credentials for the mount tool: %w", err)
		}
		defer cf.Close()
		files = append(files, cf)
	}
	logFile, out, err := openHelperOutput(m.helperLogPath(s.sandboxID, s.index))
	if err != nil {
		_ = unmountPath(s.hostPath)
		return nil, nil, nil, err
	}
	defer logFile.Close()
	newCmd := func() *exec.Cmd {
		cmd := exec.Command(bin, s.plan.Argv[1:]...)
		cmd.Env = s.plan.Env
		cmd.Dir = "/"
		cmd.Stdout, cmd.Stderr = logFile, logFile
		cmd.ExtraFiles = files
		cmd.SysProcAttr = toolProcAttr(t)
		return cmd
	}
	cmd := newCmd()
	if fd, ok := m.cgroup.fd(); ok {
		setCgroupFD(cmd.SysProcAttr, fd)
		cgErr := startToolCmd(cmd)
		if cgErr == nil {
			return cmd, out, watchExit(cmd), nil
		}
		// As spawnHelper: a plain start tells whether the cgroup was the problem.
		cmd = newCmd()
		if err := startToolCmd(cmd); err != nil {
			_ = unmountPath(s.hostPath)
			return nil, nil, nil, toolStartError(s.plan.Argv[0], err)
		}
		m.cgroup.disable(fmt.Errorf("start %s in the cgroup: %w", s.plan.Argv[0], cgErr))
		return cmd, out, watchExit(cmd), nil
	}
	if err := startToolCmd(cmd); err != nil {
		_ = unmountPath(s.hostPath)
		return nil, nil, nil, toolStartError(s.plan.Argv[0], err)
	}
	return cmd, out, watchExit(cmd), nil
}

// toolProcAttr is how an isolated tool starts: as the tools' user with no
// other groups, as the leader of a new session. A session leader cannot
// move to another process group, and its children can join only groups of
// its own session, so the tool's group (which teardown signals) holds the
// tool and its children alone.
func toolProcAttr(t *ToolUser) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true,
		Credential: &syscall.Credential{Uid: t.UID, Gid: t.GID, Groups: []uint32{}}}
}

// restartTool starts a mount's tool again after it exited: an isolated
// one on a fresh FUSE mount (the old one died with its tool), any other
// as spawnHelper starts it.
func (m *Manager) restartTool(s *mountState) (*exec.Cmd, *helperOutput, *procExit, error) {
	if s.tool != nil {
		_ = unmountPath(s.hostPath)
		return m.startTool(s)
	}
	if s.plan.CredFile != "" {
		_ = writeCredFile(s.plan.CredFile, s.plan.CredBody)
	}
	return m.spawnHelper(s.plan, m.helperLogPath(s.sandboxID, s.index))
}

// cleanupTool removes what an isolated tool had on the host besides its
// mount: its key file and its cache.
func (m *Manager) cleanupTool(s *mountState) {
	if s.tool == nil {
		return
	}
	if s.plan.CredFile != "" {
		_ = os.Remove(s.plan.CredFile)
	}
	if s.tool.cacheDir != "" {
		_ = os.RemoveAll(s.tool.cacheDir)
	}
}

// clearToolFiles removes every key file and cache an isolated tool of
// sandboxID may have left, once its mount folder is gone.
func (m *Manager) clearToolFiles(sandboxID string) {
	if m.tools == nil || models.ValidateSandboxID(sandboxID) != nil {
		return
	}
	for _, pattern := range []string{filepath.Join(m.credDir, sandboxID+"-*.id"), filepath.Join(m.tools.CacheDir, sandboxID+"-*")} {
		matches, _ := filepath.Glob(pattern)
		for _, p := range matches {
			// <id>-<n> only: another sandbox's ID can start with this one's.
			rest := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), sandboxID+"-"), ".id")
			if _, err := strconv.Atoi(rest); err != nil {
				continue
			}
			_ = os.RemoveAll(p)
		}
	}
}

// ensureToolFolder makes sure path is a folder of the Manager's own: made
// where missing, never a link, owned by root and writable by no one else.
// Every folder a mount point sits in passes it before anything is mounted
// there, so a link someone planted is never followed into another folder.
func ensureToolFolder(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir():
		return fmt.Errorf("%s: %w (mode %v)", path, ErrToolFolder, st.Mode())
	case !ok || sys.Uid != toolFolderOwner:
		return fmt.Errorf("%s: %w (owner is not root)", path, ErrToolFolder)
	case st.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s: %w (others can write it)", path, ErrToolFolder)
	}
	return nil
}

// ensureToolCache makes rclone's cache folder, the tool's alone.
func ensureToolCache(dir string, uid, gid uint32) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("mount tool cache: %w", err)
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("mount tool cache %s: %w", dir, ErrToolFolder)
	}
	if err := os.Lchown(dir, int(uid), int(gid)); err != nil {
		return fmt.Errorf("mount tool cache: %w", err)
	}
	return os.Chmod(dir, 0o700)
}

// writeToolCred writes a key file the tool's user alone can read. It is
// made afresh each time, never written through an old name.
func writeToolCred(path string, body []byte, uid, gid uint32) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("mount tool key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o400)
	if err != nil {
		return fmt.Errorf("mount tool key: %w", err)
	}
	if _, err = f.Write(body); err == nil {
		err = f.Chown(int(uid), int(gid))
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("mount tool key: %w", err)
	}
	return nil
}

// waitForServed waits for the tool to answer a stat of its mount: the
// mount exists from the start (the Manager made it), so a changed device
// says nothing; an answer says the tool serves it. The stat runs aside: it
// waits on the tool, and ends when the tool answers or exits.
func waitForServed(hostPath string, timeout time.Duration, exited <-chan struct{}) error {
	served := make(chan error, 1)
	go func() {
		_, err := os.Stat(hostPath)
		served <- err
	}()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case err := <-served:
		if err == nil {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("%w at %s", errMountToolExited, hostPath)
		default:
		}
		return fmt.Errorf("mount at %s does not answer: %w", hostPath, err)
	case <-exited:
		return fmt.Errorf("%w at %s", errMountToolExited, hostPath)
	case <-deadline.C:
		return fmt.Errorf("timed out waiting for mount at %s", hostPath)
	}
}

// markedFor is the processes whose marker names hostPath.
func markedFor(helpers []helperProcess, hostPath string) []helperProcess {
	var out []helperProcess
	for _, h := range helpers {
		if h.mark == hostPath {
			out = append(out, h)
		}
	}
	return out
}

// readMark is pid's mount marker, or "".
func readMark(pid int) string {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "environ"))
	if err != nil {
		return ""
	}
	for _, kv := range strings.Split(string(raw), "\x00") {
		if v, ok := strings.CutPrefix(kv, toolMarkEnv+"="); ok {
			return v
		}
	}
	return ""
}

// killToolsFor stops every tool serving a path under dir: by its command
// line (killFUSEProcessesFor), and in isolated mode by its marker. In
// isolated mode both stop only processes of the tools' own user.
func (m *Manager) killToolsFor(dir string) {
	if m.tools == nil {
		killFUSEProcessesFor(m.logger, dir, nil)
		return
	}
	uid := m.tools.UID
	killFUSEProcessesFor(m.logger, dir, &uid)
	killMarkedInRoot(m.logger, dir, procRoot, uid)
}

// killMarkedInRoot SIGKILLs every process of the tools' user (uid) whose
// mount marker is dir or a path under it (signalListed: the process, and
// its group only when it leads one of its own). The marker is the tool's
// own environment, which the tool can change, so the user is what makes a
// process one of the tools'.
func killMarkedInRoot(logger *slog.Logger, dir, root string, uid uint32) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	marked := func(pid int) bool {
		raw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "environ"))
		if err != nil {
			return false
		}
		for _, kv := range strings.Split(string(raw), "\x00") {
			if mark, ok := strings.CutPrefix(kv, toolMarkEnv+"="); ok && (mark == dir || strings.HasPrefix(mark, dir+"/")) {
				return true
			}
		}
		return false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 || !e.IsDir() || !marked(pid) || !runsAs(root, pid, uid) {
			continue
		}
		logger.Info("mounts: killing mount tool", "pid", pid, "dir", dir)
		_ = signalListed(pid, syscall.SIGKILL, func() bool { return marked(pid) && runsAs(root, pid, uid) })
	}
}

// prepareToolDirs readies the Manager's folders for isolated tools: the
// mounts folder root's alone (0700), so no other user reaches a mount
// with allow_other by its path; the key and cache folders root's and
// 0711, so a tool reaches its own file by name and lists nothing.
func prepareToolDirs(root, credDir string, t *ToolUser) error {
	if t.UID == 0 || t.GID == 0 {
		return errors.New("mount tools must not run as root")
	}
	if !filepath.IsAbs(t.CacheDir) || filepath.Clean(t.CacheDir) != t.CacheDir {
		return fmt.Errorf("mount tool cache folder must be a clean absolute path: %q", t.CacheDir)
	}
	if err := os.MkdirAll(t.CacheDir, 0o711); err != nil {
		return fmt.Errorf("create mount tool cache folder: %w", err)
	}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{root, 0o700}, {credDir, 0o711}, {t.CacheDir, 0o711}} {
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		if err := ensureToolFolder(d.path, d.mode); err != nil {
			return err
		}
	}
	return nil
}

// makeMountFolder makes a folder a mount point sits in, or the point
// itself: in isolated mode one of the Manager's own (ensureToolFolder).
func (m *Manager) makeMountFolder(path string) error {
	p, ok := m.inMountsRoot(path)
	if !ok {
		return fmt.Errorf("%s: %w (not below the mounts folder)", path, ErrToolFolder)
	}
	if m.tools == nil {
		return os.MkdirAll(p, 0o700)
	}
	return ensureToolFolder(p, 0o700)
}

// adoptTool is adoptOne for an isolated tool: the one process whose marker
// names the mount and that runs the plan the spec builds today.
func (m *Manager) adoptTool(sandboxID string, index int, spec models.MountSpec, hostPath string, plan adapters.Plan, helpers []helperProcess) (*mountState, ContainerBind) {
	tplan, run, err := m.toolPlan(sandboxID, index, spec.Type, plan, hostPath)
	if err != nil {
		return nil, ContainerBind{}
	}
	match := helperFor(markedFor(helpers, hostPath), tplan.Argv)
	if match == nil {
		return nil, ContainerBind{}
	}
	proc, err := openHelperProcess(match.pid, match.argv)
	if err != nil {
		return nil, ContainerBind{}
	}
	if tplan.CredFile != "" {
		// ssh reads its key again on a reconnect.
		if _, err := os.Lstat(tplan.CredFile); err != nil {
			_ = writeToolCred(tplan.CredFile, tplan.CredBody, m.tools.UID, m.tools.GID)
		}
	}
	state := &mountState{
		sandboxID:  sandboxID,
		index:      index,
		spec:       spec,
		hostPath:   hostPath,
		plan:       tplan,
		tool:       &run,
		startedAt:  time.Now().UTC(),
		proc:       proc,
		exit:       watchLiveExit(proc),
		output:     &helperOutput{path: m.helperLogPath(sandboxID, index)},
		supervised: true,
	}
	go m.superviseExit(state)
	m.logger.Info("mounts: adopted running mount tool", "sandbox_id", sandboxID, "index", index, "type", string(spec.Type), "pid", match.pid)
	return state, ContainerBind{HostPath: hostPath, ContainerPath: spec.Target, ReadOnly: spec.ReadOnly}
}
