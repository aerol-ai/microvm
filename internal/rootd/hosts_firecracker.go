package rootd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootfolder"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// firecrackerHosts are the Firecracker VMs (kind firecracker, M1 PR 9b),
// run by the jailer as in privilege mode single, from the helper's own
// settings. A VM's jail is <chroot base>/firecracker/<sandbox ID>:
//
//	<id>/          root's, 0711
//	├── stage/     the agent's, 0700: it builds the VM's disks here
//	└── root/      the jailer's chroot: the jailer's user, the agent's
//	               group, 02750
//
// The agent never writes in the chroot: the jailer works there as root
// (it copies firecracker in and makes device nodes), so a name the agent
// put there could send root's write anywhere. PrepareHost moves each disk
// the agent built from stage/ into root/ (a link of the very file it
// checked: the agent's own, with one name) and gives it to the jailer's
// user; the kernel is the helper's own file.
//
// Nor does a used chroot meet the jailer again. firecracker runs as the
// jailer's user, who owns root/, and could leave a link there: the jailer
// copies firecracker in by its name, as root, and would write through it.
// So whenever no process runs in the VM's group, PrepareHost and
// SpawnHost make root/ again from nothing (openJail's fresh); a running
// VM's jail is never touched. stage/ is kept: it is the agent's, and
// nothing in it reaches the chroot but a disk stageDisk checked.
//
// The firecracker process runs with umask 027 in a setgid chroot, so what
// it makes there comes out the agent's group's to read, never to write;
// the helper gives the API socket to that group once it is bound, and
// PrepareHost on a running VM gives both sockets.
type firecrackerHosts struct {
	cfg *FirecrackerHostsConfig
	// log is the hosts' output file; agentGID the agent's group.
	log      string
	agentGID int

	kernelMu sync.Mutex
	// checkKernel stands in for the kernel file's checks in tests, and
	// fchown for giving files away, which only root can.
	checkKernel func(path string) error
	fchown      func(fd, uid, gid int) error
}

// The names firecracker binds in its chroot (internal/runtime/firecracker
// jailerAPISocketName and hostVsockUDSName).
const (
	firecrackerAPISocket   = "api.socket"
	firecrackerVsockSocket = "vsock.sock"
)

// FirecrackerJailerExecFlag is the flag that makes the helper's own binary
// the jailer's shim (cmd/aerolvm-rootd): RunFirecrackerJailerShim.
const FirecrackerJailerExecFlag = "--firecracker-jailer-exec"

// FirecrackerShimUmask is the umask the jailer and firecracker run with:
// what they make in the chroot comes out with the chroot's group (the
// agent's, by the setgid folder) able to read but never to write, and
// others with nothing. The helper gives each socket the agent must dial
// to its group itself (shareSocket).
const FirecrackerShimUmask = 0o027

func newFirecrackerHosts(c *FirecrackerHostsConfig, logPath string, agentGID int) *firecrackerHosts {
	f := &firecrackerHosts{cfg: c, log: logPath, agentGID: agentGID, fchown: fchownAny}
	f.checkKernel = f.kernelIsRoots
	return f
}

func (f *firecrackerHosts) jail(id string) (dir, root, stage string, err error) {
	dir, root, stage, err = rootpolicy.FirecrackerJail(f.cfg.ChrootBase, id)
	if err != nil {
		err = refusedRule(codes.InvalidArgument, err)
	}
	return dir, root, stage, err
}

// openJail opens (making what is missing) the VM's jail folder and its
// two folders, each owned and moded as the jail's layout says: the
// folders above, root's alone; stage/, the agent's; root/, the jailer's
// user's with the agent's group. fresh removes root/ and all it holds
// first, for a VM with no process in its group (freshChroot).
func (f *firecrackerHosts) openJail(id string, fresh bool) (stage, root *os.File, err error) {
	dir, _, _, err := f.jail(id)
	if err != nil {
		return nil, nil, err
	}
	agent := int64(f.cfg.AgentUID)
	if agent > math.MaxInt32 {
		return nil, nil, fmt.Errorf("root helper: agent uid %d is past %d", agent, math.MaxInt32)
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		fd, err := openFolder(d)
		if err != nil {
			return nil, nil, fmt.Errorf("root helper: Firecracker jail %s: %w", d, err)
		}
		// Others may pass through to the sockets, but not list the jails.
		err = fchmodAny(fd, 0o711)
		if d == dir {
			if err == nil {
				stage, err = f.subFolder(fd, "stage", int(agent), f.agentGID, 0o700)
			}
			if err == nil && fresh {
				err = freshChroot(dir)
			}
			if err == nil {
				root, err = f.subFolder(fd, "root", f.cfg.UID, f.agentGID, 0o2750)
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			if stage != nil {
				_ = stage.Close()
			}
			return nil, nil, fmt.Errorf("root helper: Firecracker jail %s: %w", d, err)
		}
	}
	return stage, root, nil
}

// freshChroot removes a stopped VM's chroot, dir/root, and all it holds.
// The folders down to dir are root's alone (openJail has just opened and
// checked them), and os.RemoveAll opens nothing below dir through a link,
// so the jailer's user can send the removal nowhere else. openJail then
// makes root/ again, empty.
func freshChroot(dir string) error {
	if err := os.RemoveAll(filepath.Join(dir, "root")); err != nil {
		return fmt.Errorf("remove the used chroot: %w", err)
	}
	return nil
}

// subFolder makes (when missing) and opens the folder name in the jail
// folder dfd, with no link followed, and sets its owner and mode.
func (f *firecrackerHosts) subFolder(dfd int, name string, uid, gid int, mode uint32) (*os.File, error) {
	if err := unix.Mkdirat(dfd, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(dfd, name, rootfolder.FolderFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s without following a link: %w", name, err)
	}
	if err := f.fchown(fd, uid, gid); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// After the chown, which drops a setgid bit.
	if err := fchmodAny(fd, mode); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (f *firecrackerHosts) prepare(id string, running bool, req *rootdpb.PrepareHostRequest) (*rootdpb.PrepareHostResponse, error) {
	for _, name := range req.GetFirecracker().GetStage() {
		if err := rootpolicy.CheckFirecrackerFile(name); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
	}
	_, rootPath, stagePath, err := f.jail(id)
	if err != nil {
		return nil, err
	}
	// A VM whose group is empty gets a chroot made again from nothing; a
	// running VM's is left as it is.
	stage, root, err := f.openJail(id, !running)
	if err != nil {
		return nil, err
	}
	defer stage.Close()
	defer root.Close()
	if err := f.stageKernel(int(root.Fd())); err != nil {
		return nil, err
	}
	for _, name := range req.GetFirecracker().GetStage() {
		if err := f.stageDisk(int(stage.Fd()), int(root.Fd()), name); err != nil {
			return nil, err
		}
	}
	if running {
		for _, name := range []string{firecrackerAPISocket, firecrackerVsockSocket} {
			if err := f.shareSocket(int(root.Fd()), name); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, fmt.Errorf("root helper: Firecracker %s %s: %w", id, name, err)
			}
		}
	}
	return &rootdpb.PrepareHostResponse{RunDir: rootPath, StageDir: stagePath}, nil
}

// stageDisk moves the disk name the agent built in stage into the chroot
// for the jailer's user. It must be the agent's own regular file with one
// name (no link to anyone else's file). The very file checked is linked
// in: after the link the helper opens the chroot's name again and
// refuses it unless it is that file. The stage name goes after.
func (f *firecrackerHosts) stageDisk(stage, root int, name string) error {
	fd, err := unix.Openat(stage, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		var st unix.Stat_t
		if unix.Fstatat(root, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && int64(st.Uid) == int64(f.cfg.UID) && st.Mode&unix.S_IFMT == unix.S_IFREG {
			return nil // moved by an earlier call
		}
		return badRequest("root helper: Firecracker disk %s is not in the stage folder", name)
	}
	if err != nil {
		return badRequest("root helper: Firecracker disk %s: %v", name, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return badRequest("root helper: Firecracker disk %s is not a regular file", name)
	case st.Uid != f.cfg.AgentUID:
		return badRequest("root helper: Firecracker disk %s belongs to uid %d, not the agent", name, st.Uid)
	case st.Nlink != 1:
		return badRequest("root helper: Firecracker disk %s has %d names; want its own file", name, st.Nlink)
	}
	if err := unix.Unlinkat(root, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("root helper: clear %s in the chroot: %w", name, err)
	}
	if err := unix.Linkat(stage, name, root, name, 0); err != nil {
		return fmt.Errorf("root helper: link %s into the chroot: %w", name, err)
	}
	var in unix.Stat_t
	if err := unix.Fstatat(root, name, &in, unix.AT_SYMLINK_NOFOLLOW); err != nil || in.Dev != st.Dev || in.Ino != st.Ino {
		_ = unix.Unlinkat(root, name, 0)
		return badRequest("root helper: Firecracker disk %s changed while it was moved", name)
	}
	if err := f.fchown(fd, f.cfg.UID, f.cfg.GID); err != nil {
		return err
	}
	if err := fchmodAny(fd, 0o600); err != nil {
		return err
	}
	_ = unix.Unlinkat(stage, name, 0)
	return nil
}

// stageKernel puts the helper's kernel in the chroot, as single mode's
// chrootSharedFile does: root's, the jailer's group, 0640, so every VM
// reads it and none writes it. A link where the file system allows, else a
// copy. Owner and mode are set through a handle on the very file: the
// chroot is the jailer's user's, so a name there may change under the
// helper.
func (f *firecrackerHosts) stageKernel(root int) error {
	f.kernelMu.Lock()
	defer f.kernelMu.Unlock()
	if err := f.checkKernel(f.cfg.Kernel); err != nil {
		return fmt.Errorf("root helper: Firecracker kernel %s: %w", f.cfg.Kernel, err)
	}
	name := rootpolicy.FirecrackerKernel
	src, err := os.Open(f.cfg.Kernel)
	if err != nil {
		return err
	}
	defer src.Close()
	var want unix.Stat_t
	if err := unix.Fstat(int(src.Fd()), &want); err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Fstatat(root, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Dev == want.Dev && st.Ino == want.Ino {
		return nil
	}
	if err := unix.Unlinkat(root, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	var fd int
	if err := unix.Linkat(unix.AT_FDCWD, f.cfg.Kernel, root, name, 0); err == nil {
		fd, err = unix.Openat(root, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Fstat(fd, &st); err != nil || st.Dev != want.Dev || st.Ino != want.Ino {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(root, name, 0)
			return fmt.Errorf("root helper: the kernel in the chroot changed while it was linked")
		}
	} else if errors.Is(err, unix.EXDEV) {
		if fd, err = copyInto(root, name, src); err != nil {
			return fmt.Errorf("root helper: Firecracker kernel into the chroot: %w", err)
		}
	} else {
		return fmt.Errorf("root helper: Firecracker kernel into the chroot: %w", err)
	}
	defer unix.Close(fd)
	if err := f.fchown(fd, 0, f.cfg.GID); err != nil {
		return err
	}
	return fchmodAny(fd, 0o640)
}

// copyInto writes src to a new file name in dir, and answers a handle on it.
func copyInto(dir int, name string, src io.Reader) (int, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return -1, err
	}
	out := os.NewFile(uintptr(fd), name)
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		_ = unix.Unlinkat(dir, name, 0)
		return -1, err
	}
	nfd, err := unix.Dup(fd)
	_ = out.Close()
	if err != nil {
		_ = unix.Unlinkat(dir, name, 0)
	}
	return nfd, err
}

// kernelIsRoots refuses a kernel the agent could swap: each folder above it
// root's and closed to others, the file root's own regular file.
func (f *firecrackerHosts) kernelIsRoots(path string) error {
	dfd, err := walkFolder(filepath.Dir(path), false, func(at string, st *unix.Stat_t, _ bool) error {
		return rootfolder.CheckFolder(at, uint32(st.Mode), st.Uid, 0, false)
	})
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o022 != 0 {
		return fmt.Errorf("want a regular file of root's that no one else can write (uid %d, mode %o)", st.Uid, st.Mode&0o7777)
	}
	return nil
}

// shareSocket gives a socket firecracker bound in the chroot to the agent's
// group, 0660. Through an O_PATH handle on the name, never following a
// link, and only when it is a socket: firecracker owns the chroot and
// could put anything at the name.
func (f *firecrackerHosts) shareSocket(root int, name string) error {
	fd, err := pathHandle(root, name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("%s is not a socket", name)
	}
	return chmodPath(fd, f.agentGID, 0o660)
}

// command runs only when no process runs in the VM's group (spawnHost
// checks under the VM's lock), so the jailer always gets a chroot made
// again from nothing, with the helper's kernel and no name a VM before it
// left there: not even an old API socket, which firecracker will not bind
// over.
func (f *firecrackerHosts) command(_ context.Context, id string, _ *rootdpb.SpawnHostRequest) (*exec.Cmd, func(), error) {
	dir, _, _, err := f.jail(id)
	if err != nil {
		return nil, nil, err
	}
	fd, err := openFolderNoMake(dir)
	if err != nil {
		return nil, nil, &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf("root helper: Firecracker VM %s has no jail; PrepareHost first", id)}
	}
	_ = unix.Close(fd)
	stage, root, err := f.openJail(id, true)
	if err != nil {
		return nil, nil, err
	}
	_ = stage.Close()
	defer root.Close()
	if err := f.stageKernel(int(root.Fd())); err != nil {
		return nil, nil, err
	}
	out, err := hostLog(f.log)
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: hosts' log %s: %w", f.log, err)
	}
	cmd := exec.Command(f.cfg.Shim, firecrackerJailerArgs(f.cfg, id)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = out, out
	return cmd, func() { _ = out.Close() }, nil
}

// firecrackerJailerArgs are the shim's arguments: the jailer and its
// argv, as single mode's jailerArgv builds them, from the helper's
// settings and the checked sandbox ID.
func firecrackerJailerArgs(c *FirecrackerHostsConfig, id string) []string {
	return []string{FirecrackerJailerExecFlag, c.JailerBinary,
		"--id", id,
		"--exec-file", c.FirecrackerBinary,
		"--uid", strconv.Itoa(c.UID),
		"--gid", strconv.Itoa(c.GID),
		"--chroot-base-dir", c.ChrootBase,
		"--",
		"--api-sock", firecrackerAPISocket,
	}
}

func (f *firecrackerHosts) socket(string) string { return "" }

// limits: a VM's memory and CPUs are its machine config, as in single mode.
func (f *firecrackerHosts) limits(l rootpolicy.HostLimits) (rootpolicy.HostLimits, bool) {
	return l, false
}

// started waits until firecracker has bound its API socket in the chroot,
// then gives it to the agent's group.
func (f *firecrackerHosts) started(ctx context.Context, cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	id := firecrackerIDOf(cmd)
	_, rootPath, _, err := f.jail(id)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(f.cfg.SocketWait)
	for {
		rfd, err := openFolderNoMake(rootPath)
		if err == nil {
			var st unix.Stat_t
			err = unix.Fstatat(rfd, firecrackerAPISocket, &st, unix.AT_SYMLINK_NOFOLLOW)
			_ = unix.Close(rfd)
		}
		if err == nil {
			// The jailer owns the chroot it set up: give its folder back
			// to the agent's group to pass through, then the socket.
			stage, root, jerr := f.openJail(id, false)
			if jerr != nil {
				return jerr
			}
			_ = stage.Close()
			err = f.shareSocket(int(root.Fd()), firecrackerAPISocket)
			_ = root.Close()
			if err == nil {
				return nil
			}
		}
		if !errors.Is(err, unix.ENOENT) || time.Now().After(deadline) {
			return fmt.Errorf("root helper: Firecracker VM %s did not bind its API socket within %s: %w (its output is in %s)",
				id, f.cfg.SocketWait, err, f.log)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(socketPoll):
		}
	}
}

// socketPoll paces started's look for the API socket. firecracker binds it
// some 10 ms after the jailer starts; a 10 ms poll then often saw it only
// at 20 ms (M1 PR 14b's box timing), on every create and load. Each look
// is two syscalls.
const socketPoll = 2 * time.Millisecond

// RunFirecrackerJailerShim is the helper's own binary as the jailer's shim:
// it sets firecracker's umask (the jailer and firecracker keep the one
// they are started with) and becomes the jailer, args[0], with args. The
// helper alone starts it, with argv built from its own settings.
func RunFirecrackerJailerShim(args []string) error {
	if len(args) == 0 || !filepath.IsAbs(args[0]) {
		return errors.New("jailer shim: want the jailer's absolute path and its arguments")
	}
	unix.Umask(FirecrackerShimUmask)
	return unix.Exec(args[0], args, os.Environ())
}

// firecrackerIDOf reads the sandbox ID back from a command this launcher
// built.
func firecrackerIDOf(cmd *exec.Cmd) string {
	for i, a := range cmd.Args {
		if a == "--id" && i+1 < len(cmd.Args) {
			return cmd.Args[i+1]
		}
	}
	return ""
}

// teardown removes the VM's jail: its disks, its sockets and what the
// jailer made. os.RemoveAll follows no link.
func (f *firecrackerHosts) teardown(id string) error {
	dir, _, _, err := f.jail(id)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	pfd, err := openFolder(filepath.Dir(dir))
	if err != nil {
		return err
	}
	_ = unix.Close(pfd)
	return os.RemoveAll(dir)
}

// present lists the VMs whose jails are on disk.
func (f *firecrackerHosts) present() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(f.cfg.ChrootBase, "firecracker"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && rootpolicy.CheckHostID(rootpolicy.HostFirecracker, e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// openFolderNoMake opens a folder of the helper's without making it.
func openFolderNoMake(dir string) (int, error) {
	return walkFolder(dir, false, func(string, *unix.Stat_t, bool) error { return nil })
}

// makeFilesystem makes an ext4 filesystem in one of a VM's disk files in
// its stage folder, as the agent's own user mapped to root in a user
// namespace of its own (makeFilesystemAttr): the files come out root's in
// the image, as single mode's root mkfs makes them, and mkfs.ext4 can read
// and write nothing the agent could not.
func (f *firecrackerHosts) makeFilesystem(ctx context.Context, req *rootdpb.MakeFilesystemRequest) (*rootdpb.MakeFilesystemResponse, error) {
	if err := rootpolicy.CheckHostID(rootpolicy.HostFirecracker, req.GetId()); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	if err := rootpolicy.CheckFirecrackerFile(req.GetName()); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	src := req.GetSource()
	if src != "" {
		if !filepath.IsAbs(src) || filepath.Clean(src) != src {
			return nil, badRequest("root helper: filesystem source %q: want a clean absolute folder", src)
		}
		if err := rootpolicy.CheckFilesystemSize(req.GetSizeMib()); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
	} else if req.GetSizeMib() != 0 {
		return nil, badRequest("root helper: an empty filesystem takes its file's size, not a size")
	}
	stage, root, err := f.openJail(req.GetId(), false)
	if err != nil {
		return nil, err
	}
	_ = root.Close()
	defer stage.Close()
	// The out file is named through the stage folder the helper opened:
	// the agent owns the folder, never the path to it.
	out := fmt.Sprintf("/proc/self/fd/%d/%s", 3, req.GetName())
	cmd := exec.CommandContext(ctx, f.cfg.Mkfs4Bin, mkfsArgs(out, src, req.GetSizeMib())...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{stage}
	if err := makeFilesystemAttr(cmd, f.cfg.AgentUID, f.agentGID); err != nil {
		return nil, err
	}
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, &fileError{code: codes.InvalidArgument, reason: ReasonBadRequest,
			msg: fmt.Sprintf("root helper: mkfs.ext4 %s for %s: %v: %s", req.GetName(), req.GetId(), err, tail(b))}
	}
	return &rootdpb.MakeFilesystemResponse{}, nil
}

// mkfsArgs are mkfs.ext4's arguments for an ext4 filesystem in out: empty,
// in out's own size, or, with src, holding src's files in sizeMib. -t ext4
// because mke2fs picks ext4 by its own name only when called mkfs.ext4,
// and SB_FIRECRACKER_MKFS_BIN may name mke2fs itself (the file `readlink
// -f` prints for mkfs.ext4 on Ubuntu and Debian).
func mkfsArgs(out, src string, sizeMib uint64) []string {
	if src == "" {
		return []string{"-t", "ext4", "-F", out}
	}
	return []string{"-t", "ext4", "-d", src, "-F", out, strconv.FormatUint(sizeMib, 10) + "M"}
}

// tail is the end of a tool's output, for an error.
func tail(b []byte) string {
	const keep = 512
	if len(b) > keep {
		b = b[len(b)-keep:]
	}
	return string(b)
}
