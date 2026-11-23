package rootd

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// A Firecracker VM's memory and state files and its disks (M1 PR 14b):
// ShareFirecrackerFiles and HandOutFirecrackerFiles. In privilege mode
// single sandboxd is root and moves these files as it likes. In split it is
// not: firecracker runs as the jailer's user in a chroot that user owns,
// and writes its snapshots there; sandboxd keeps its saved snapshots and
// templates in folders of its own. So the helper hands files across, by
// group and mode alone, and never gives a file to another owner:
//
//   - Into a VM (share), read-only: a snapshot's memory and state and a
//     template's root disk. The agent links its own file into the VM's
//     stage folder; the helper opens it there with no link followed,
//     checks it is the agent's regular file within the cap, gives it the
//     jailer's group and mode 0640 through that handle, and links that
//     very file into the chroot (checked again after the link). It stays
//     the agent's: the jailer's user reads it and cannot write it, so no
//     VM can change a template every later VM loads. It may have other
//     names (the agent's saved copy, other VMs of the same template); only
//     its owner and its group's read are what the helper vouches for.
//   - Out of a VM (hand out), read-only: what firecracker wrote (a
//     snapshot's memory and state) and the VM's disks. The helper opens
//     each in the chroot with no link followed and checks it is a regular
//     file of the jailer's user with one name, within the cap; then it
//     gives it the agent's group and mode 0640 through that handle. The
//     owner stays the jailer's user, so a VM that resumes after a failed
//     stop keeps its disks as they were. The agent copies the file out
//     into a file of its own, with the same checks on its side. A file the
//     helper shared in is the agent's already: it is left as it is.
//   - Writable disks go in through PrepareHost's stage list, as the
//     jailer's (hosts_firecracker.go stageDisk), as for a cold boot.
//
// No path from a request reaches a file call: a request names a VM, which
// rootpolicy checks, and files from a fixed list; the helper builds every
// path from its own settings and opens each name through a folder handle.
// Nothing the jailer's user or the agent can write is ever followed as a
// link by root, and a file's content is never trusted by root: only the
// VM reads a snapshot, and only the agent copies and hashes it.

// firecrackerFileFeatures are the calls the helper lists when it serves
// Firecracker.
var firecrackerFileFeatures = []string{rootdpb.FeatureShareFirecrackerFiles, rootdpb.FeatureHandOutFirecrackerFiles}

// firecrackerFiles checks a files call's VM and names, takes the VM's
// lock, and answers whether its process runs.
func (h *hostCalls) firecrackerFiles(ctx context.Context, req *rootdpb.FirecrackerFilesRequest, check func(string) error) (func(), bool, error) {
	if err := rootpolicy.CheckHostID(rootpolicy.HostFirecracker, req.GetId()); err != nil {
		return nil, false, refusedRule(codes.InvalidArgument, err)
	}
	if err := rootpolicy.CheckFirecrackerNames(req.GetNames(), check); err != nil {
		return nil, false, refusedRule(codes.InvalidArgument, err)
	}
	unlock, err := h.locks.lock(ctx, hostKey(rootpolicy.HostFirecracker, req.GetId()))
	if err != nil {
		return nil, false, err
	}
	pid, _, err := h.running(rootpolicy.HostGroup(rootpolicy.HostFirecracker, req.GetId()))
	if err != nil {
		unlock()
		return nil, false, err
	}
	return unlock, pid > 0, nil
}

func (h *hostCalls) shareFirecrackerFiles(ctx context.Context, req *rootdpb.FirecrackerFilesRequest) (*rootdpb.FirecrackerFilesResponse, error) {
	unlock, running, err := h.firecrackerFiles(ctx, req, rootpolicy.CheckFirecrackerShare)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// A chroot with no process in its group is made again from nothing
	// before the jailer starts, so a file shared now would be gone.
	if !running {
		return nil, &fileError{code: codes.FailedPrecondition,
			msg: fmt.Sprintf("root helper: Firecracker VM %s runs no process; files go into its chroot once it runs", req.GetId())}
	}
	if err := h.firecracker().share(req.GetId(), req.GetNames()); err != nil {
		return nil, err
	}
	return &rootdpb.FirecrackerFilesResponse{}, nil
}

func (h *hostCalls) handOutFirecrackerFiles(ctx context.Context, req *rootdpb.FirecrackerFilesRequest) (*rootdpb.FirecrackerFilesResponse, error) {
	unlock, _, err := h.firecrackerFiles(ctx, req, rootpolicy.CheckFirecrackerHandOut)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := h.firecracker().handOut(req.GetId(), req.GetNames()); err != nil {
		return nil, err
	}
	return &rootdpb.FirecrackerFilesResponse{}, nil
}

// share links each named file the agent built in the VM's stage folder
// into its chroot, read-only for the jailer's group.
func (f *firecrackerHosts) share(id string, names []string) error {
	stage, root, err := f.openJail(id, false)
	if err != nil {
		return err
	}
	defer stage.Close()
	defer root.Close()
	for _, name := range names {
		if err := f.shareFile(int(stage.Fd()), int(root.Fd()), name); err != nil {
			return err
		}
	}
	return nil
}

// sharedMode is a shared file's mode: its owner (the agent) reads and
// writes it, the jailer's group reads it, others nothing.
const sharedMode = 0o640

func (f *firecrackerHosts) shareFile(stage, root int, name string) error {
	fd, err := unix.Openat(stage, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		var st unix.Stat_t
		if unix.Fstatat(root, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && f.isShared(&st) {
			return nil // shared by an earlier call
		}
		return badRequest("root helper: Firecracker file %s is not in the stage folder", name)
	}
	if err != nil {
		return badRequest("root helper: Firecracker file %s: %v", name, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return badRequest("root helper: Firecracker file %s is not a regular file", name)
	case st.Uid != f.cfg.AgentUID:
		return badRequest("root helper: Firecracker file %s belongs to uid %d, not the agent", name, st.Uid)
	case st.Size < 0 || st.Size > rootpolicy.MaxFirecrackerFileBytes:
		return badRequest("root helper: Firecracker file %s is %d bytes; at most %d", name, st.Size, rootpolicy.MaxFirecrackerFileBytes)
	}
	// Group and mode first, through the handle: the file is readable by
	// the jailer's user, and writable by it never, before it has a name
	// in the chroot.
	if err := f.fchown(fd, -1, f.cfg.GID); err != nil {
		return err
	}
	if err := fchmodAny(fd, sharedMode); err != nil {
		return err
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
		return badRequest("root helper: Firecracker file %s changed while it was shared", name)
	}
	_ = unix.Unlinkat(stage, name, 0)
	return nil
}

// isShared: a file the helper shared into a chroot, as it left it.
func (f *firecrackerHosts) isShared(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == f.cfg.AgentUID && int64(st.Gid) == int64(f.cfg.GID) &&
		st.Mode&0o7777 == sharedMode
}

// handOut lets the agent's group read each named file in the VM's chroot.
// The chroot must be there; nothing is made.
func (f *firecrackerHosts) handOut(id string, names []string) error {
	_, rootPath, _, err := f.jail(id)
	if err != nil {
		return err
	}
	root, err := openFolderNoMake(rootPath)
	if err != nil {
		return &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf("root helper: Firecracker VM %s has no chroot to hand files out of", id)}
	}
	defer unix.Close(root)
	for _, name := range names {
		if err := f.handOutFile(root, name); err != nil {
			return err
		}
	}
	return nil
}

func (f *firecrackerHosts) handOutFile(root int, name string) error {
	fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return badRequest("root helper: Firecracker file %s in the chroot: %v", name, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return badRequest("root helper: Firecracker file %s in the chroot is not a regular file", name)
	case st.Size < 0 || st.Size > rootpolicy.MaxFirecrackerFileBytes:
		return badRequest("root helper: Firecracker file %s in the chroot is %d bytes; at most %d", name, st.Size, rootpolicy.MaxFirecrackerFileBytes)
	case f.isShared(&st):
		return nil // the agent's own, shared in by the helper
	case int64(st.Uid) != int64(f.cfg.UID):
		return badRequest("root helper: Firecracker file %s in the chroot belongs to uid %d, not the jailer's user", name, st.Uid)
	case st.Nlink != 1:
		return badRequest("root helper: Firecracker file %s in the chroot has %d names; want its own file", name, st.Nlink)
	}
	if err := f.fchown(fd, -1, f.agentGID); err != nil {
		return err
	}
	return fchmodAny(fd, sharedMode)
}
