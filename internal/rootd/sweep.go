package rootd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The helper sweeps its own container folders (hosts, ready names, FIFOs)
// of containers containerd no longer has. The agent removes a container's
// files when it destroys the container or undoes a failed create
// (ReleaseSandbox's files part), but a crash between the create's files
// and its container, or a destroy while the helper was down, leaves a
// folder nothing names again. The helper keeps no list of its own: it
// reads containerd's (plan §3.3, "The helper keeps no state").
//
// A container's files are made just before the container (PrepareSandbox),
// so a folder with no container may be a create in flight. Only folders
// that no call changed for sweepGrace go: every create and start makes
// fresh FIFOs (a rename in the container's FIFO folder), so a folder in
// use is never that old. The sweep takes each container's lock, as every
// call for it does (D11).

// ContainerLister lists the containers in the helper's containerd
// namespace (Options.Containers). The helper's main wires containerd's own
// list; tests a fake.
type ContainerLister interface {
	ContainerIDs(ctx context.Context) (map[string]bool, error)
}

// Sweep timing: the first sweep after start, then one an hour, and the age
// a folder must reach before it goes. Vars for tests.
var (
	sweepFirst = 5 * time.Minute
	sweepEvery = time.Hour
	sweepGrace = 10 * time.Minute
)

// SweepContainerFiles removes the files of every container the lister no
// longer has whose folders are older than grace, and returns the IDs it
// removed.
func (s *Server) SweepContainerFiles(ctx context.Context, lister ContainerLister, grace time.Duration) ([]string, error) {
	ids, err := s.files.containerIDs()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	live, err := lister.ContainerIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("root helper: list containers: %w", err)
	}
	var removed []string
	cutoff := time.Now().Add(-grace)
	for _, id := range ids {
		if live[id] {
			continue
		}
		unlock, err := s.locks.lock(ctx, containerKey(id))
		if err != nil {
			return removed, err
		}
		if s.files.newestChange(id).Before(cutoff) {
			if _, err := s.files.removeContainerFiles(&rootdpb.RemoveContainerFilesRequest{ContainerId: id}); err == nil {
				removed = append(removed, id)
			} else {
				s.log.Warn("root helper: sweep: could not remove a gone container's files", "container_id", id, "error", err)
			}
		}
		unlock()
	}
	return removed, nil
}

// SweepMoves removes the move folders a crash left behind (moves.go): a
// staged bundle older than grace, and a saved checkpoint older than grace
// whose container the lister no longer has. It returns the sandboxes whose
// folders it removed; none when this helper takes no moves.
func (s *Server) SweepMoves(ctx context.Context, lister ContainerLister, grace time.Duration) ([]string, error) {
	if s.moves == nil {
		return nil, nil
	}
	live, err := lister.ContainerIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("root helper: list containers: %w", err)
	}
	return s.moves.sweep(ctx, live, grace), nil
}

// sweepLoop sweeps on sweepFirst, then every sweepEvery, until ctx ends.
func (s *Server) sweepLoop(ctx context.Context, lister ContainerLister) {
	t := time.NewTimer(sweepFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		removed, err := s.SweepContainerFiles(ctx, lister, sweepGrace)
		switch {
		case err != nil && ctx.Err() == nil:
			s.log.Warn("root helper: sweep of gone containers' files failed", "error", err)
		case len(removed) > 0:
			s.log.Info("root helper: removed gone containers' files", "containers", len(removed))
		}
		if moved, err := s.SweepMoves(ctx, lister, moveSweepGrace); err != nil && ctx.Err() == nil {
			s.log.Warn("root helper: sweep of old move folders failed", "error", err)
		} else if len(moved) > 0 {
			s.log.Info("root helper: removed old move folders", "sandboxes", len(moved))
		}
		t.Reset(sweepEvery)
	}
}

// containerIDs lists the container folders in the helper's folders, each
// name once; a name that is no container ID (a temporary name) is left.
func (f *files) containerIDs() ([]string, error) {
	var out []string
	for _, base := range []int{f.hosts, f.ready, f.fifo} {
		names, err := folderNames(base)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if rootpolicy.ValidateID(n) == nil && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// newestChange is when anything last changed in a container's folders:
// the newest change time among them. A folder that is not there counts as
// never changed.
func (f *files) newestChange(id string) time.Time {
	var newest time.Time
	for _, base := range []int{f.hosts, f.ready, f.fifo} {
		var st unix.Stat_t
		if err := unix.Fstatat(base, id, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		for _, ts := range []unix.Timespec{st.Mtim, st.Ctim} {
			if t := time.Unix(ts.Unix()); t.After(newest) {
				newest = t
			}
		}
	}
	return newest
}

// folderNames lists the names in the open folder fd.
func folderNames(fd int) ([]string, error) {
	dfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(dfd), ".")
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return names, nil
}
