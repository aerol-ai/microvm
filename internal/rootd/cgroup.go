package rootd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// Part "cgroup" of PrepareSandbox (M1 PR 6; finding F10 of the Kubernetes
// plan): the helper makes a started sandbox's group the kernel's whole
// out-of-memory choice, the two settings sandboxd writes itself in
// privilege mode single (internal/runtime/containerd markWholeOOMVictim):
//
//   - memory.oom.group 1 on the sandbox's group, so an out-of-memory kill
//     takes every process in it at once: a gVisor sandbox's memory is one
//     file several of its processes share, and killing one frees nothing;
//   - OOM score 500 on every process in the group and below it, so the
//     kernel picks a sandbox before the machinery, which runs at -999.
//     gVisor's processes inherit the shim's score, not the spec's.
//
// Only the group's own memory.oom.group is written, never a group above
// it: the worker's supervisor keeps those at 0, so one event never takes
// the machinery or another sandbox.
//
// The part comes alone. runc or runsc makes a sandbox's group with its
// task, after the namespace and rules of the create's first PrepareSandbox,
// and the processes to mark exist only once the task runs. So the agent
// sends it right after the task starts and again once the sandbox
// answers (gVisor starts some processes after Start returns), at the same
// two points single mode writes the same values.
//
// The agent names the container; the helper builds the path from its own
// parent (SB_CONTAINERD_CGROUP_PARENT) and refuses a name the machinery
// keeps (rootpolicy.SandboxCgroup) and a group that holds the helper itself
// (rootpolicy.CheckSparesHelper, from what /proc/self/cgroup says). Which
// sandbox a container ID means is the agent's bookkeeping (plan R9):
// naming another sandbox writes the values that sandbox already has.
//
// Each pid listed in the group's cgroup.procs is opened as its /proc
// folder, and the helper checks there that the process is still in the
// group before it writes the score through that same open folder. A pid
// that exited and went to another process meanwhile is a different folder,
// so the helper never raises the score of anything outside the group.

// The kernel's mounts the part reads and writes. Options overrides them
// for tests.
const (
	defaultCgroupRoot = "/sys/fs/cgroup"
	defaultProcRoot   = "/proc"
)

// sandboxCgroups serves part "cgroup"; nil when the helper has no cgroup
// parent, and then it does not list the part.
type sandboxCgroups struct {
	parent string
	root   string
	proc   string
	locks  *keyedLocks

	selfOnce sync.Once
	self     string
	selfErr  error
}

func newSandboxCgroups(cfg Config, opts Options, locks *keyedLocks) *sandboxCgroups {
	if cfg.Policy.CgroupParent == "" {
		return nil
	}
	c := &sandboxCgroups{parent: cfg.Policy.CgroupParent, root: defaultCgroupRoot, proc: defaultProcRoot, locks: locks}
	if opts.CgroupRoot != "" {
		c.root = opts.CgroupRoot
	}
	if opts.ProcRoot != "" {
		c.proc = opts.ProcRoot
	}
	return c
}

// helperGroup is the helper's own cgroup v2 path, read once: the
// supervisor starts the helper in its group and it never moves.
func (c *sandboxCgroups) helperGroup() (string, error) {
	c.selfOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join(c.proc, "self", "cgroup"))
		if err != nil {
			c.selfErr = fmt.Errorf("root helper: read its own cgroup: %w", err)
			return
		}
		var ok bool
		if c.self, ok = rootpolicy.CgroupV2Path(string(raw)); !ok {
			c.selfErr = errors.New("root helper: its own cgroup has no cgroup v2 path; sandbox groups need cgroup v2")
		}
	})
	return c.self, c.selfErr
}

func (c *sandboxCgroups) prepare(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	if req.GetNetnsName() != "" || req.GetContainerIp() != "" || req.GetFirewall() != nil {
		return nil, badRequest("root helper: the cgroup part comes alone: a sandbox's group is made with its task, after its namespace and rules")
	}
	if req.GetCgroup() == nil {
		return nil, badRequest("root helper: the cgroup part names no container")
	}
	id := req.GetCgroup().GetContainerId()
	group, err := rootpolicy.SandboxCgroup(c.parent, id)
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	self, err := c.helperGroup()
	if err != nil {
		return nil, err
	}
	if err := rootpolicy.CheckSparesHelper(group, self); err != nil {
		return nil, refusedRule(codes.PermissionDenied, err)
	}
	// D11: the container's calls run in order, as its files' calls do.
	unlock, err := c.locks.lock(ctx, containerKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := c.markWhole(ctx, group); err != nil {
		return nil, err
	}
	return &rootdpb.PrepareSandboxResponse{}, nil
}

// markWhole writes the two settings. A group that is gone fails with
// NotFound: the sandbox died while it started, and the agent's create
// fails, as in single mode.
func (c *sandboxCgroups) markWhole(ctx context.Context, group string) error {
	dir := filepath.Join(c.root, filepath.FromSlash(group))
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &fileError{code: codes.NotFound, msg: fmt.Sprintf("root helper: sandbox cgroup %s is gone: its task is not running", group)}
	case err != nil:
		return fmt.Errorf("root helper: sandbox cgroup %s: %w", group, err)
	case !fi.IsDir():
		return fmt.Errorf("root helper: sandbox cgroup %s is not a group", group)
	}
	if err := writeExisting(filepath.Join(dir, "memory.oom.group"), "1"); err != nil {
		return fmt.Errorf("root helper: sandbox cgroup %s: set memory.oom.group: %w", group, err)
	}
	score := strconv.Itoa(rootpolicy.SandboxOOMScoreAdj)
	return filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("root helper: sandbox cgroup %s: %w", group, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !e.IsDir() {
			return nil
		}
		procs, err := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if err != nil {
			return fmt.Errorf("root helper: sandbox cgroup %s: read cgroup.procs: %w", group, err)
		}
		for _, pid := range strings.Fields(string(procs)) {
			if err := c.markProcess(pid, group, score); err != nil {
				return fmt.Errorf("root helper: sandbox cgroup %s: set OOM score of pid %s: %w", group, pid, err)
			}
		}
		return nil
	})
}

// markProcess writes score to one process's OOM score, through its /proc
// folder held open, once that folder says the process is in group. A
// process that has exited, or that is in another group now, is left.
func (c *sandboxCgroups) markProcess(pid, group, score string) error {
	if n, err := strconv.ParseUint(pid, 10, 31); err != nil || n == 0 {
		// cgroup.procs lists the pids this pid namespace sees; 0 is a
		// process it cannot see, and nothing else is a pid.
		if err == nil {
			return nil
		}
		return fmt.Errorf("not a pid: %q", pid)
	}
	r, err := os.OpenRoot(filepath.Join(c.proc, pid))
	if err != nil {
		return ignoreExited(err)
	}
	defer func() { _ = r.Close() }()
	raw, err := r.ReadFile("cgroup")
	if err != nil {
		return ignoreExited(err)
	}
	if cg, ok := rootpolicy.CgroupV2Path(string(raw)); !ok || !rootpolicy.InGroup(cg, group) {
		return nil
	}
	f, err := r.OpenFile("oom_score_adj", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return ignoreExited(err)
	}
	_, err = f.WriteString(score)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return ignoreExited(err)
}

// ignoreExited: a process that has already exited is not a victim to mark.
func ignoreExited(err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// writeExisting writes value to a file that must exist: a cgroup's
// interface file, never one the helper would make. O_TRUNC, as a shell's
// redirect and os.WriteFile open it: the kernel's files take it.
func writeExisting(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
