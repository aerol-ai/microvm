package supervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// HelperGroup is the cgroup the root helper runs in, alone: aerolvm-rootd,
// inside the runtime's group (Layout.HelperDir). The helper starts in it
// from its first instruction (StartHelper, CLONE_INTO_CGROUP), so all it
// starts is in it too: a CNI plugin, and the IPAM plugin that plugin runs
// in turn. Those can outlive the helper. A crash, an out-of-memory kill or
// the keeper's SIGKILL ends the helper alone, and a call cut by the drain's
// deadline kills at most the child it ran, never that child's own. The
// exclusive handover (HelperKeeper) needs every one of them gone, so to the
// keeper a helper has stopped only once its group is empty.
//
// Helpers never run at once, so one group serves them all. Nothing else is
// ever put in it: containerd, and so every shim, runs in the runtime's
// group itself, and the gate puts each sandbox directly under the
// sandboxes' parent (rootpolicy's cgroup rule), two levels above this one.
// Whatever a helper starts that must outlive it (a sandbox's host process
// or mount, plan §3.3 "Failure rules") must go in a group of its own, never
// stay in this one: the keeper kills all that is left here.
//
// The group holds processes beside a parent that holds processes too
// (containerd). cgroup v2's no-internal-process rule allows that while the
// parent hands no controller down: what it forbids is a group with
// processes of its own enabling a domain controller in
// cgroup.subtree_control, and the runtime's group enables none. So this
// group has no controller of its own, and the helper's memory, CPU and pids
// count in the runtime's group, inside sandboxes/'s cap, exactly as when it
// ran there. cgroup.kill, cgroup.freeze, cgroup.events and cgroup.procs are
// core files, in every group whatever its controllers.
type HelperGroup interface {
	// Empty makes the group if it is missing and returns once it holds no
	// process, killing whatever is left in it; an error when it could not
	// be emptied in a bounded time. Never called while a helper runs.
	Empty() error
	// Remove removes the group, once empty, as the supervisor stops.
	Remove() error
}

const (
	// helperGroupWait bounds one Empty. A SIGKILL ends a process as it
	// next leaves the kernel; one asleep there where nothing can wake it
	// (a hung NFS read, say) dies only when that ends. Empty then fails
	// rather than wait on: the keeper tries again with a growing wait, and
	// no helper starts meanwhile.
	helperGroupWait = 5 * time.Second
	// helperGroupPoll paces Empty's reads of cgroup.events.
	helperGroupPoll = 5 * time.Millisecond
	// helperFreezeWait bounds killEach's wait for the freeze to take hold.
	helperFreezeWait = 100 * time.Millisecond
)

// NewHelperGroup is the kernel's HelperGroup at dir, on a cgroup v2 mount.
func NewHelperGroup(dir string) HelperGroup {
	return &helperCgroup{
		dir: dir, wait: helperGroupWait, poll: helperGroupPoll, freezeWait: helperFreezeWait,
		read:    func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) },
		write:   func(name, value string) error { return writeCgroupFile(filepath.Join(dir, name), value) },
		mkdir:   func() error { return os.Mkdir(dir, 0o755) },
		rmdir:   func() error { return os.Remove(dir) },
		openPid: openPidfd,
	}
}

// helperCgroup is a HelperGroup on the kernel's files.
type helperCgroup struct {
	dir string
	// wait bounds one Empty; poll paces its reads; freezeWait bounds the
	// wait for a freeze to take hold.
	wait, poll, freezeWait time.Duration
	// The group's files by name, the group itself, and a process held by
	// pidfd: the kernel's, replaced in tests.
	read    func(name string) ([]byte, error)
	write   func(name, value string) error
	mkdir   func() error
	rmdir   func() error
	openPid func(pid int) (pidHandle, error)
	// noKillFile is set once cgroup.kill is found missing (Linux before
	// 5.14), so later kills go straight to killEach.
	noKillFile bool
}

// pidHandle is one process held by pidfd: a signal through it reaches that
// process or none, never one that took its pid after it was reaped.
type pidHandle interface {
	Kill() error
	Close() error
}

func (g *helperCgroup) Empty() error {
	if err := g.mkdir(); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("make the root helper's cgroup %s: %w", g.dir, err)
	}
	// A group left frozen (a supervisor stopped inside killEach) would
	// freeze the next helper from its first instruction.
	if err := g.thawIfFrozen(); err != nil {
		return err
	}
	deadline := time.Now().Add(g.wait)
	for {
		populated, err := g.event("populated")
		if err != nil || !populated {
			return err
		}
		if time.Now().After(deadline) {
			pids, _ := g.procs()
			return fmt.Errorf("the root helper's cgroup %s still holds processes %v after %v", g.dir, pids, g.wait)
		}
		if err := g.kill(); err != nil {
			return err
		}
		time.Sleep(g.poll)
	}
}

func (g *helperCgroup) Remove() error {
	if err := g.rmdir(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the root helper's cgroup %s: %w", g.dir, err)
	}
	return nil
}

// kill sends SIGKILL to every process in the group. cgroup.kill does it in
// the kernel, for the whole group at once, forks under way included (Linux
// 5.14); before that killEach does it by hand.
func (g *helperCgroup) kill() error {
	if !g.noKillFile {
		err := g.write("cgroup.kill", "1")
		if !errors.Is(err, fs.ErrNotExist) {
			if err != nil {
				return fmt.Errorf("kill the root helper's cgroup %s: %w", g.dir, err)
			}
			return nil
		}
		g.noKillFile = true
	}
	return g.killEach()
}

// killEach is cgroup.kill by hand: it freezes the group, so nothing in it
// forks while the list is read, sends SIGKILL to each process listed (a
// frozen process dies of it too), and thaws the group. Each process is
// held by pidfd and signalled only if the list still names it after it
// was held, so the signal never reaches a process that took the pid of one
// that died meanwhile: the supervisor reaps the helper's orphans, so a pid
// can go free and be taken at any time. One forked before the freeze took
// hold is caught by the next pass: Empty repeats until the group is empty.
func (g *helperCgroup) killEach() (err error) {
	if err := g.write("cgroup.freeze", "1"); err != nil {
		return fmt.Errorf("freeze the root helper's cgroup %s: %w", g.dir, err)
	}
	defer func() {
		if terr := g.write("cgroup.freeze", "0"); terr != nil && err == nil {
			err = fmt.Errorf("thaw the root helper's cgroup %s: %w", g.dir, terr)
		}
	}()
	// A process asleep in the kernel freezes only as it leaves it; the
	// kill is sent either way, so the wait is short.
	for until := time.Now().Add(g.freezeWait); time.Now().Before(until); time.Sleep(g.poll) {
		if frozen, ferr := g.event("frozen"); ferr != nil || frozen {
			break
		}
	}
	pids, err := g.procs()
	if err != nil {
		return err
	}
	held := make(map[int]pidHandle, len(pids))
	defer func() {
		for _, p := range held {
			_ = p.Close()
		}
	}()
	for _, pid := range pids {
		if p, oerr := g.openPid(pid); oerr == nil { // an error: it is gone
			held[pid] = p
		}
	}
	still, err := g.procs()
	if err != nil {
		return err
	}
	for _, pid := range still {
		if p, ok := held[pid]; ok {
			_ = p.Kill()
		}
	}
	return nil
}

// thawIfFrozen thaws a group whose own cgroup.freeze says frozen. A kernel
// with no freezer (no file) has nothing to thaw.
func (g *helperCgroup) thawIfFrozen() error {
	raw, err := g.read("cgroup.freeze")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("read the root helper's cgroup %s: %w", g.dir, err)
	case strings.TrimSpace(string(raw)) != "1":
		return nil
	}
	if err := g.write("cgroup.freeze", "0"); err != nil {
		return fmt.Errorf("thaw the root helper's cgroup %s: %w", g.dir, err)
	}
	return nil
}

// event reads one key of cgroup.events: "populated 1" while the group or
// one below it holds a process, "frozen 1" once a freeze took hold.
func (g *helperCgroup) event(key string) (bool, error) {
	raw, err := g.read("cgroup.events")
	if err != nil {
		return false, fmt.Errorf("read the root helper's cgroup %s: %w", g.dir, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok && k == key {
			return v == "1", nil
		}
	}
	return false, fmt.Errorf("the root helper's cgroup %s: cgroup.events has no %q", g.dir, key)
}

// procs lists the processes in the group itself.
func (g *helperCgroup) procs() ([]int, error) {
	raw, err := g.read("cgroup.procs")
	if err != nil {
		return nil, fmt.Errorf("list the root helper's cgroup %s: %w", g.dir, err)
	}
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		if pid, err := strconv.Atoi(f); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// writeCgroupFile writes one value to a cgroup file that must be there
// already. A cgroup mount makes no file, so a missing one is a kernel that
// lacks it (ENOENT), not the EACCES that creating it would give.
func writeCgroupFile(p, value string) error {
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
