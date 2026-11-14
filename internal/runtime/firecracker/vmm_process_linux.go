//go:build linux

package firecracker

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
)

// vmmCgroupRoot is the cgroup v2 mount and procRoot is procfs. Vars so
// tests can stand in directories.
var (
	vmmCgroupRoot = "/sys/fs/cgroup"
	procRoot      = "/proc"
)

// vmmCgroupDir is the VMs' cgroup directory: <mount>/<parent>/aerolvm-vmm.
func vmmCgroupDir() string {
	return filepath.Join(vmmCgroupRoot, currentVMMCgroupParent(), vmmCgroupName)
}

// moveToVMMCgroup moves a VMM out of sandboxd's cgroup into a group of its
// own, <VMs' cgroup>/<group> (group is the sandbox's ID, or a warm slot's).
// systemd stops a unit by killing every process in the unit's cgroup
// (KillMode=control-group); a VM left there dies with every sandboxd restart
// or upgrade. Docker's containers live outside dockerd's unit the same way.
// One group per VM is what lets the ownership lease freeze one sandbox's VM
// and no other (Driver.Freeze; the runtime supervisor, FenceGroup): the VMs'
// cgroup is shared. A VM that was in another VM group (a warm slot's, or one
// a release before this left in the VMs' cgroup itself) moves, and an
// emptied child group is removed. cgroup v2 only: on a v1 host the VM stays
// where it is and a restart still takes it, as before.
func moveToVMMCgroup(pid int, group string) error {
	if _, err := os.Stat(filepath.Join(vmmCgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("no cgroup v2 hierarchy at %s: %w", vmmCgroupRoot, err)
	}
	if err := validateSandboxID(group); err != nil {
		return err
	}
	dir := vmmCgroupDir()
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	child := filepath.Join(dir, group)
	if err := os.Mkdir(child, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	from := ""
	if raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")); err == nil {
		from, _ = vmmChildGroup(raw)
	}
	// No O_CREATE: the kernel makes cgroup.procs with the cgroup, so a
	// missing one means child is not a cgroup.
	f, err := os.OpenFile(filepath.Join(child, "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(strconv.Itoa(pid))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && from != "" && from != group {
		// Empty now, or the kernel refuses and it stays.
		_ = os.Remove(filepath.Join(dir, from))
	}
	return err
}

// vmmCgroupPIDs lists the processes in the VMs' cgroup and in each VM's own
// group under it.
func vmmCgroupPIDs() ([]int, error) {
	dir := vmmCgroupDir()
	pids, err := readCgroupPIDs(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		more, err := readCgroupPIDs(filepath.Join(dir, e.Name()))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		pids = append(pids, more...)
	}
	return pids, nil
}

func readCgroupPIDs(dir string) ([]int, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, field := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(field)
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// setVMMGroupFrozen freezes or thaws one VM's own group. A VM with no group
// of its own (a v1 host; a VM placed before this release) answers
// runtime.ErrCannotFreeze: the VMs' cgroup holds every VM, and is never
// frozen whole.
func setVMMGroupFrozen(group string, frozen bool) error {
	if err := validateSandboxID(group); err != nil {
		return err
	}
	dir := filepath.Join(vmmCgroupDir(), group)
	if _, err := os.Stat(filepath.Join(dir, "cgroup.procs")); err != nil {
		return fmt.Errorf("firecracker VM %s has no group of its own (%v): %w", group, err, sbruntime.ErrCannotFreeze)
	}
	v := "0"
	if frozen {
		v = "1"
	}
	// No O_CREATE, as for cgroup.procs.
	f, err := os.OpenFile(filepath.Join(dir, "cgroup.freeze"), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(v)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// vmmGroupFrozen reports whether a VM's own group is frozen.
func vmmGroupFrozen(group string) bool {
	if validateSandboxID(group) != nil {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(vmmCgroupDir(), group, "cgroup.freeze"))
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

// removeVMMGroup removes a VM's own group once the VM is gone. The kernel
// refuses while a process is still in it, and then it stays.
func removeVMMGroup(group string) {
	if validateSandboxID(group) != nil {
		return
	}
	_ = os.Remove(filepath.Join(vmmCgroupDir(), group))
}

// removeEmptyVMMGroups removes every VM group no process is left in: VMs
// that ended with no Destroy (a template's helper VM, a sandboxd that
// stopped mid-destroy). A group a VM still runs in stays: the kernel
// refuses to remove it.
func removeEmptyVMMGroups() {
	entries, err := os.ReadDir(vmmCgroupDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			removeVMMGroup(e.Name())
		}
	}
}

// procStartTicks is when pid started, in clock ticks after boot (field 22
// of /proc/<pid>/stat). With the boot ID it names one process for good:
// a pid is reused, a (boot, pid, start) triple is not.
func procStartTicks(pid int) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// The command name (field 2) is in parentheses and may hold spaces
	// and parentheses itself; the fields after it start past the last ')'.
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, fmt.Errorf("pid %d: malformed stat", pid)
	}
	fields := strings.Fields(string(raw[end+1:]))
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return 0, fmt.Errorf("pid %d: short stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// currentBootID identifies this boot of the host.
func currentBootID() (string, error) {
	raw, err := os.ReadFile(filepath.Join(procRoot, "sys/kernel/random/boot_id"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// pidfdProcess is a process this sandboxd did not start, held by a pidfd so
// a signal can never reach another process that reused its pid.
type pidfdProcess struct {
	fd   int
	done chan struct{}

	mu     sync.Mutex
	closed bool
}

// openLiveProcess opens pid if it is still the process that started at
// startTicks. The check runs after the pidfd is open, so the pid cannot be
// reused between the two.
func openLiveProcess(pid int, startTicks uint64) (liveProcess, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	ticks, err := procStartTicks(pid)
	if err != nil || ticks != startTicks {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("pid %d is no longer the process that started at tick %d: %w", pid, startTicks, errProcessGone)
	}
	p := &pidfdProcess{fd: fd, done: make(chan struct{})}
	go p.watch()
	return p, nil
}

// watch closes done when the process exits: a pidfd turns readable then.
// The timeout lets Close end the loop.
func (p *pidfdProcess) watch() {
	defer close(p.done)
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	for {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return
		}
		n, err := unix.Poll(fds, int(time.Second/time.Millisecond))
		if err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
		if n > 0 && fds[0].Revents != 0 {
			return
		}
	}
}

func (p *pidfdProcess) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errProcessGone
	}
	err := unix.PidfdSendSignal(p.fd, sig, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return errProcessGone
	}
	return err
}

func (p *pidfdProcess) Done() <-chan struct{} { return p.done }

func (p *pidfdProcess) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	// The watcher holds the fd in poll; it notices closed within a second.
	<-p.done
	return unix.Close(p.fd)
}

// killCgroupStray kills pid if it is still in the VMs' cgroup: the check
// runs on a pidfd, so a pid reused since the cgroup was listed is left
// alone.
func killCgroupStray(pid int) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(fd)
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !inVMMCgroup(raw) {
		return nil
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

// inVMMCgroup reports whether a /proc/<pid>/cgroup file puts the process in
// the VMs' cgroup or a VM's own group under it (the v2 line,
// "0::/aerolvm-vmm" or "0::/aerolvm-vmm/<sandbox>", or under its parent).
func inVMMCgroup(procCgroup []byte) bool {
	_, in := vmmChildGroup(procCgroup)
	return in
}

// vmmChildGroup reads a /proc/<pid>/cgroup file: whether it puts the
// process in the VMs' cgroup or one VM's group under it, and that VM
// group's name ("" in the VMs' cgroup itself). Anything deeper is not a VM.
func vmmChildGroup(procCgroup []byte) (child string, in bool) {
	want := path.Join("/", currentVMMCgroupParent(), vmmCgroupName)
	for _, line := range strings.Split(string(procCgroup), "\n") {
		p, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		if p == want {
			return "", true
		}
		if rest, ok := strings.CutPrefix(p, want+"/"); ok && rest != "" && !strings.Contains(rest, "/") {
			return rest, true
		}
	}
	return "", false
}

// procCmdline is pid's argv.
func procCmdline(pid int) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"), nil
}
