package nodeupgrade

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// vmmCgroup is the cgroup, under the cgroup v2 root, Firecracker VMs run
// in (internal/runtime/firecracker/vmm_adopt.go).
const vmmCgroup = "aerolvm-vmm"

// keepFirecrackerVMsRunning moves running Firecracker VMs out of sandboxd's
// cgroup before sandboxd stops: the unit stops with KillMode=control-group,
// which would stop them too. Moved, they keep running and the next sandboxd
// takes them over. It is the Go form of install.sh's
// keep_firecracker_vms_running, for VMs started by releases up to v0.6.11;
// current releases start every VM outside the unit already. A no-op without
// cgroup v2 or without such VMs. It returns how many processes it moved.
//
// Those releases also gave each VM's output to a pipe sandboxd read. With
// sandboxd gone the VM's next write would fail with EPIPE, and
// Firecracker's SIGPIPE handler deadlocks the VMM: the guest freezes. So
// each such VM gets a reader of its own, in the VMs' cgroup, that drains
// the pipe for as long as the VM lives and exits with it.
func (u *Upgrader) keepFirecrackerVMsRunning(ctx context.Context) int {
	root := u.Paths.CgroupRoot
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return 0
	}
	cg := u.Host.UnitControlGroup(ctx, sandboxdUnit)
	if cg == "" {
		return 0
	}
	procs, err := os.ReadFile(filepath.Join(root, cg, "cgroup.procs"))
	if err != nil {
		return 0
	}
	dest := filepath.Join(root, vmmCgroup)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0
	}
	destProcs := filepath.Join(dest, "cgroup.procs")
	moved := 0
	sc := bufio.NewScanner(bytes.NewReader(procs))
	for sc.Scan() {
		pid, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
		if err != nil || pid <= 0 {
			continue
		}
		procDir := filepath.Join(u.Paths.ProcRoot, strconv.Itoa(pid))
		cmdline, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err != nil {
			continue
		}
		// A jailed VM's argv[0] is /firecracker; an unjailed one's the
		// binary's path.
		argv0, _, _ := strings.Cut(string(cmdline), "\x00")
		if filepath.Base(argv0) != "firecracker" {
			continue
		}
		if writeCgroupPID(destProcs, pid) == nil {
			moved++
		}
		out := filepath.Join(procDir, "fd", "1")
		if link, err := os.Readlink(out); err == nil && strings.HasPrefix(link, "pipe:") {
			reader, err := u.Host.StartDrain(out)
			if err != nil {
				u.logf("warning: no reader for Firecracker VM %d's output pipe: %v", pid, err)
				continue
			}
			if writeCgroupPID(destProcs, reader) == nil {
				moved++
			}
		}
	}
	return moved
}

// writeCgroupPID moves a process into the cgroup whose cgroup.procs this
// is. One write per process, as the kernel takes it.
func writeCgroupPID(procs string, pid int) error {
	f, err := os.OpenFile(procs, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(strconv.Itoa(pid) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
