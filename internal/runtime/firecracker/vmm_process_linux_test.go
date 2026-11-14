//go:build linux

package firecracker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/ownerlease"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

func withCgroupRoot(t *testing.T, v2 bool) string {
	t.Helper()
	root := t.TempDir()
	if v2 {
		if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saved := vmmCgroupRoot
	vmmCgroupRoot = root
	t.Cleanup(func() { vmmCgroupRoot = saved })
	return root
}

// Each VM goes into a group of its own under the VMs' cgroup, named after
// its sandbox: the ownership lease freezes one VM's group and no other
// (review N2).
func TestMoveToVMMCgroup(t *testing.T) {
	root := withCgroupRoot(t, true)
	withProcRoot(t)
	// A directory the kernel did not make a cgroup has no cgroup.procs:
	// the move fails rather than writing a plain file.
	if err := moveToVMMCgroup(4141, "sb-a"); err == nil {
		t.Fatal("a directory with no cgroup.procs was written to")
	}
	procs := filepath.Join(root, vmmCgroupName, "sb-a", "cgroup.procs")
	if err := os.WriteFile(procs, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveToVMMCgroup(4242, "sb-a"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(procs)
	if err != nil || string(raw) != "4242" {
		t.Fatalf("cgroup.procs = %q, %v", raw, err)
	}
	if err := moveToVMMCgroup(4242, "../escape"); err == nil {
		t.Fatal("a group name with a path in it was accepted")
	}

	withCgroupRoot(t, false)
	if err := moveToVMMCgroup(1, "sb-a"); err == nil {
		t.Fatal("a host without cgroup v2 was accepted")
	}

	blocked := withCgroupRoot(t, true)
	if err := os.WriteFile(filepath.Join(blocked, vmmCgroupName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveToVMMCgroup(1, "sb-a"); err == nil {
		t.Fatal("a cgroup path that is a file was accepted")
	}
	inner := withCgroupRoot(t, true)
	if err := os.MkdirAll(filepath.Join(inner, vmmCgroupName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, vmmCgroupName, "sb-a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveToVMMCgroup(1, "sb-a"); err == nil {
		t.Fatal("a VM group path that is a file was accepted")
	}
}

// A warm VM taken for a sandbox moves from the slot's group to the
// sandbox's, and the emptied slot group goes; a VM a release before left in
// the VMs' cgroup itself moves too, and that cgroup stays.
func TestMoveToVMMCgroupLeavesTheOldGroup(t *testing.T) {
	root := withCgroupRoot(t, true)
	proc := withProcRoot(t)
	for _, g := range []string{"slot-1", "sb-b", "sb-c"} {
		if err := os.MkdirAll(filepath.Join(root, vmmCgroupName, g), 0o755); err != nil {
			t.Fatal(err)
		}
		if g != "slot-1" {
			if err := os.WriteFile(filepath.Join(root, vmmCgroupName, g, "cgroup.procs"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeProcCgroup := func(pid int, group string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(proc, strconv.Itoa(pid)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, strconv.Itoa(pid), "cgroup"), []byte("0::/"+group+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeProcCgroup(51, vmmCgroupName+"/slot-1")
	if err := moveToVMMCgroup(51, "sb-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, vmmCgroupName, "slot-1")); !os.IsNotExist(err) {
		t.Fatalf("the emptied slot group stayed: %v", err)
	}
	writeProcCgroup(52, vmmCgroupName)
	if err := moveToVMMCgroup(52, "sb-c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, vmmCgroupName)); err != nil {
		t.Fatalf("the VMs' cgroup went: %v", err)
	}
	// Already in its own group: written again, nothing removed.
	writeProcCgroup(53, vmmCgroupName+"/sb-b")
	if err := moveToVMMCgroup(53, "sb-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, vmmCgroupName, "sb-b")); err != nil {
		t.Fatalf("a VM's own group went: %v", err)
	}
}

// A VM the ownership lease froze is the stale copy a failover leaves:
// Destroy kills it where it stands, never thaws it to shut it down. A VM
// that is not frozen shuts down as before, and its emptied group goes.
func TestDestroyKillsAFrozenVM(t *testing.T) {
	root := withCgroupRoot(t, true)
	frozen := filepath.Join(root, vmmCgroupName, "sb-frozen")
	if err := os.MkdirAll(frozen, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(frozen, "cgroup.freeze"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128}, "sb-frozen", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-frozen"}); err != nil {
		t.Fatal(err)
	}
	if !f.vmm.killed || f.vmm.graceful {
		t.Fatalf("frozen VM: killed %v, shut down gracefully %v; want a kill only", f.vmm.killed, f.vmm.graceful)
	}

	thawed := filepath.Join(root, vmmCgroupName, "sb-running")
	if err := os.MkdirAll(thawed, 0o755); err != nil {
		t.Fatal(err)
	}
	g := newDriverFixture(t)
	if _, err := g.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128}, "sb-running", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := g.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-running"}); err != nil {
		t.Fatal(err)
	}
	if !g.vmm.graceful || g.vmm.killed {
		t.Fatalf("running VM: graceful %v, killed %v; want a shutdown", g.vmm.graceful, g.vmm.killed)
	}
	if _, err := os.Stat(thawed); !os.IsNotExist(err) {
		t.Fatalf("the destroyed VM's empty group stayed: %v", err)
	}
}

// The boot sweep removes VM groups no process is left in, and leaves the
// VMs' cgroup and any group still in use.
func TestRemoveEmptyVMMGroups(t *testing.T) {
	root := withCgroupRoot(t, true)
	removeEmptyVMMGroups() // no VMs' cgroup yet: nothing to do
	for _, g := range []string{"sb-gone", "sb-live"} {
		if err := os.MkdirAll(filepath.Join(root, vmmCgroupName, g), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Stands in for a process still in the group: the kernel refuses to
	// remove it, as rmdir refuses a folder with a file.
	if err := os.WriteFile(filepath.Join(root, vmmCgroupName, "sb-live", "cgroup.procs"), []byte("7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, vmmCgroupName, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	removeEmptyVMMGroups()
	if _, err := os.Stat(filepath.Join(root, vmmCgroupName, "sb-gone")); !os.IsNotExist(err) {
		t.Fatalf("an empty VM group stayed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, vmmCgroupName, "sb-live")); err != nil {
		t.Fatalf("a VM group in use went: %v", err)
	}
}

// Freeze and thaw write a VM's own group's cgroup.freeze; a VM with no
// group of its own cannot be frozen (never the VMs' cgroup whole); a gone
// VM's group is removed.
func TestVMMGroupFreeze(t *testing.T) {
	root := withCgroupRoot(t, true)
	group := filepath.Join(root, vmmCgroupName, "sb-f")
	if err := os.MkdirAll(group, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := setVMMGroupFrozen("sb-f", true); !errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Fatalf("a group with no cgroup.procs: %v, want ErrCannotFreeze", err)
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setVMMGroupFrozen("sb-f", true); err == nil {
		t.Fatal("a group with no cgroup.freeze was written")
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.freeze"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, frozen := range []bool{true, false, true} {
		if err := setVMMGroupFrozen("sb-f", frozen); err != nil {
			t.Fatal(err)
		}
		if got := vmmGroupFrozen("sb-f"); got != frozen {
			t.Fatalf("frozen = %v, want %v", got, frozen)
		}
	}
	if err := setVMMGroupFrozen("sb-missing", true); !errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Fatalf("a VM with no group: %v, want ErrCannotFreeze", err)
	}
	if err := setVMMGroupFrozen("../"+vmmCgroupName, true); err == nil || errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Fatalf("a path for a name: %v", err)
	}
	if vmmGroupFrozen("../x") || vmmGroupFrozen("sb-missing") {
		t.Fatal("a bad name or missing group read as frozen")
	}
	// The driver's Freezer and the supervisor's group name.
	d := New(Config{}, nil)
	if err := d.Thaw(context.Background(), "sb-f"); err != nil || vmmGroupFrozen("sb-f") {
		t.Fatalf("Thaw: %v", err)
	}
	if err := d.Freeze(context.Background(), "sb-f"); err != nil || !vmmGroupFrozen("sb-f") {
		t.Fatalf("Freeze: %v", err)
	}
	if g := d.FenceGroup("sb-f"); g != vmmCgroupName+"/sb-f" || !ownerlease.ValidRef(g) {
		t.Fatalf("FenceGroup = %q", g)
	}
	// Removed only when empty (here, once its files are gone).
	removeVMMGroup("sb-f")
	if _, err := os.Stat(group); err != nil {
		t.Fatal("a group with files in it was removed")
	}
	for _, f := range []string{"cgroup.procs", "cgroup.freeze"} {
		_ = os.Remove(filepath.Join(group, f))
	}
	removeVMMGroup("sb-f")
	removeVMMGroup("../x")
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Fatalf("the empty group stayed: %v", err)
	}
}

func TestVMMCgroupPIDs(t *testing.T) {
	root := withCgroupRoot(t, true)
	if pids, err := vmmCgroupPIDs(); err != nil || pids != nil {
		t.Fatalf("no cgroup yet: %v, %v", pids, err)
	}
	if err := os.MkdirAll(filepath.Join(root, vmmCgroupName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, vmmCgroupName, "cgroup.procs"), []byte("12\n0\nx\n34\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pids, err := vmmCgroupPIDs(); err != nil || !reflect.DeepEqual(pids, []int{12, 34}) {
		t.Fatalf("pids = %v, %v", pids, err)
	}
	// Each VM's own group is listed too; a folder that is not a cgroup and
	// a plain file are passed over.
	for g, procs := range map[string]string{"sb-a": "56\n", "sb-b": "78\n"} {
		if err := os.MkdirAll(filepath.Join(root, vmmCgroupName, g), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, vmmCgroupName, g, "cgroup.procs"), []byte(procs), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, vmmCgroupName, "not-a-cgroup"), 0o755); err != nil {
		t.Fatal(err)
	}
	if pids, err := vmmCgroupPIDs(); err != nil || !reflect.DeepEqual(pids, []int{12, 34, 56, 78}) {
		t.Fatalf("pids with VM groups = %v, %v", pids, err)
	}
	if err := os.Remove(filepath.Join(root, vmmCgroupName, "sb-b", "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, vmmCgroupName, "sb-b", "cgroup.procs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := vmmCgroupPIDs(); err == nil {
		t.Fatal("a VM group's unreadable cgroup.procs was accepted")
	}
	if err := os.RemoveAll(filepath.Join(root, vmmCgroupName, "sb-b")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, vmmCgroupName, "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, vmmCgroupName, "cgroup.procs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := vmmCgroupPIDs(); err == nil {
		t.Fatal("an unreadable cgroup.procs was accepted")
	}
}

func withProcRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	saved := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = saved })
	return root
}

func TestProcStartTicksAndBootID(t *testing.T) {
	ticks, err := procStartTicks(os.Getpid())
	if err != nil || ticks == 0 {
		t.Fatalf("own start = %d, %v", ticks, err)
	}
	if boot, err := currentBootID(); err != nil || len(boot) < 32 {
		t.Fatalf("boot id = %q, %v", boot, err)
	}

	root := withProcRoot(t)
	write := func(pid int, stat string) {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A command name with spaces and parentheses does not shift the fields.
	write(7, "7 (fire (cracker) x) S 1 7 7 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 98765 0 0")
	if ticks, err := procStartTicks(7); err != nil || ticks != 98765 {
		t.Fatalf("ticks = %d, %v", ticks, err)
	}
	write(8, "8 no parenthesis")
	write(9, "9 (short) S 1")
	for _, pid := range []int{8, 9, 10} {
		if _, err := procStartTicks(pid); err == nil {
			t.Fatalf("pid %d: a bad stat was accepted", pid)
		}
	}
	if _, err := currentBootID(); err == nil {
		t.Fatal("a missing boot id was accepted")
	}
}

func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func TestOpenLiveProcess(t *testing.T) {
	cmd := startSleeper(t)
	pid := cmd.Process.Pid
	ticks, err := procStartTicks(pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openLiveProcess(pid, ticks+1); !errors.Is(err, errProcessGone) {
		t.Fatalf("a different start time: %v", err)
	}
	if _, err := openLiveProcess(1<<22+1, 0); err == nil {
		t.Fatal("a pid that does not exist was opened")
	}
	proc, err := openLiveProcess(pid, ticks)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.Done():
		t.Fatal("done before the process exited")
	default:
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// This test is the parent: reap, or the pidfd never turns readable.
	_ = cmd.Wait()
	select {
	case <-proc.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("exit not seen")
	}
	if err := proc.Signal(syscall.SIGTERM); !errors.Is(err, errProcessGone) {
		t.Fatalf("signal after exit: %v", err)
	}
	if err := proc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proc.Close(); err != nil {
		t.Fatal("a second close failed")
	}
	if err := proc.Signal(syscall.SIGTERM); !errors.Is(err, errProcessGone) {
		t.Fatalf("signal after close: %v", err)
	}
}

// Close ends the watcher of a process that is still running.
func TestOpenLiveProcessCloseWhileRunning(t *testing.T) {
	cmd := startSleeper(t)
	ticks, err := procStartTicks(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := openLiveProcess(cmd.Process.Pid, ticks)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKillCgroupStray(t *testing.T) {
	root := withProcRoot(t)
	put := func(pid int, cgroup string) {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere := startSleeper(t)
	put(elsewhere.Process.Pid, "0::/system.slice/sandboxd.service\n")
	if err := killCgroupStray(elsewhere.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := elsewhere.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("a process outside the VM cgroup was killed")
	}

	stray := startSleeper(t)
	put(stray.Process.Pid, "0::/"+vmmCgroupName+"\n")
	if err := killCgroupStray(stray.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := stray.Wait(); err == nil {
		t.Fatal("the stray exited cleanly; it was not killed")
	}

	// Gone before its cgroup was read, and a pid that never existed.
	gone := startSleeper(t)
	if err := killCgroupStray(gone.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := killCgroupStray(1<<22 + 1); err != nil {
		t.Fatal(err)
	}
	// A cgroup file that cannot be read.
	odd := startSleeper(t)
	if err := os.MkdirAll(filepath.Join(root, strconv.Itoa(odd.Process.Pid), "cgroup"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := killCgroupStray(odd.Process.Pid); err == nil {
		t.Fatal("an unreadable cgroup file was accepted")
	}
}

func TestInVMMCgroup(t *testing.T) {
	for in, want := range map[string]bool{
		"0::/aerolvm-vmm\n":                   true,
		"12:pids:/x\n0::/aerolvm-vmm":         true,
		"0::/aerolvm-vmm/sb-a\n":              true, // a VM's own group
		"0::/aerolvm-vmm/sb-a/deeper\n":       false,
		"0::/aerolvm-vmm/\n":                  false,
		"0::/system.slice/sandboxd.service\n": false,
		"1:name=systemd:/aerolvm-vmm\n":       false,
		"":                                    false,
	} {
		if got := inVMMCgroup([]byte(in)); got != want {
			t.Errorf("inVMMCgroup(%q) = %v, want %v", in, got, want)
		}
	}
	if g, in := vmmChildGroup([]byte("0::/aerolvm-vmm/sb-a\n")); g != "sb-a" || !in {
		t.Fatalf("vmmChildGroup = %q, %v", g, in)
	}
}

func TestProcCmdline(t *testing.T) {
	args, err := procCmdline(os.Getpid())
	if err != nil || len(args) == 0 || args[0] == "" {
		t.Fatalf("own argv = %q, %v", args, err)
	}
	root := withProcRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "7"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "7", "cmdline"), []byte("/firecracker\x00--id\x00sb-a\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if args, err := procCmdline(7); err != nil || !reflect.DeepEqual(args, []string{"/firecracker", "--id", "sb-a"}) {
		t.Fatalf("argv = %q, %v", args, err)
	}
	if _, err := procCmdline(8); err == nil {
		t.Fatal("a missing process was read")
	}
}

// In a worker pod the VMs' cgroup is under the runtime container's
// sandboxes group (Config.VMMCgroupParent, C14): made, listed and matched
// there, and a VM at the machine's root is no longer counted as one.
func TestVMMCgroupUnderAParent(t *testing.T) {
	root := withCgroupRoot(t, true)
	const parent = "/kubepods.slice/pod1/sandboxes"
	New(Config{VMMCgroupParent: parent}, nil)
	t.Cleanup(func() { New(Config{}, nil) })
	if err := os.MkdirAll(filepath.Join(root, parent), 0o755); err != nil {
		t.Fatal(err)
	}
	withProcRoot(t)
	for _, f := range []string{
		filepath.Join(root, parent, vmmCgroupName, "cgroup.procs"),
		filepath.Join(root, parent, vmmCgroupName, "sb-p", "cgroup.procs"),
	} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := moveToVMMCgroup(4343, "sb-p"); err != nil {
		t.Fatal(err)
	}
	if pids, err := vmmCgroupPIDs(); err != nil || !reflect.DeepEqual(pids, []int{4343}) {
		t.Fatalf("pids = %v, %v; want [4343] from the parent's group", pids, err)
	}
	if !inVMMCgroup([]byte("0::" + parent + "/" + vmmCgroupName + "\n")) {
		t.Fatal("a VM in the parent's group was not recognised")
	}
	if !inVMMCgroup([]byte("0::" + parent + "/" + vmmCgroupName + "/sb-p\n")) {
		t.Fatal("a VM in its own group under the parent's was not recognised")
	}
	if inVMMCgroup([]byte("0::/" + vmmCgroupName + "\n")) {
		t.Fatal("a process in the machine's root group counted as one of this pod's VMs")
	}
}
