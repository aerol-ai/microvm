//go:build linux

package firecracker

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"
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

func TestMoveToVMMCgroup(t *testing.T) {
	root := withCgroupRoot(t, true)
	// A directory the kernel did not make a cgroup has no cgroup.procs:
	// the move fails rather than writing a plain file.
	if err := moveToVMMCgroup(4141); err == nil {
		t.Fatal("a directory with no cgroup.procs was written to")
	}
	procs := filepath.Join(root, vmmCgroupName, "cgroup.procs")
	if err := os.WriteFile(procs, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveToVMMCgroup(4242); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(procs)
	if err != nil || string(raw) != "4242" {
		t.Fatalf("cgroup.procs = %q, %v", raw, err)
	}

	withCgroupRoot(t, false)
	if err := moveToVMMCgroup(1); err == nil {
		t.Fatal("a host without cgroup v2 was accepted")
	}

	blocked := withCgroupRoot(t, true)
	if err := os.WriteFile(filepath.Join(blocked, vmmCgroupName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveToVMMCgroup(1); err == nil {
		t.Fatal("a cgroup path that is a file was accepted")
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
		"0::/aerolvm-vmm/child\n":             false,
		"0::/system.slice/sandboxd.service\n": false,
		"1:name=systemd:/aerolvm-vmm\n":       false,
		"":                                    false,
	} {
		if got := inVMMCgroup([]byte(in)); got != want {
			t.Errorf("inVMMCgroup(%q) = %v, want %v", in, got, want)
		}
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
	procs := filepath.Join(root, parent, vmmCgroupName, "cgroup.procs")
	if err := os.MkdirAll(filepath.Dir(procs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(procs, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveToVMMCgroup(4343); err != nil {
		t.Fatal(err)
	}
	if pids, err := vmmCgroupPIDs(); err != nil || !reflect.DeepEqual(pids, []int{4343}) {
		t.Fatalf("pids = %v, %v; want [4343] from the parent's group", pids, err)
	}
	if !inVMMCgroup([]byte("0::" + parent + "/" + vmmCgroupName + "\n")) {
		t.Fatal("a VM in the parent's group was not recognised")
	}
	if inVMMCgroup([]byte("0::/" + vmmCgroupName + "\n")) {
		t.Fatal("a process in the machine's root group counted as one of this pod's VMs")
	}
}
