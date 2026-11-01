//go:build linux && kerneltest

package containerd

// What an "oom" event means, on a real kernel, as root with cgroup v2:
//
//	sudo go test -tags kerneltest ./internal/runtime/containerd/ -run KernelOOM -v
//
// (In a container, first move every process out of the namespace's root
// cgroup so the memory controller can be enabled below it:
// mkdir /sys/fs/cgroup/init; for p in $(cat /sys/fs/cgroup/cgroup.procs); do
// echo $p > /sys/fs/cgroup/init/cgroup.procs; done.)
//
// StreamEvents maps containerd's /tasks/oom to the "oom" action. The runc
// shim publishes that event from its cgroup watcher (containerd pkg/oom/v2):
// through cgroups/v3 cgroup2.Manager.EventChan it watches the cgroup's
// memory.events and publishes TaskOOM whenever its oom_kill count goes up,
// for ANY process in the cgroup. This test reads that same counter: a
// long-lived "init" and a memory hog share a cgroup capped at 32 MiB. The hog
// is OOM-killed, oom_kill goes 0 → 1 (the shim would publish TaskOOM), and
// the init is still running: an oom event is not the container's exit.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const oomHogEnv = "AEROL_KERNEL_OOM_HOG"

// TestKernelOOMHogHelper allocates and touches memory until it is killed.
func TestKernelOOMHogHelper(t *testing.T) {
	if os.Getenv(oomHogEnv) == "" {
		t.Skip("helper process only")
	}
	var keep [][]byte
	for {
		b := make([]byte, 4<<20)
		for i := range b {
			b[i] = byte(i)
		}
		keep = append(keep, b)
	}
}

// memoryEvents reads a cgroup's memory.events counters.
func memoryEvents(t *testing.T, dir string) map[string]uint64 {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "memory.events"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		out[k] = n
	}
	return out
}

func writeCgroupFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatalf("write %s=%q (in a container, see the comment at the top): %v", path, value, err)
	}
}

func TestKernelOOMEventWithASurvivingInit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (cgroup v2 writes)")
	}
	const root = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		t.Skip("needs cgroup v2 at /sys/fs/cgroup")
	}
	writeCgroupFile(t, filepath.Join(root, "cgroup.subtree_control"), "+memory")
	dir := filepath.Join(root, fmt.Sprintf("aerol-oom-kt-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	writeCgroupFile(t, filepath.Join(dir, "memory.max"), strconv.Itoa(32<<20))
	if _, err := os.Stat(filepath.Join(dir, "memory.swap.max")); err == nil {
		writeCgroupFile(t, filepath.Join(dir, "memory.swap.max"), "0")
	}
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	inCgroup := &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if before := memoryEvents(t, dir)["oom_kill"]; before != 0 {
		t.Fatalf("a new cgroup already counts %d OOM kills", before)
	}

	// The container's init: it never allocates, so the kernel picks the hog.
	initProc := exec.Command("sleep", "600")
	initProc.SysProcAttr = inCgroup
	if err := initProc.Start(); err != nil {
		t.Fatal(err)
	}
	initDone := make(chan error, 1)
	go func() { initDone <- initProc.Wait() }()
	t.Cleanup(func() {
		_ = initProc.Process.Kill()
		<-initDone
	})

	hog := exec.Command(os.Args[0], "-test.run=^TestKernelOOMHogHelper$")
	hog.Env = append(os.Environ(), oomHogEnv+"=1")
	hog.SysProcAttr = inCgroup
	start := time.Now()
	err = hog.Run()
	if err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("the hog was not killed: %v", err)
	}
	t.Logf("hog ended after %v: %v", time.Since(start).Round(time.Millisecond), err)

	// The counter the shim turns into TaskOOM went up.
	events := memoryEvents(t, dir)
	t.Logf("memory.events: oom=%d oom_kill=%d oom_group_kill=%d", events["oom"], events["oom_kill"], events["oom_group_kill"])
	if events["oom_kill"] < 1 {
		t.Fatalf("oom_kill did not go up: %v", events)
	}

	// The init survived it: what containerd reports as /tasks/oom, and
	// Docker as "oom", came while the container's init kept running.
	select {
	case err := <-initDone:
		t.Fatalf("the init exited with the hog: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(raw)); len(got) != 1 || got[0] != strconv.Itoa(initProc.Process.Pid) {
		t.Fatalf("cgroup processes after the OOM kill = %v, want only the init %d", got, initProc.Process.Pid)
	}
}
