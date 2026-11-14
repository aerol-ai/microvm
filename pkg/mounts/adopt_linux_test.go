//go:build linux

package mounts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// The restart these tests stage: one Manager mounts (its helper is a real
// process, `sh -c 'sleep 300; :' mount-tool <path>`), then a second Manager
// on the same directories, like the next sandboxd, reestablishes the same
// sandbox. probeMount stands in for a live FUSE mount at the path.

var fuseSpec = []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"}}

func restartPair(t *testing.T) (first, next *Manager) {
	t.Helper()
	// The stand-in helper never mounts anything: ready at once.
	prevProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration, <-chan struct{}) error { return nil }
	t.Cleanup(func() { waitForMountProbe = prevProbe })
	first = newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: liveFUSEAdapter{}})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next, err := New(logger, Config{RootDir: first.rootDir, CredDir: first.credDir, WaitTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	next.adapters = first.adapters
	t.Cleanup(next.Close)
	return first, next
}

// helpersRunning lists the live helpers running sandboxID's plan. The
// stand-in shell forks sleep, and a forked child carries the shell's argv
// until it execs, so a match whose parent is a match is not counted.
func helpersRunning(t *testing.T, m *Manager, sandboxID string) []int {
	t.Helper()
	plan, _ := liveFUSEAdapter{}.Build(sandboxID, 0, fuseSpec[0], m.hostPath(sandboxID, 0), m.credDir)
	var matches []helperProcess
	for _, h := range m.listHelperProcesses() {
		if slices.Equal(h.argv, plan.Argv) {
			matches = append(matches, h)
		}
	}
	var pids []int
	for _, h := range matches {
		if !slices.ContainsFunc(matches, func(o helperProcess) bool { return o.pid == h.ppid }) {
			pids = append(pids, h.pid)
		}
	}
	return pids
}

func stateOf(m *Manager, sandboxID string) (*mountState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	states := m.state[sandboxID]
	if len(states) != 1 {
		return nil, false
	}
	return states[0], true
}

// mountFirst mounts with the first Manager and then has it die: it forgets
// the mount without tearing it down, as a stopped sandboxd does, so it never
// restarts the helper. It still reaps the helper (its child) when it exits.
func mountFirst(t *testing.T, first *Manager, sandboxID string) (int, *procExit) {
	t.Helper()
	if _, err := first.MountAll(context.Background(), sandboxID, fuseSpec); err != nil {
		t.Fatalf("MountAll: %v", err)
	}
	first.mu.Lock()
	defer first.mu.Unlock()
	st := first.state[sandboxID][0]
	delete(first.state, sandboxID)
	return st.cmd.Process.Pid, st.exit
}

// The restart: the next Manager takes the running helper over instead of
// starting a second one, and tears it down when the sandbox's mounts go.
func TestReestablishAdoptsARunningHelper(t *testing.T) {
	first, next := restartPair(t)
	pid, _ := mountFirst(t, first, "sb-adopt")
	withProbeMount(t, func(string) mountProbe { return mountLive })

	if err := next.Reestablish(context.Background(), "sb-adopt", fuseSpec); err != nil {
		t.Fatalf("Reestablish: %v", err)
	}
	st, ok := stateOf(next, "sb-adopt")
	if !ok || st.cmd != nil || st.proc == nil || st.proc.Pid() != pid || !st.supervised {
		t.Fatalf("state after Reestablish = %+v, want the helper %d adopted", st, pid)
	}
	if got := helpersRunning(t, next, "sb-adopt"); !slices.Equal(got, []int{pid}) {
		t.Fatalf("helpers running = %v, want only the original %d", got, pid)
	}
	if binds := next.HostBindsFor("sb-adopt"); len(binds) != 1 || binds[0].HostPath != next.hostPath("sb-adopt", 0) {
		t.Fatalf("binds = %+v", binds)
	}
	// A second pass sees it tracked and does nothing.
	if err := next.Reestablish(context.Background(), "sb-adopt", fuseSpec); err != nil {
		t.Fatalf("second Reestablish: %v", err)
	}

	if err := next.UnmountAll("sb-adopt"); err != nil {
		t.Fatalf("UnmountAll: %v", err)
	}
	select {
	case <-st.exit.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the adopted helper outlived UnmountAll")
	}
}

// An adopted helper that dies is restarted by the next Manager, as a helper
// it started itself would be.
func TestAdoptedHelperIsRestartedWhenItExits(t *testing.T) {
	first, next := restartPair(t)
	pid, _ := mountFirst(t, first, "sb-restart")
	withProbeMount(t, func(string) mountProbe { return mountLive })
	if err := next.Reestablish(context.Background(), "sb-restart", fuseSpec); err != nil {
		t.Fatalf("Reestablish: %v", err)
	}
	t.Cleanup(func() { _ = next.UnmountAll("sb-restart") })

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		next.mu.Lock()
		st := next.state["sb-restart"][0]
		restarted := st.cmd != nil && st.restarts == 1
		next.mu.Unlock()
		if restarted {
			if st.cmd.Process.Pid == pid {
				t.Fatal("restart reused the dead pid")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the adopted helper was never restarted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A helper running other arguments at the path (an older spec, a stray) is
// stopped and the mount started afresh: never two helpers on one path.
func TestReestablishReplacesAHelperRunningOtherArguments(t *testing.T) {
	_, next := restartPair(t)
	hostPath := next.hostPath("sb-stray", 0)
	stray := exec.Command("sh", "-c", "sleep 300; :", "mount-tool", "--other-bucket", hostPath)
	stray.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := stray.Start(); err != nil {
		t.Fatal(err)
	}
	strayExit := watchExit(stray)
	t.Cleanup(func() { _ = killMount(stray) })
	// Adoption finds helpers by their arguments, as the sweep does.
	waitForArgv(t, stray.Process.Pid, hostPath, strayExit.done)
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	probes := 0
	withProbeMount(t, func(string) mountProbe {
		probes++
		if probes == 1 {
			return mountLive // what adoptOne sees
		}
		return notMounted // after the stray is gone
	})

	if err := next.Reestablish(context.Background(), "sb-stray", fuseSpec); err != nil {
		t.Fatalf("Reestablish: %v", err)
	}
	t.Cleanup(func() { _ = next.UnmountAll("sb-stray") })
	select {
	case <-strayExit.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stray helper was left running on the path")
	}
	st, ok := stateOf(next, "sb-stray")
	if !ok || st.cmd == nil || st.proc != nil {
		t.Fatalf("state = %+v, want a fresh helper this Manager started", st)
	}
}

// A mount whose helper died with the old sandboxd (a host without the
// cgroup) is unmounted and mounted again rather than failing on the dead
// FUSE mount.
func TestReestablishRemountsWhenTheHelperDied(t *testing.T) {
	first, next := restartPair(t)
	pid, firstExit := mountFirst(t, first, "sb-dead")
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-firstExit.done

	var unmounted []string
	prevU := runUmount
	runUmount = func(p string) error { unmounted = append(unmounted, p); return nil }
	t.Cleanup(func() { runUmount = prevU })
	// Both looks (adoptOne's and clearStaleMount's) find the dead mount.
	withProbeMount(t, func(string) mountProbe { return mountBroken })

	if err := next.Reestablish(context.Background(), "sb-dead", fuseSpec); err != nil {
		t.Fatalf("Reestablish: %v", err)
	}
	t.Cleanup(func() { _ = next.UnmountAll("sb-dead") })
	if !slices.Contains(unmounted, next.hostPath("sb-dead", 0)) {
		t.Fatalf("unmounted %v, want the dead mount at %s", unmounted, next.hostPath("sb-dead", 0))
	}
	if st, ok := stateOf(next, "sb-dead"); !ok || st.cmd == nil {
		t.Fatalf("state = %+v, want a fresh helper", st)
	}
}

// waitExeced waits until pid runs argv. Right after Start the child may not
// have exec'd yet, and its /proc cmdline is still the test binary's, which
// openHelperProcess rightly calls a different process.
func waitExeced(t *testing.T, pid int, argv []string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := readCmdline(pid)
		if err == nil && slices.Equal(got, argv) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never ran %q (cmdline %q, %v)", pid, argv, got, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOpenHelperProcess(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 300; :", "probe")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitExeced(t, cmd.Process.Pid, cmd.Args)
	exit := watchExit(cmd)
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exit.done })
	argv := []string{"sh", "-c", "sleep 300; :", "probe"}

	if _, err := openHelperProcess(cmd.Process.Pid, []string{"other"}); !errors.Is(err, errProcessGone) {
		t.Fatalf("open with other argv = %v, want errProcessGone", err)
	}
	if _, err := openHelperProcess(1<<22, argv); err == nil {
		t.Fatal("opened a pid that does not exist")
	}
	p, err := openHelperProcess(cmd.Process.Pid, argv)
	if err != nil {
		t.Fatalf("openHelperProcess: %v", err)
	}
	if p.Pid() != cmd.Process.Pid {
		t.Fatalf("Pid = %d", p.Pid())
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("Signal(0): %v", err)
	}
	if err := p.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}
	select {
	case <-p.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done never closed")
	}
	<-exit.done
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := p.Signal(syscall.SIGTERM); !errors.Is(err, errProcessGone) {
		t.Fatalf("Signal after Close = %v, want errProcessGone", err)
	}

	// A process that exited (reaped) before the signal reports gone.
	cmd2 := exec.Command("sh", "-c", "sleep 300; :", "probe2")
	if err := cmd2.Start(); err != nil {
		t.Fatal(err)
	}
	waitExeced(t, cmd2.Process.Pid, cmd2.Args)
	p2, err := openHelperProcess(cmd2.Process.Pid, []string{"sh", "-c", "sleep 300; :", "probe2"})
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd2.Process.Kill()
	_ = cmd2.Wait()
	if err := p2.Signal(syscall.SIGTERM); !errors.Is(err, errProcessGone) {
		t.Fatalf("Signal to a reaped process = %v, want errProcessGone", err)
	}
	_ = p2.Close()
}
