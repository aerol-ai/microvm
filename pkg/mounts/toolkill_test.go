package mounts

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestProcUIDs(t *testing.T) {
	root := t.TempDir()
	write := func(pid int, body string) {
		t.Helper()
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(10, "Name:\tx\nUid:\t5\t6\t5\t5\n")
	write(11, "Name:\tx\nGid:\t0\t0\t0\t0\n")
	write(12, "Uid:\t5\n")
	write(13, "Uid:\tx\t5\t5\t5\n")
	write(14, "Uid:\t5\tx\t5\t5\n")
	write(15, "Uid:\t7\t7\t7\t7\n")
	for _, tc := range []struct {
		pid       int
		real, eff uint32
		ok        bool
	}{
		{10, 5, 6, true},
		{11, 0, 0, false}, // no Uid line
		{12, 0, 0, false}, // too short
		{13, 0, 0, false}, // not a number
		{14, 0, 0, false},
		{99, 0, 0, false}, // no such process
	} {
		r, e, ok := procUIDs(root, tc.pid)
		if r != tc.real || e != tc.eff || ok != tc.ok {
			t.Errorf("pid %d: %d %d %v, want %d %d %v", tc.pid, r, e, ok, tc.real, tc.eff, tc.ok)
		}
	}
	// Real and effective both: a process whose effective uid differs is not
	// the user's.
	if runsAs(root, 10, 5) || runsAs(root, 10, 6) || !runsAs(root, 15, 7) || runsAs(root, 99, 0) {
		t.Fatal("runsAs")
	}
	seven := uint32(7)
	if !ownerOK(root, 10, nil) || !ownerOK(root, 15, &seven) || ownerOK(root, 10, &seven) {
		t.Fatal("ownerOK")
	}
}

// startTest starts argv with attr and returns it with its end.
func startTest(t *testing.T, attr *syscall.SysProcAttr, argv ...string) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
	return cmd, done
}

func endsWithin(done chan struct{}, d time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// groupGone waits for every member of group pgid to end.
func groupGone(pgid int) bool {
	for i := 0; i < 300; i++ {
		if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestLeadsOwnGroup(t *testing.T) {
	leader, _ := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sleep", "30")
	member, _ := startTest(t, &syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid}, "sleep", "30")
	for _, tc := range []struct {
		pid  int
		want bool
	}{
		{0, false},
		{1, false}, // never group 1, whoever leads it
		{-5, false},
		{leader.Process.Pid, true},
		{member.Process.Pid, false},
		{4194307, false}, // above pid_max: no such process
	} {
		if got := leadsOwnGroup(tc.pid); got != tc.want {
			t.Errorf("leadsOwnGroup(%d) = %v", tc.pid, got)
		}
	}
	// The default killGroup signals a group only through its leader.
	killGroup(member.Process.Pid, syscall.Signal(0))
	killGroup(1, syscall.Signal(0))
}

// TestSignalListed: a listed process is signalled only while still holds;
// its group with it only when it leads that group; never pid 1 or below.
func TestSignalListed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signal func(int, syscall.Signal, func() bool) error
	}{{"listed", signalListed}, {"plain", signalListedPlain}} {
		t.Run(tc.name, func(t *testing.T) {
			yes := func() bool { return true }
			no := func() bool { return false }
			if err := tc.signal(1, syscall.SIGKILL, yes); !errors.Is(err, errProcessGone) {
				t.Fatalf("pid 1: %v", err)
			}
			if err := tc.signal(0, syscall.SIGKILL, yes); !errors.Is(err, errProcessGone) {
				t.Fatalf("pid 0: %v", err)
			}
			_ = tc.signal(4194308, syscall.SIGKILL, yes) // no such process: no panic, nothing signalled

			// still says no: nothing is signalled.
			p, pdone := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sleep", "30")
			if err := tc.signal(p.Process.Pid, syscall.SIGKILL, no); !errors.Is(err, errProcessGone) || endsWithin(pdone, 200*time.Millisecond) {
				t.Fatalf("signalled while still said no: %v", err)
			}

			// A leader: it and its group (a child of a shell).
			sh, shDone := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sh", "-c", "sleep 30 & wait")
			time.Sleep(100 * time.Millisecond) // the shell starts its child
			if err := tc.signal(sh.Process.Pid, syscall.SIGKILL, yes); err != nil {
				t.Fatal(err)
			}
			if !endsWithin(shDone, 5*time.Second) || !groupGone(sh.Process.Pid) {
				t.Fatal("the leader or its group still runs")
			}

			// A member of another's group: it alone.
			leader, leaderDone := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sleep", "30")
			member, memberDone := startTest(t, &syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid}, "sleep", "30")
			if err := tc.signal(member.Process.Pid, syscall.SIGKILL, yes); err != nil {
				t.Fatal(err)
			}
			if !endsWithin(memberDone, 5*time.Second) {
				t.Fatal("the member still runs")
			}
			if endsWithin(leaderDone, 200*time.Millisecond) {
				t.Fatal("the group the member was in was signalled")
			}
		})
	}
}

// TestKillFUSEProcessesOwner: with an owner, a process whose command line
// names the folder is stopped only when it runs as that user.
func TestKillFUSEProcessesOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := t.TempDir()
	p, done := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sleep", "30")
	fakeProc(t, proc, p.Process.Pid, "mount-s3", "/m/sb-1/0")
	me := uint32(os.Getuid())
	writeStatusUID(t, proc, p.Process.Pid, me+1)
	killFUSEProcessesInRoot(logger, "/m/sb-1", proc, &me)
	if endsWithin(done, 200*time.Millisecond) {
		t.Fatal("another user's process was stopped")
	}
	writeStatusUID(t, proc, p.Process.Pid, me)
	killFUSEProcessesInRoot(logger, "/m/sb-1", proc, &me)
	if !endsWithin(done, 5*time.Second) {
		t.Fatal("the owner's process still runs")
	}
}

// TestKillMarkedOwner: a marked process of another user is never stopped,
// and pid 1 never is.
func TestKillMarkedOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := t.TempDir()
	p, done := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sleep", "30")
	me := uint32(os.Getuid())
	fakeProc(t, proc, p.Process.Pid, "mount-s3")
	writeEnviron(t, proc, p.Process.Pid, toolMarkEnv+"=/m/sb-1/0")
	writeStatusUID(t, proc, p.Process.Pid, me+1)
	fakeProc(t, proc, 1, "init")
	writeEnviron(t, proc, 1, toolMarkEnv+"=/m/sb-1/0")
	writeStatusUID(t, proc, 1, me)
	killMarkedInRoot(logger, "/m/sb-1", proc, me)
	if endsWithin(done, 200*time.Millisecond) {
		t.Fatal("another user's marked process was stopped")
	}
}

// TestKillMountSignalsItsOwnGroup: killMount stops the tool and the group
// it was started as the leader of, with SIGKILL when SIGTERM is not
// enough; a tool found in another group has only itself signalled, never
// that group. killMount reaps the tool itself, so the tests start it bare.
func TestKillMountSignalsItsOwnGroup(t *testing.T) {
	bare := func(attr *syscall.SysProcAttr, argv ...string) *exec.Cmd {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.SysProcAttr = attr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		return cmd
	}
	prev := killMountGrace
	killMountGrace = 100 * time.Millisecond
	t.Cleanup(func() { killMountGrace = prev })
	sh := bare(&syscall.SysProcAttr{Setpgid: true}, "sh", "-c", "trap '' TERM; sleep 30")
	time.Sleep(100 * time.Millisecond)
	_ = killMount(sh)
	if !groupGone(sh.Process.Pid) {
		t.Fatal("the tool's group still runs")
	}

	leader, leaderDone := startTest(t, &syscall.SysProcAttr{Setpgid: true}, "sleep", "30")
	moved := bare(&syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid}, "sleep", "30")
	_ = killMount(moved)
	if endsWithin(leaderDone, 200*time.Millisecond) {
		t.Fatal("the group the tool was in was signalled")
	}
	if err := killMount(nil); err != nil {
		t.Fatal(err)
	}
}
