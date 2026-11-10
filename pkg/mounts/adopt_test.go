package mounts

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// fakeProc writes a stand-in /proc entry.
func fakeProc(t *testing.T, root string, pid int, argv ...string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := ""
	if len(argv) > 0 {
		raw = strings.Join(argv, "\x00") + "\x00"
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withProcRoot(t *testing.T, root string) {
	t.Helper()
	prev := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = prev })
}

func withProbeMount(t *testing.T, probe func(string) mountProbe) {
	t.Helper()
	prev := probeMount
	probeMount = probe
	t.Cleanup(func() { probeMount = prev })
}

func TestRunsPlan(t *testing.T) {
	plan := []string{"mount-s3", "--foreground", "--", "bucket", "/m/sb/0"}
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{"same command", plan, true},
		{"by path", []string{"/usr/bin/mount-s3", "--foreground", "--", "bucket", "/m/sb/0"}, true},
		{"through an interpreter", []string{"/bin/sh", "/usr/local/bin/mount-s3", "--foreground", "--", "bucket", "/m/sb/0"}, true},
		{"other bucket", []string{"mount-s3", "--foreground", "--", "other", "/m/sb/0"}, false},
		{"other program", []string{"rclone", "--foreground", "--", "bucket", "/m/sb/0"}, false},
		{"shorter", []string{"/m/sb/0"}, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runsPlan(tt.argv, plan); got != tt.want {
				t.Fatalf("runsPlan(%q) = %v, want %v", tt.argv, got, tt.want)
			}
		})
	}
	if runsPlan(plan, nil) {
		t.Fatal("runsPlan matched an empty plan")
	}
}

func TestListHelperProcesses(t *testing.T) {
	proc := t.TempDir()
	withProcRoot(t, proc)
	fakeProc(t, proc, 10, "mount-s3", "--", "b", "/m/a/0")
	fakeProc(t, proc, 11, "sshfs", "-f", "--", "h:/", "/m/b/0")
	fakeProc(t, proc, 12) // a kernel thread: empty cmdline
	if err := os.MkdirAll(filepath.Join(proc, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "99"), nil, 0o644); err != nil { // not a directory
		t.Fatal(err)
	}

	m := newTestManager(t, nil)
	// No cgroup: every process.
	got := m.listHelperProcesses()
	pids := make([]int, 0, len(got))
	for _, h := range got {
		pids = append(pids, h.pid)
	}
	slices.Sort(pids)
	if !slices.Equal(pids, []int{10, 11}) {
		t.Fatalf("pids without a cgroup = %v, want [10 11]", pids)
	}

	// With the cgroup: only its members, gone ones skipped.
	cgRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cgRoot, helperCgroupName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, helperCgroupName, "cgroup.procs"), []byte("11\n4242\nnot-a-pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.cgroup = newHelperCgroup(m.logger, cgRoot)
	got = m.listHelperProcesses()
	if len(got) != 1 || got[0].pid != 11 || got[0].argv[0] != "sshfs" {
		t.Fatalf("helpers from the cgroup = %+v, want pid 11 only", got)
	}

	withProcRoot(t, filepath.Join(proc, "missing"))
	m.cgroup = nil
	if got := m.listHelperProcesses(); len(got) != 0 {
		t.Fatalf("helpers with no procfs = %+v, want none", got)
	}
}

func TestReadPPID(t *testing.T) {
	proc := t.TempDir()
	withProcRoot(t, proc)
	stats := map[int]string{
		20: "20 (mount-s3) S 1 20 20 0 -1",
		21: "21 (odd ) name) S 20 21 21 0 -1", // a comm with ") " in it
		22: "22 no-parens S 1",
		23: "23 (short) S",
	}
	for pid, stat := range stats {
		fakeProc(t, proc, pid, "x")
		if err := os.WriteFile(filepath.Join(proc, strconv.Itoa(pid), "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for pid, want := range map[int]int{20: 1, 21: 20, 22: 0, 23: 0, 24: 0} {
		if got := readPPID(pid); got != want {
			t.Errorf("readPPID(%d) = %d, want %d", pid, got, want)
		}
	}
}

// A helper's freshly forked child carries its argv until it execs; it is
// not a second helper. Two unrelated matches are.
func TestHelperFor(t *testing.T) {
	plan := []string{"sshfs", "-f", "--", "h:/", "/m/sb/0"}
	other := []string{"sshfs", "-f", "--", "h:/", "/m/sb/1"}
	tests := []struct {
		name    string
		helpers []helperProcess
		want    int // 0: none
	}{
		{"none", []helperProcess{{pid: 5, argv: other}}, 0},
		{"one", []helperProcess{{pid: 5, ppid: 1, argv: plan}, {pid: 6, argv: other}}, 5},
		{"helper and its forked child", []helperProcess{{pid: 7, ppid: 5, argv: plan}, {pid: 5, ppid: 1, argv: plan}}, 5},
		{"two unrelated helpers", []helperProcess{{pid: 5, ppid: 1, argv: plan}, {pid: 9, ppid: 1, argv: plan}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := helperFor(tt.helpers, plan)
			if (got == nil) != (tt.want == 0) || (got != nil && got.pid != tt.want) {
				t.Fatalf("helperFor = %+v, want pid %d", got, tt.want)
			}
		})
	}
}

func TestProbeMount(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := probeMount(filepath.Join(dir, "missing")); got != notMounted {
		t.Fatalf("missing path = %v, want notMounted", got)
	}
	if got := probeMount(plain); got != notMounted {
		t.Fatalf("plain dir = %v, want notMounted", got)
	}
	if got := probeMount(filepath.Join(file, "child")); got != mountBroken {
		t.Fatalf("unreadable path = %v, want mountBroken", got)
	}
	prev := pathDevOf
	pathDevOf = func(string) uint64 { return 1<<62 + 7 } // the parent is on another device
	t.Cleanup(func() { pathDevOf = prev })
	if got := probeMount(plain); got != mountLive {
		t.Fatalf("dir on another device than its parent = %v, want mountLive", got)
	}
}

// fakeLive is a liveProcess under a test's control.
type fakeLive struct {
	pid      int
	mu       sync.Mutex
	signals  []syscall.Signal
	done     chan struct{}
	exitOn   syscall.Signal // closes done when this signal arrives; 0 never
	closed   int
	closeErr error
}

func newFakeLive(pid int, exitOn syscall.Signal) *fakeLive {
	return &fakeLive{pid: pid, done: make(chan struct{}), exitOn: exitOn}
}

func (f *fakeLive) Pid() int { return f.pid }
func (f *fakeLive) Signal(sig syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, sig)
	if sig == f.exitOn {
		select {
		case <-f.done:
		default:
			close(f.done)
		}
	}
	return nil
}
func (f *fakeLive) Done() <-chan struct{} { return f.done }
func (f *fakeLive) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return f.closeErr
}

func recordGroupKills(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	prev := killGroup
	killGroup = func(pgid int, sig syscall.Signal) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, strconv.Itoa(pgid)+":"+sig.String())
	}
	t.Cleanup(func() { killGroup = prev })
	return &got
}

func TestKillLiveProcess(t *testing.T) {
	prevGrace := adoptedKillGrace
	adoptedKillGrace = 20 * time.Millisecond
	t.Cleanup(func() { adoptedKillGrace = prevGrace })

	t.Run("exits on SIGTERM", func(t *testing.T) {
		groups := recordGroupKills(t)
		p := newFakeLive(4100, syscall.SIGTERM)
		killLiveProcess(p)
		if !slices.Equal(p.signals, []syscall.Signal{syscall.SIGTERM}) || p.closed != 1 {
			t.Fatalf("signals = %v closed = %d, want SIGTERM only and one close", p.signals, p.closed)
		}
		if len(*groups) != 1 || !strings.HasPrefix((*groups)[0], "4100:") {
			t.Fatalf("group signals = %v, want one to group 4100", *groups)
		}
	})
	t.Run("ignores SIGTERM", func(t *testing.T) {
		groups := recordGroupKills(t)
		p := newFakeLive(4101, syscall.SIGKILL)
		killLiveProcess(p)
		if !slices.Equal(p.signals, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
			t.Fatalf("signals = %v, want SIGTERM then SIGKILL", p.signals)
		}
		if len(*groups) != 2 {
			t.Fatalf("group signals = %v, want TERM and KILL", *groups)
		}
	})
}

func TestWatchLiveExit(t *testing.T) {
	p := newFakeLive(1, syscall.SIGTERM)
	exit := watchLiveExit(p)
	if _, exited := exit.status(); exited {
		t.Fatal("exited before the process did")
	}
	_ = p.Signal(syscall.SIGTERM)
	<-exit.done
	if status, _ := exit.status(); status != errAdoptedToolExited.Error() {
		t.Fatalf("status = %q", status)
	}
}

// liveFUSEAdapter builds a FUSE-style plan whose last argument is the mount
// path, like mount-s3, sshfs and rclone.
type liveFUSEAdapter struct{ buildErr error }

func (a liveFUSEAdapter) Build(_ string, _ int, _ models.MountSpec, hostTarget, _ string) (adapters.Plan, error) {
	if a.buildErr != nil {
		return adapters.Plan{}, a.buildErr
	}
	return adapters.Plan{Argv: []string{"sh", "-c", "sleep 300; :", "mount-tool", hostTarget}}, nil
}

func TestAdoptOneRefuses(t *testing.T) {
	spec := models.MountSpec{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3:    liveFUSEAdapter{},
		models.MountTypeSSHFS: liveFUSEAdapter{buildErr: errors.New("bad spec")},
		models.MountTypeNFS:   fakeAdapter{},
	})
	hostPath := m.hostPath("sb-a", 0)
	plan, _ := liveFUSEAdapter{}.Build("", 0, spec, hostPath, "")
	live := func(string) mountProbe { return mountLive }

	tests := []struct {
		name    string
		spec    models.MountSpec
		probe   func(string) mountProbe
		helpers []helperProcess
		adopted bool
	}{
		{name: "no adapter", spec: models.MountSpec{Type: models.MountTypeRclone}, probe: live},
		{name: "not mounted", spec: spec, probe: func(string) mountProbe { return notMounted }},
		{name: "broken mount", spec: spec, probe: func(string) mountProbe { return mountBroken }},
		{name: "build fails", spec: models.MountSpec{Type: models.MountTypeSSHFS}, probe: live},
		{name: "no helper", spec: spec, probe: live},
		{name: "two helpers", spec: spec, probe: live, helpers: []helperProcess{{pid: 1, argv: plan.Argv}, {pid: 2, argv: plan.Argv}}},
		{name: "helper cannot be opened", spec: spec, probe: live, helpers: []helperProcess{{pid: 1 << 22, argv: plan.Argv}}},
		{name: "kernel mount is adopted with no process", spec: models.MountSpec{Type: models.MountTypeNFS, Target: "/nfs", ReadOnly: true}, probe: live, adopted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withProbeMount(t, tt.probe)
			state, bind := m.adoptOne("sb-a", 0, tt.spec, tt.helpers)
			if (state != nil) != tt.adopted {
				t.Fatalf("adopted = %v, want %v", state != nil, tt.adopted)
			}
			if tt.adopted && (state.proc != nil || state.supervised || bind != (ContainerBind{HostPath: hostPath, ContainerPath: "/nfs", ReadOnly: true})) {
				t.Fatalf("kernel mount adopted as %+v, bind %+v", state, bind)
			}
		})
	}
}

// A helper that cannot be adopted is cleared before the path is mounted
// again: a broken mount is unmounted, a healthy empty directory is left.
func TestClearStaleMountUnmounts(t *testing.T) {
	var mu sync.Mutex
	var unmounted []string
	prevU, prevL := runUmount, runLazyUmount
	runUmount = func(p string) error { mu.Lock(); unmounted = append(unmounted, p); mu.Unlock(); return nil }
	runLazyUmount = func(string) error { return nil }
	t.Cleanup(func() { runUmount, runLazyUmount = prevU, prevL })

	var logs bytes.Buffer
	m := newTestManager(t, nil)
	m.logger = slog.New(slog.NewTextHandler(&logs, nil))
	hostPath := m.hostPath("sb-c", 0)
	helpers := []helperProcess{
		{pid: 1 << 22, argv: []string{"mount-s3", "--", "b", hostPath}}, // gone: cannot be opened
		{pid: 2, argv: []string{"mount-s3", "--", "b", "/elsewhere"}},
	}

	withProbeMount(t, func(string) mountProbe { return notMounted })
	m.clearStaleMount("sb-c", 0, helpers)
	if len(unmounted) != 0 {
		t.Fatalf("unmounted %v with nothing mounted", unmounted)
	}

	withProbeMount(t, func(string) mountProbe { return mountBroken })
	m.clearStaleMount("sb-c", 0, helpers)
	if !slices.Equal(unmounted, []string{hostPath}) {
		t.Fatalf("unmounted = %v, want %s", unmounted, hostPath)
	}

	runUmount = func(string) error { return errors.New("busy") }
	runLazyUmount = func(string) error { return errors.New("busy") }
	m.clearStaleMount("sb-c", 0, helpers)
	if !strings.Contains(logs.String(), "unmount stale mount failed") {
		t.Fatalf("a failed unmount was not logged: %s", logs.String())
	}
}

// Reestablish of a sandbox with no mount directory never looks for helpers:
// nothing could have been left there.
func TestReestablishWithoutADirectoryMountsAfresh(t *testing.T) {
	proc := t.TempDir()
	withProcRoot(t, proc)
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}})
	withProbeMount(t, func(string) mountProbe {
		t.Error("probed a mount of a sandbox with no directory")
		return notMounted
	})
	if err := m.Reestablish(t.Context(), "sb-new", []models.MountSpec{{Type: models.MountTypeNFS, Target: "/n"}}); err != nil {
		t.Fatalf("Reestablish: %v", err)
	}
}

func TestHelperCgroupNilAndLogOnce(t *testing.T) {
	var nilCG *helperCgroup
	if _, ok := nilCG.fd(); ok {
		t.Fatal("a nil cgroup offered a descriptor")
	}
	if nilCG.procsFile() != "" {
		t.Fatal("a nil cgroup named a procs file")
	}

	var logs bytes.Buffer
	cg := newHelperCgroup(slog.New(slog.NewTextHandler(&logs, nil)), filepath.Join(t.TempDir(), "not-a-cgroup"))
	for range 3 {
		if _, ok := cg.fd(); ok {
			t.Fatal("a missing cgroup root offered a descriptor")
		}
	}
	cg.disable(errors.New("again"))
	if n := strings.Count(logs.String(), "mount helpers run in sandboxd's cgroup"); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, logs.String())
	}
}

// The adoption lifecycle with a stand-in process, on any platform: adopted
// at Reestablish, restarted as a child when it exits, and an adopted helper
// that is still running is stopped by UnmountAll.
func TestAdoptionLifecycleWithAStandInProcess(t *testing.T) {
	proc := t.TempDir()
	withProcRoot(t, proc)
	prevProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration, <-chan struct{}) error { return nil }
	t.Cleanup(func() { waitForMountProbe = prevProbe })
	withProbeMount(t, func(string) mountProbe { return mountLive })
	groups := recordGroupKills(t)
	spec := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}}

	adopt := func(t *testing.T, sandboxID string, pid int, exitOn syscall.Signal) (*Manager, *fakeLive) {
		t.Helper()
		m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: liveFUSEAdapter{}})
		hostPath := m.hostPath(sandboxID, 0)
		if err := os.MkdirAll(hostPath, 0o700); err != nil {
			t.Fatal(err)
		}
		plan, _ := liveFUSEAdapter{}.Build(sandboxID, 0, spec[0], hostPath, m.credDir)
		fakeProc(t, proc, pid, plan.Argv...)
		live := newFakeLive(pid, exitOn)
		prevOpen := openHelperProcess
		openHelperProcess = func(gotPID int, argv []string) (liveProcess, error) {
			if gotPID != pid || !slices.Equal(argv, plan.Argv) {
				return nil, errProcessGone
			}
			return live, nil
		}
		t.Cleanup(func() { openHelperProcess = prevOpen })
		if err := m.Reestablish(t.Context(), sandboxID, spec); err != nil {
			t.Fatalf("Reestablish: %v", err)
		}
		m.mu.Lock()
		st := m.state[sandboxID][0]
		m.mu.Unlock()
		if st.proc != live || st.cmd != nil {
			t.Fatalf("state = %+v, want the stand-in adopted", st)
		}
		return m, live
	}

	t.Run("restarted when it exits", func(t *testing.T) {
		m, live := adopt(t, "sb-fake-exit", 4242, 0)
		close(live.done)
		deadline := time.Now().Add(10 * time.Second)
		for {
			m.mu.Lock()
			st := m.state["sb-fake-exit"][0]
			restarted := st.cmd != nil && st.restarts == 1
			m.mu.Unlock()
			if restarted {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the adopted helper was never restarted")
			}
			time.Sleep(5 * time.Millisecond)
		}
		live.mu.Lock()
		closed := live.closed
		live.mu.Unlock()
		if closed != 1 {
			t.Fatalf("the adopted helper's handle was closed %d times, want once", closed)
		}
		if err := m.UnmountAll("sb-fake-exit"); err != nil {
			t.Fatalf("UnmountAll: %v", err)
		}
	})

	t.Run("stopped by UnmountAll", func(t *testing.T) {
		m, live := adopt(t, "sb-fake-stop", 4343, syscall.SIGTERM)
		if err := m.UnmountAll("sb-fake-stop"); err != nil {
			t.Fatalf("UnmountAll: %v", err)
		}
		live.mu.Lock()
		defer live.mu.Unlock()
		if !slices.Equal(live.signals, []syscall.Signal{syscall.SIGTERM}) || live.closed == 0 {
			t.Fatalf("signals = %v closed = %d, want SIGTERM and a close", live.signals, live.closed)
		}
		if !slices.Contains(*groups, "4343:"+syscall.SIGTERM.String()) {
			t.Fatalf("group signals = %v, want SIGTERM to group 4343", *groups)
		}
	})
}

// spawnHelper's cgroup branches with a stand-in cgroup directory and start,
// on any platform: a working clone keeps the cgroup; a refused one falls
// back to a plain start and turns it off; a tool that cannot start at all
// leaves it on.
func TestSpawnHelperCgroupBranches(t *testing.T) {
	prevOpen := openCgroupDir
	openCgroupDir = func(string) (*os.File, error) { return os.Open(t.TempDir()) }
	t.Cleanup(func() { openCgroupDir = prevOpen })

	run := func(t *testing.T, plan adapters.Plan, start func(attempt int, cmd *exec.Cmd) error) (*Manager, error) {
		t.Helper()
		m := newTestManager(t, nil)
		m.cgroup = newHelperCgroup(m.logger, "stand-in")
		attempt := 0
		prevStart := startCmd
		startCmd = func(cmd *exec.Cmd) error { attempt++; return start(attempt, cmd) }
		t.Cleanup(func() { startCmd = prevStart })
		cmd, _, exit, err := m.spawnHelper(plan, filepath.Join(t.TempDir(), "0.log"))
		if err == nil {
			if cmd.Process != nil {
				_ = killMount(cmd)
			}
			<-exit.done
		}
		return m, err
	}

	t.Run("clone accepted", func(t *testing.T) {
		// Pretend the clone worked: Wait on the unstarted command returns at once.
		m, err := run(t, adapters.Plan{Argv: []string{"true"}}, func(int, *exec.Cmd) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m.cgroup.fd(); !ok {
			t.Fatal("a working cgroup was turned off")
		}
	})
	t.Run("clone refused", func(t *testing.T) {
		m, err := run(t, adapters.Plan{Argv: []string{"true"}}, func(attempt int, cmd *exec.Cmd) error {
			if attempt == 1 {
				return errors.New("clone3 refused")
			}
			return cmd.Start()
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m.cgroup.fd(); ok {
			t.Fatal("the cgroup stayed on after the clone was refused")
		}
	})
	t.Run("tool cannot start", func(t *testing.T) {
		m, err := run(t, adapters.Plan{Argv: []string{"true"}}, func(int, *exec.Cmd) error { return errors.New("exec format error") })
		if err == nil || !strings.Contains(err.Error(), "exec format error") {
			t.Fatalf("err = %v, want the tool's start error", err)
		}
		if _, ok := m.cgroup.fd(); !ok {
			t.Fatal("a tool that cannot start turned the cgroup off")
		}
	})
}
