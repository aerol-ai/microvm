package supervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSelfCgroup(t *testing.T) {
	for _, tc := range []struct{ in, want, err string }{
		{in: "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-ab.scope\n", want: "/kubepods.slice/kubepods-pod1.slice/cri-containerd-ab.scope"},
		{in: "0::/\n", want: ""},
		{in: "12:pids:/x\n0::/a/b/\n", want: "/a/b"},
		{in: "12:pids:/x\n1:name=systemd:/x\n", err: "needs cgroup v2"},
	} {
		got, err := SelfCgroup([]byte(tc.in))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: err = %v, want %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q = %q %v, want %q", tc.in, got, err, tc.want)
		}
	}
}

// fakeCgroup lays out a container group with processes and a memory limit,
// and makes moving a process take it out of the old group, as the kernel does.
func fakeCgroup(t *testing.T, self, memoryMax string, pids ...string) Layout {
	t.Helper()
	l := Layout{Root: t.TempDir(), Self: self}
	if err := os.MkdirAll(l.dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, v string) {
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(l.dir("cgroup.procs"), strings.Join(pids, "\n"))
	if memoryMax != "" {
		write(l.dir("memory.max"), memoryMax+"\n")
	}
	orig := moveProc
	t.Cleanup(func() { moveProc = orig })
	moveProc = func(to, pid string) error {
		raw, _ := os.ReadFile(l.dir("cgroup.procs"))
		var left []string
		for _, p := range strings.Fields(string(raw)) {
			if p != pid {
				left = append(left, p)
			}
		}
		write(l.dir("cgroup.procs"), strings.Join(left, "\n"))
		old, _ := os.ReadFile(to)
		return os.WriteFile(to, append(old, []byte(pid+"\n")...), 0o644)
	}
	return l
}

func read(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// The shape spike S3 settled on: processes out of the container's group,
// controllers handed down, group OOM kills off above the sandboxes, and
// sandboxes/ capped at the limit less a 10% reserve between 1 and 4 GiB.
func TestSetupShape(t *testing.T) {
	const gib = int64(1) << 30
	for _, tc := range []struct {
		name               string
		self, memoryMax    string
		wantCap, wantRsrv  int64
		wantPodOOMGroupSet bool
	}{
		{name: "a 12 GiB container", self: "/kubepods/pod1/ctr", memoryMax: "12884901888", wantCap: 12*gib - 12*gib/10, wantRsrv: 12 * gib / 10, wantPodOOMGroupSet: true},
		{name: "the reserve is at least 1 GiB", self: "/kubepods/pod1/ctr", memoryMax: "4294967296", wantCap: 3 * gib, wantRsrv: gib, wantPodOOMGroupSet: true},
		{name: "and at most 4 GiB", self: "/kubepods/pod1/ctr", memoryMax: "107374182400", wantCap: 96 * gib, wantRsrv: 4 * gib, wantPodOOMGroupSet: true},
		{name: "no limit, no cap", self: "/kubepods/pod1/ctr", memoryMax: "max", wantPodOOMGroupSet: true},
		{name: "a limit below the reserve, no cap", self: "/kubepods/pod1/ctr", memoryMax: "536870912", wantPodOOMGroupSet: true},
		{name: "its own cgroup namespace", self: "", memoryMax: "12884901888", wantCap: 12*gib - 12*gib/10, wantRsrv: 12 * gib / 10},
		{name: "an unreadable limit, no cap", self: "/kubepods/pod1/ctr", wantPodOOMGroupSet: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := fakeCgroup(t, tc.self, tc.memoryMax, "1", "7")
			shape, err := Setup(l, quiet())
			if err != nil {
				t.Fatal(err)
			}
			if want := filepath.Join("/", tc.self, "sandboxes"); shape.Parent != want {
				t.Fatalf("Parent = %q, want %q", shape.Parent, want)
			}
			if got := read(t, l.dir("supervisor", "cgroup.procs")); got != "1\n7" {
				t.Fatalf("supervisor/ holds %q, want both processes", got)
			}
			if got := read(t, l.dir("cgroup.procs")); got != "" {
				t.Fatalf("the container's group still holds %q", got)
			}
			for _, d := range []string{l.dir(), l.dir("sandboxes")} {
				if got := read(t, filepath.Join(d, "cgroup.subtree_control")); got != "+cpu +memory +pids" {
					t.Fatalf("%s hands down %q", d, got)
				}
			}
			for _, d := range []string{l.dir(), l.dir("sandboxes"), l.RuntimeDir()} {
				if got := read(t, filepath.Join(d, "memory.oom.group")); got != "0" {
					t.Fatalf("%s memory.oom.group = %q, want 0", d, got)
				}
			}
			podOOM := filepath.Join(l.Root, "kubepods", "pod1", "memory.oom.group")
			if _, err := os.Stat(podOOM); (err == nil) != tc.wantPodOOMGroupSet {
				t.Fatalf("pod group's oom.group written = %v, want %v", err == nil, tc.wantPodOOMGroupSet)
			}
			if shape.CapBytes != tc.wantCap || shape.ReserveBytes != tc.wantRsrv {
				t.Fatalf("cap %d reserve %d, want %d %d", shape.CapBytes, shape.ReserveBytes, tc.wantCap, tc.wantRsrv)
			}
			_, capErr := os.Stat(l.dir("sandboxes", "memory.max"))
			if (capErr == nil) != (tc.wantCap > 0) {
				t.Fatalf("sandboxes/memory.max written = %v, want %v", capErr == nil, tc.wantCap > 0)
			}
			if tc.wantCap > 0 && read(t, l.dir("supervisor", "memory.min")) == "" {
				t.Fatal("no reserve kept for the machinery")
			}
		})
	}
}

func TestSetupFailures(t *testing.T) {
	t.Run("controllers cannot be handed down", func(t *testing.T) {
		l := fakeCgroup(t, "/c", "max")
		if err := os.Mkdir(l.dir("cgroup.subtree_control"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Setup(l, quiet()); err == nil || !strings.Contains(err.Error(), "hand +cpu +memory +pids down") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a process cannot be moved", func(t *testing.T) {
		l := fakeCgroup(t, "/c", "max", "9")
		moveProc = func(string, string) error { return errors.New("EBUSY") }
		if _, err := Setup(l, quiet()); err == nil || !strings.Contains(err.Error(), "move process 9") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a process that exited is fine", func(t *testing.T) {
		l := fakeCgroup(t, "/c", "max", "9")
		calls := 0
		moveProc = func(string, string) error {
			calls++
			_ = os.WriteFile(l.dir("cgroup.procs"), nil, 0o644)
			return os.NewSyscallError("write", errESRCH)
		}
		if _, err := Setup(l, quiet()); err != nil || calls != 1 {
			t.Fatalf("err = %v after %d moves", err, calls)
		}
	})
	t.Run("processes keep appearing", func(t *testing.T) {
		l := fakeCgroup(t, "/c", "max", "9")
		moveProc = func(string, string) error { return nil }
		if _, err := Setup(l, quiet()); err == nil || !strings.Contains(err.Error(), "keep appearing") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the folders cannot be made", func(t *testing.T) {
		l := Layout{Root: filepath.Join(t.TempDir(), "file"), Self: "/c"}
		if err := os.WriteFile(l.Root, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Setup(l, quiet()); err == nil || !strings.Contains(err.Error(), "make ") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the process list cannot be read", func(t *testing.T) {
		l := Layout{Root: t.TempDir(), Self: "/c"}
		if _, err := Setup(l, quiet()); err == nil || !strings.Contains(err.Error(), "list this container's processes") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCgroupReadOnly(t *testing.T) {
	ro := "30 25 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n"
	rw := "30 25 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n"
	other := "29 25 0:25 / /sys rw,nosuid - sysfs sysfs rw\n"
	if !CgroupReadOnly([]byte(other+ro), CgroupRoot) || CgroupReadOnly([]byte(other+rw), CgroupRoot) || CgroupReadOnly([]byte(other), CgroupRoot) {
		t.Fatal("read-only detection is wrong")
	}
}

func TestWriteParentFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "run", "aerolvm", "cgroup-parent")
	if err := WriteParentFile(f, "/k/sandboxes"); err != nil || read(t, f) != "/k/sandboxes" {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(f + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary file was left behind")
	}
	blocked := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(blocked, nil, 0o644)
	if err := WriteParentFile(filepath.Join(blocked, "y", "z"), "/p"); err == nil {
		t.Fatal("a parent under a file was written")
	}
}

func TestSettingsFromEnv(t *testing.T) {
	t.Setenv("SB_CONTAINERD_BINARY", "")
	t.Setenv("SB_CONTAINERD_CONFIG", " /etc/c.toml ")
	t.Setenv("SB_CGROUP_PARENT_FILE", "")
	t.Setenv("SB_OWNERSHIP_LEASE_FILE", "")
	s := SettingsFromEnv()
	if s.ContainerdBinary != "containerd" || s.ContainerdConfig != "/etc/c.toml" || s.ParentFile != "/run/aerolvm/cgroup-parent" || s.NetnsDir != "/run/netns" || s.LeaseFile != "" {
		t.Fatalf("%+v", s)
	}
	t.Setenv("SB_OWNERSHIP_LEASE_FILE", "/run/aerolvm/ownership-lease")
	if s := SettingsFromEnv(); s.LeaseFile != "/run/aerolvm/ownership-lease" {
		t.Fatalf("lease file %q", s.LeaseFile)
	}
	if s.IsolateJailDir != "" {
		t.Fatalf("isolate jail dir %q without SB_ISOLATE_JAIL_DIR", s.IsolateJailDir)
	}
	t.Setenv("SB_ISOLATE_JAIL_DIR", "/var/lib/sandboxd/isolate-jail")
	if s := SettingsFromEnv(); s.IsolateJailDir != "/var/lib/sandboxd/isolate-jail" {
		t.Fatalf("isolate jail dir %q", s.IsolateJailDir)
	}
	// The external-storage folder and the pid file are off unless the pod
	// names them.
	t.Setenv("SB_MOUNTS_DIR", "")
	t.Setenv("SB_RUNTIME_PID_FILE", "")
	if s := SettingsFromEnv(); s.MountsDir != "" || s.PIDFile != "" {
		t.Fatalf("mounts dir %q, pid file %q without their settings", s.MountsDir, s.PIDFile)
	}
	t.Setenv("SB_MOUNTS_DIR", "/var/lib/sandboxd/mounts")
	t.Setenv("SB_RUNTIME_PID_FILE", "/run/aerolvm/runtime.pid")
	if s := SettingsFromEnv(); s.MountsDir != "/var/lib/sandboxd/mounts" || s.PIDFile != "/run/aerolvm/runtime.pid" {
		t.Fatalf("mounts dir %q, pid file %q", s.MountsDir, s.PIDFile)
	}
}

// fakeClock fires each After at once and records the waits.
type fakeClock struct {
	now   time.Time
	waits []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.waits = append(c.waits, d)
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

// containerd is started again each time it exits, with a wait that doubles
// to the cap and resets after a healthy run; a failed start is retried; the
// supervisor stopping stops containerd.
func TestKeeper(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	exited := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var starts, stopped int
	runFor := []time.Duration{time.Second, time.Second, time.Second, 2 * time.Minute, time.Second}
	k := &Keeper{
		Start: func() (int, error) {
			starts++
			if starts == 3 {
				return 0, errors.New("exec: containerd: not found")
			}
			if starts == 7 {
				cancel() // the supervisor is told to stop while containerd runs
				return 107, nil
			}
			pid := 100 + starts
			go func(d time.Duration) {
				clock.now = clock.now.Add(d)
				exited <- 999 // an orphaned shim: ignored
				exited <- pid
			}(runFor[min(starts-1, len(runFor)-1)])
			return pid, nil
		},
		Exited:       exited,
		Stop:         func(pid int) { stopped = pid },
		Log:          quiet(),
		MinBackoff:   2 * time.Second,
		MaxBackoff:   8 * time.Second,
		HealthyAfter: time.Minute,
		Now:          clock.Now,
		After:        clock.After,
	}
	done := make(chan struct{})
	go func() { k.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context ended")
	}
	if stopped != 107 {
		t.Fatalf("stopped %d, want the running containerd 107", stopped)
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	if len(clock.waits) != len(want) {
		t.Fatalf("waits %v, want %v", clock.waits, want)
	}
	for i := range want {
		if clock.waits[i] != want[i] {
			t.Fatalf("waits %v, want %v", clock.waits, want)
		}
	}
}

// The context ending during a wait returns without another start.
func TestKeeperStopsWhileWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	starts := 0
	k := &Keeper{
		Start:      func() (int, error) { starts++; cancel(); return 0, errors.New("no") },
		Exited:     make(chan int),
		Stop:       func(int) { t.Fatal("nothing to stop") },
		Log:        quiet(),
		MinBackoff: time.Hour, MaxBackoff: time.Hour,
	}
	k.Run(ctx)
	if starts != 1 {
		t.Fatalf("%d starts, want 1", starts)
	}
}

// Run end to end with the machine faked: the mount made writable, the shape
// built, the parent published, the config written, containerd started in
// _runtime, and stopped when the supervisor is.
func TestRun(t *testing.T) {
	l := fakeCgroup(t, "/kubepods/pod1/ctr", "12884901888", "1")
	dir := t.TempDir()
	netns := filepath.Join(dir, "netns")
	_ = os.MkdirAll(netns, 0o755)
	for _, n := range []string{"aerol-netns-0", "aerol-netns-1"} {
		_ = os.WriteFile(filepath.Join(netns, n), nil, 0o644)
	}
	s := Settings{ContainerdBinary: "/opt/containerd", ContainerdConfig: filepath.Join(dir, "etc", "config.toml"), ParentFile: filepath.Join(dir, "run", "cgroup-parent"), NetnsDir: netns,
		LeaseFile: filepath.Join(dir, "ownership-lease"), IsolateJailDir: "/var/lib/sandboxd/isolate-jail",
		MountsDir: "/var/lib/sandboxd/mounts", PIDFile: filepath.Join(dir, "run", "runtime.pid")}
	// A lease that already ran out, fencing one sandbox: the guard Run
	// starts freezes it (T3).
	if err := os.MkdirAll(filepath.Join(l.Root, "kubepods/pod1/ctr/sandboxes/sb-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ownerlease.Write(s.LeaseFile, ownerlease.Lease{ConfirmedUnixMs: 1, WrittenUnixMs: 15_001, LeaseMs: 15_000, Fence: []string{"sb-1"}}); err != nil {
		t.Fatal(err)
	}
	froze := make(chan string, 1)
	var unmounted []string
	ctx, cancel := context.WithCancel(context.Background())
	var remounted bool
	var startedIn string
	var startedArgv []string
	var terminated atomic.Int64
	sys := OS{
		CgroupRoot: l.Root,
		ReadFile: func(p string) ([]byte, error) {
			switch p {
			case "/proc/self/mountinfo":
				return []byte("30 25 0:26 / " + l.Root + " ro,nosuid - cgroup2 cgroup rw\n" +
					"31 25 0:40 / /var/lib/sandboxd/isolate-jail/g1/run rw,noexec shared:7 - tmpfs tmpfs rw\n" +
					"32 25 0:60 / /var/lib/sandboxd/mounts/sb-1/0 rw,nosuid shared:9 - fuse.rclone store: rw\n"), nil
			case "/proc/self/cgroup":
				return []byte("0::/kubepods/pod1/ctr\n"), nil
			}
			return os.ReadFile(p)
		},
		Remount:       func() error { remounted = true; return nil },
		LowerOOM:      func() error { return errors.New("no /proc here") },
		BecomeReaper:  func() error { return nil },
		DefaultConfig: func(bin string) ([]byte, error) { return []byte("version = 3 # " + bin), nil },
		StartInGroup: func(d string, argv []string) (int, error) {
			startedIn, startedArgv = d, argv
			cancel()
			return 4242, nil
		},
		Terminate: func(pid int) { terminated.Store(int64(pid)) },
		Unmount: func(p string) error {
			if terminated.Load() == 0 {
				t.Error("a namespace was unmounted while containerd still ran")
			}
			unmounted = append(unmounted, filepath.Base(p))
			return nil
		},
		Reap: func(*atomic.Int64, chan<- int, *slog.Logger) {},
		SetFrozen: func(d string, frozen bool) error {
			if frozen {
				froze <- d
			}
			return nil
		},
	}
	var logs bytes.Buffer
	if err := Run(ctx, s, sys, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-froze:
		if d != filepath.Join(l.Root, "kubepods/pod1/ctr/sandboxes/sb-1") {
			t.Fatalf("froze %s", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lease guard never froze the fenced sandbox")
	}
	if !remounted {
		t.Fatal("a read-only cgroup mount was not made writable")
	}
	if read(t, s.ParentFile) != "/kubepods/pod1/ctr/sandboxes" {
		t.Fatalf("parent file = %q", read(t, s.ParentFile))
	}
	if read(t, s.ContainerdConfig) != "version = 3 # /opt/containerd" {
		t.Fatal("the default containerd config was not written")
	}
	if startedIn != l.RuntimeDir() || strings.Join(startedArgv, " ") != "/opt/containerd --config "+s.ContainerdConfig {
		t.Fatalf("started %v in %s", startedArgv, startedIn)
	}
	if terminated.Load() != 4242 {
		t.Fatal("containerd was not stopped with the supervisor")
	}
	if !strings.Contains(logs.String(), "could not lower its own OOM score") {
		t.Fatal("a failed OOM score change was not logged")
	}
	if strings.Join(unmounted, ",") != "aerol-netns-0,aerol-netns-1,run,0" {
		t.Fatalf("unmounted %v, want both namespaces, the V8 jail's tmpfs and the sandbox's storage after containerd stopped (findings F8, F13)", unmounted)
	}
	// sandboxd checks an external mount through this pid's view (F13).
	if read(t, s.PIDFile) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("pid file = %q, want %d", read(t, s.PIDFile), os.Getpid())
	}
}

// A pid file that cannot be written does not stop the runtime: restarting
// it would end every sandbox, and sandboxd refuses external mounts without
// the file. It is logged.
func TestRunPIDFileNotWritable(t *testing.T) {
	l := fakeCgroup(t, "/kubepods/pod1/ctr", "12884901888", "1")
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s := Settings{ContainerdBinary: "/opt/containerd", ContainerdConfig: filepath.Join(dir, "config.toml"), ParentFile: filepath.Join(dir, "parent"),
		NetnsDir: filepath.Join(dir, "netns"), PIDFile: filepath.Join(blocker, "runtime.pid")}
	ctx, cancel := context.WithCancel(context.Background())
	sys := OS{
		CgroupRoot: l.Root,
		ReadFile: func(p string) ([]byte, error) {
			switch p {
			case "/proc/self/mountinfo":
				return nil, nil
			case "/proc/self/cgroup":
				return []byte("0::/kubepods/pod1/ctr\n"), nil
			}
			return os.ReadFile(p)
		},
		Remount:       func() error { return nil },
		LowerOOM:      func() error { return nil },
		BecomeReaper:  func() error { return nil },
		DefaultConfig: func(string) ([]byte, error) { return []byte("version = 3"), nil },
		StartInGroup:  func(string, []string) (int, error) { cancel(); return 4242, nil },
		Terminate:     func(int) {},
		Unmount:       func(string) error { return nil },
		Reap:          func(*atomic.Int64, chan<- int, *slog.Logger) {},
		SetFrozen:     func(string, bool) error { return nil },
	}
	var logs bytes.Buffer
	if err := Run(ctx, s, sys, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("Run stopped on a pid file it could not write: %v", err)
	}
	if !strings.Contains(logs.String(), "could not publish its pid") {
		t.Fatalf("logs: %s", logs.String())
	}
}

func TestUnmountNamespaces(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	UnmountNamespaces(filepath.Join(t.TempDir(), "missing"), func(string) error { t.Fatal("nothing to unmount"); return nil }, log)
	if logs.Len() != 0 {
		t.Fatalf("a missing folder was reported: %s", logs.String())
	}
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		_ = os.WriteFile(filepath.Join(dir, n), nil, 0o644)
	}
	UnmountNamespaces(dir, func(p string) error {
		if filepath.Base(p) == "a" {
			return errors.New("EBUSY")
		}
		return nil
	}, log)
	if !strings.Contains(logs.String(), "could not unmount a network namespace") || !strings.Contains(logs.String(), "count=1") {
		t.Fatalf("logs: %s", logs.String())
	}
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, nil, 0o644)
	logs.Reset()
	UnmountNamespaces(file, func(string) error { return nil }, log)
	if !strings.Contains(logs.String(), "could not list network namespaces") {
		t.Fatalf("a folder that cannot be listed was not reported: %s", logs.String())
	}
}

func TestRunFailures(t *testing.T) {
	base := func(t *testing.T) (Settings, OS) {
		l := fakeCgroup(t, "/c", "max")
		dir := t.TempDir()
		return Settings{ContainerdBinary: "containerd", ContainerdConfig: filepath.Join(dir, "config.toml"), ParentFile: filepath.Join(dir, "parent")},
			OS{
				CgroupRoot: l.Root,
				ReadFile: func(p string) ([]byte, error) {
					switch p {
					case "/proc/self/mountinfo":
						return nil, errors.New("none")
					case "/proc/self/cgroup":
						return []byte("0::/c\n"), nil
					}
					return os.ReadFile(p)
				},
				LowerOOM: func() error { return nil }, BecomeReaper: func() error { return errors.New("EPERM") },
				DefaultConfig: func(string) ([]byte, error) { return nil, errors.New("exec: not found") },
			}
	}
	for _, tc := range []struct {
		name  string
		tweak func(*Settings, *OS)
		want  string
	}{
		{name: "a read-only mount that cannot be remounted", tweak: func(_ *Settings, o *OS) {
			o.ReadFile = func(p string) ([]byte, error) {
				return []byte("30 25 0:26 / " + o.CgroupRoot + " ro - cgroup2 cgroup rw\n"), nil
			}
			o.Remount = func() error { return errors.New("EPERM") }
		}, want: "could not be made writable"},
		{name: "no /proc/self/cgroup", tweak: func(_ *Settings, o *OS) {
			o.ReadFile = func(string) ([]byte, error) { return nil, errors.New("ENOENT") }
		}, want: "ENOENT"},
		{name: "cgroup v1", tweak: func(_ *Settings, o *OS) {
			o.ReadFile = func(p string) ([]byte, error) {
				if p == "/proc/self/cgroup" {
					return []byte("1:cpu:/x\n"), nil
				}
				return nil, errors.New("none")
			}
		}, want: "needs cgroup v2"},
		{name: "setup fails", tweak: func(_ *Settings, o *OS) { o.CgroupRoot = "/dev/null/x" }, want: "cgroup setup"},
		{name: "the parent cannot be published", tweak: func(s *Settings, _ *OS) { s.ParentFile = "/dev/null/x/parent" }, want: "publish the cgroup parent"},
		{name: "no containerd to make a config", want: "containerd config default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, o := base(t)
			if tc.tweak != nil {
				tc.tweak(&s, &o)
			}
			if err := Run(context.Background(), s, o, quiet()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSetupBestEffortAndCapFailure(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	l := fakeCgroup(t, "/c", "12884901888")
	for _, d := range []string{l.dir("memory.oom.group"), l.dir("supervisor", "memory.min")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Setup(l, log); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"could not turn off group OOM kills", "could not keep the reserve"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log lacks %q: %s", want, logs.String())
		}
	}
	l2 := fakeCgroup(t, "/c", "12884901888")
	if err := os.MkdirAll(l2.dir("sandboxes", "memory.max"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(l2, quiet()); err == nil || !strings.Contains(err.Error(), "cap sandboxes/") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureConfigAndRealOS(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(existing, []byte("mine"), 0o644)
	never := OS{DefaultConfig: func(string) ([]byte, error) { t.Fatal("an existing config was replaced"); return nil, nil }}
	if err := ensureConfig(Settings{ContainerdConfig: existing}, never); err != nil || read(t, existing) != "mine" {
		t.Fatalf("err %v", err)
	}
	ok := OS{DefaultConfig: func(string) ([]byte, error) { return []byte("x"), nil }}
	if err := ensureConfig(Settings{ContainerdConfig: filepath.Join(existing, "sub", "c.toml")}, ok); err == nil {
		t.Fatal("a config under a file was written")
	}
	sys := RealOS()
	if sys.CgroupRoot != CgroupRoot || sys.ReadFile == nil || sys.Remount == nil || sys.StartInGroup == nil || sys.Reap == nil {
		t.Fatal("RealOS is incomplete")
	}
	if _, err := sys.DefaultConfig(filepath.Join(dir, "no-such-containerd")); err == nil {
		t.Fatal("a missing containerd printed a config")
	}
}

func TestWriteParentFileOverAFolder(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cgroup-parent")
	if err := os.MkdirAll(filepath.Join(f, "busy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteParentFile(f, "/p"); err == nil {
		t.Fatal("renamed over a folder that holds files")
	}
}

// At pod end every mount below the V8 jail's chroot base goes, deepest
// first: the tmpfs on each group's run and tmp folders, found in the mount
// table, not the base itself and not a sibling folder (C14).
func TestUnmountUnder(t *testing.T) {
	const base = "/var/lib/sandboxd/isolate-jail"
	table := strings.Join([]string{
		"36 35 98:0 / " + base + " rw,relatime shared:1 - ext4 /dev/root rw",
		"37 36 0:51 / " + base + "/g1/run rw,nosuid,nodev,noexec shared:2 - tmpfs tmpfs rw",
		"38 37 0:52 / " + base + "/g1/run/inner rw shared:3 - tmpfs tmpfs rw",
		"39 36 0:53 / " + base + "/g1/tmp rw shared:4 - tmpfs tmpfs rw",
		`40 36 0:54 / ` + base + `/g\0402/run rw shared:5 - tmpfs tmpfs rw`,
		"41 1 0:55 / " + base + "x/other rw - tmpfs tmpfs rw",
		"42 1 0:4 / /run/netns/sb-1 rw - nsfs nsfs rw",
		"short line",
	}, "\n")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	var got []string
	UnmountUnder(base+"/", "V8 jail", []byte(table), func(p string) error {
		got = append(got, p)
		if strings.HasSuffix(p, "/tmp") {
			return errors.New("EBUSY")
		}
		return nil
	}, log)
	if len(got) != 4 || got[0] != base+"/g1/run/inner" {
		t.Fatalf("unmounted %v; want the 4 mounts below the base, deepest first", got)
	}
	want := map[string]bool{base + "/g1/run/inner": true, base + "/g1/run": true, base + "/g1/tmp": true, base + "/g 2/run": true}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("unmounted %q, which is not below the jail base", p)
		}
	}
	if !strings.Contains(logs.String(), "could not unmount a V8 jail mount") || !strings.Contains(logs.String(), "count=3") {
		t.Fatalf("logs: %s", logs.String())
	}
	logs.Reset()
	UnmountUnder(base, "V8 jail", []byte("42 1 0:4 / /run/netns/sb-1 rw - nsfs nsfs rw\n"), func(string) error { t.Fatal("nothing to unmount"); return nil }, log)
	if logs.Len() != 0 {
		t.Fatalf("nothing to unmount was reported: %s", logs.String())
	}
}
