package isolate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// fakeJailLauncher is the root helper as a launched host sees it.
type fakeJailLauncher struct {
	mu     sync.Mutex
	run    string
	calls  []string
	limits []Limits
	groups []string
	proc   *launchedWorkerd
	fail   map[string]error
	// onStart runs as workerd starts: the test's controller.
	onStart func()
}

// launchedWorkerd is a held workerd that knows its start time.
type launchedWorkerd struct{ *heldWorkerd }

func (launchedWorkerd) StartTicks() uint64 { return 888 }

func newFakeJailLauncher(run string) *fakeJailLauncher {
	return &fakeJailLauncher{run: run, proc: &launchedWorkerd{newHeldWorkerd()}, fail: map[string]error{}}
}

func (l *fakeJailLauncher) note(c string) {
	l.mu.Lock()
	l.calls = append(l.calls, c)
	l.mu.Unlock()
}

func (l *fakeJailLauncher) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

func (l *fakeJailLauncher) Prepare(_ context.Context, group string) (string, error) {
	l.note("prepare " + group)
	return l.run, l.fail["prepare"]
}

func (l *fakeJailLauncher) Start(_ context.Context, group string, lim Limits) (hostproc.Process, error) {
	l.note("start " + group)
	if err := l.fail["start"]; err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.limits = append(l.limits, lim)
	l.mu.Unlock()
	if l.onStart != nil {
		l.onStart()
	}
	return l.proc, nil
}

func (l *fakeJailLauncher) SetLimits(_ context.Context, group string, lim Limits) error {
	l.note("limits " + group)
	l.mu.Lock()
	l.limits = append(l.limits, lim)
	l.mu.Unlock()
	return l.fail["limits"]
}

func (l *fakeJailLauncher) Stop(_ context.Context, group string) error {
	l.note("stop " + group)
	return l.fail["stop"]
}

func (l *fakeJailLauncher) Open(_ context.Context, group string, pid int, ticks uint64) (hostproc.Process, error) {
	l.note("open " + group)
	if err := l.fail["open"]; err != nil {
		return nil, err
	}
	return l.proc, nil
}

func (l *fakeJailLauncher) Groups(context.Context) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.groups), l.fail["groups"]
}

// launchedHost is a jailed host whose launcher is l, in a chroot under a
// short folder, as the V8 driver builds it in split mode.
func launchedHost(t *testing.T, l func(run string) *fakeJailLauncher) (*Host, *fakeJailLauncher) {
	t.Helper()
	chroot := shortRunDir(t)
	run := filepath.Join(chroot, JailRunDirName)
	if err := os.Mkdir(run, 0o770); err != nil {
		t.Fatal(err)
	}
	fl := l(run)
	h, err := NewHost(HostConfig{
		WorkerdPath:    "/workerd",
		GroupKey:       "tenant-a",
		RunDir:         run,
		EgressPoolSize: 2,
		StartTimeout:   2 * time.Second,
		RecordDir:      filepath.Join(chroot, "records"),
		Launcher:       fl,
		Jail:           JailConfig{Require: true, ChrootDir: chroot, UID: 1000, GID: 1000, CPUQuota: 0.5, MemoryLimitMB: 128, PidsMax: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, fl
}

func withBootID(t *testing.T) {
	t.Helper()
	old := hostBootID
	hostBootID = func() (string, error) { return "boot-1", nil }
	t.Cleanup(func() { hostBootID = old })
}

// TestLaunchedHostStartAndStop: in split mode the launcher builds the jail
// and runs workerd; the agent writes the config and binds the sockets in
// the run folder for the jail's group to read and dial, and never touches
// a chroot, a mount, a cgroup or a signal itself.
func TestLaunchedHostStartAndStop(t *testing.T) {
	withBootID(t)
	h, l := launchedHost(t, newFakeJailLauncher)
	l.onStart = func() { fakeController(t, h.controlSock) }
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := l.seen(); !slices.Equal(got, []string{"prepare tenant-a", "start tenant-a"}) {
		t.Fatalf("launcher calls %v", got)
	}
	if l.limits[0] != (Limits{CPU: 0.5, MemoryMB: 128, Pids: 64}) {
		t.Fatalf("start limits %+v", l.limits[0])
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(h.cfg.RunDir, "config.capnp"):       0o640,
		filepath.Join(h.cfg.RunDir, controllerModuleName): 0o640,
		h.hostSock:       0o660,
		h.egressDenySock: 0o660,
	} {
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s mode %o, want %o", path, st.Mode().Perm(), want)
		}
	}
	rec := readRecord(t, h.recordPath())
	if rec.PID != 4321 || rec.StartTicks != 888 || rec.BootID != "boot-1" || !rec.Jailed || rec.CgroupDir != "" {
		t.Fatalf("record %+v", rec)
	}
	if err := h.ApplyCaps(1, 256, 32); err != nil {
		t.Fatal(err)
	}
	if got := l.limits[len(l.limits)-1]; got != (Limits{CPU: 1, MemoryMB: 256, Pids: 32}) {
		t.Fatalf("caps %+v", got)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(l.seen(), "stop tenant-a") {
		t.Fatalf("Stop did not stop through the launcher: %v", l.seen())
	}
	if l.proc.killed() {
		t.Fatal("the agent signalled workerd itself")
	}
	if _, err := os.Stat(h.hostSock); !os.IsNotExist(err) {
		t.Fatal("the bundle socket outlived Stop")
	}
}

func TestLaunchedHostStartFailures(t *testing.T) {
	withBootID(t)
	boom := errors.New("boom")
	for _, tc := range []struct {
		name     string
		set      func(*Host, *fakeJailLauncher)
		want     string
		stopped  bool
		prepared bool
	}{
		{"prepare fails", func(_ *Host, l *fakeJailLauncher) { l.fail["prepare"] = boom }, "prepare group", false, true},
		{"the helper's run folder is another", func(_ *Host, l *fakeJailLauncher) { l.run = "/elsewhere/run" },
			"SB_ISOLATE_JAIL_CHROOT_BASE", true, true},
		{"start fails", func(_ *Host, l *fakeJailLauncher) { l.fail["start"] = boom }, "start group", true, true},
		{"workerd exits at once", func(_ *Host, l *fakeJailLauncher) { l.onStart = func() { close(l.proc.done) } },
			"exited during startup", true, true},
		{"a socket cannot be bound", func(h *Host, _ *fakeJailLauncher) {
			if err := os.Mkdir(h.hostSock, 0o700); err != nil {
				panic(err)
			}
			if err := os.WriteFile(filepath.Join(h.hostSock, "x"), nil, 0o600); err != nil {
				panic(err)
			}
		}, "listen bundle socket", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, l := launchedHost(t, newFakeJailLauncher)
			tc.set(h, l)
			err := h.Start(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Start = %v, want %q", err, tc.want)
			}
			if got := slices.Contains(l.seen(), "stop tenant-a"); got != tc.stopped {
				t.Fatalf("launcher stopped the group: %v, want %v (%v)", got, tc.stopped, l.seen())
			}
			if h.started.Load() {
				t.Fatal("a failed start counts as started")
			}
		})
	}
	t.Run("stop fails", func(t *testing.T) {
		h, l := launchedHost(t, newFakeJailLauncher)
		l.onStart = func() { fakeController(t, h.controlSock) }
		if err := h.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		l.fail["stop"] = boom
		if err := h.Stop(); err == nil || !errors.Is(err, boom) {
			t.Fatalf("Stop = %v, want the launcher's error", err)
		}
	})
	t.Run("a launched host is always jailed", func(t *testing.T) {
		if _, err := NewHost(HostConfig{WorkerdPath: "/workerd", GroupKey: "g", RunDir: "/r", Launcher: newFakeJailLauncher("/r")}); err == nil {
			t.Fatal("an unjailed launched host was made")
		}
	})
}

func TestShareWithJail(t *testing.T) {
	h, _ := launchedHost(t, newFakeJailLauncher)
	run := h.cfg.RunDir
	file := filepath.Join(run, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(run, "d")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	runSt, err := os.Lstat(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.grantJailAccess(run, file, sub, filepath.Join(run, "missing"), ""); err != nil {
		t.Fatal(err)
	}
	// The run folder is left as the launcher made it; a folder in it is
	// not the agent's to open.
	for path, want := range map[string]os.FileMode{run: runSt.Mode().Perm(), file: 0o640, sub: 0o700} {
		if st, _ := os.Lstat(path); st.Mode().Perm() != want {
			t.Errorf("%s mode %o, want %o", path, st.Mode().Perm(), want)
		}
	}
	if err := h.grantJailAccess(filepath.Join(file, "under-a-file")); err == nil {
		t.Fatal("a path under a file was taken for missing")
	}
}

// TestAdoptLaunchedHost: after an agent restart in split mode the record's
// workerd is held through the launcher, and one it cannot hold, or that
// does not answer, is stopped through it: the agent never kills or
// unmounts itself.
func TestAdoptLaunchedHost(t *testing.T) {
	withBootID(t)
	write := func(t *testing.T, records, chroot string) {
		t.Helper()
		if err := writeRecordFile(filepath.Join(records, "tenant-a.json"), hostRecord{
			GroupKey: "tenant-a", PID: 4321, StartTicks: 888, BootID: "boot-1", RunDir: filepath.Join(chroot, JailRunDirName),
			EgressPoolSize: 2, Jailed: true, ChrootDir: chroot, UID: 1000, GID: 1000, Loaded: []string{"sb-1"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T) (string, string, *fakeJailLauncher) {
		chroot := shortRunDir(t)
		if err := os.Mkdir(filepath.Join(chroot, JailRunDirName), 0o770); err != nil {
			t.Fatal(err)
		}
		records := filepath.Join(chroot, "records")
		write(t, records, chroot)
		return chroot, records, newFakeJailLauncher(filepath.Join(chroot, JailRunDirName))
	}
	t.Run("taken over", func(t *testing.T) {
		chroot, records, l := setup(t)
		fakeController(t, filepath.Join(chroot, JailRunDirName, controlSocketName))
		adopted := AdoptHosts(context.Background(), HostConfig{RecordDir: records, Launcher: l})
		if len(adopted) != 1 || adopted[0].Host.PID() != 4321 {
			t.Fatalf("adopted %+v", adopted)
		}
		if got := l.seen(); !slices.Equal(got, []string{"open tenant-a"}) {
			t.Fatalf("launcher calls %v", got)
		}
		if adopted[0].Host.jail != nil {
			t.Fatal("an adopted launched host holds a jail of its own to tear down")
		}
		sock := filepath.Join(chroot, JailRunDirName, hostSocketName)
		if st, err := os.Lstat(sock); err != nil || st.Mode().Perm() != 0o660 {
			t.Fatalf("bundle socket %v %v", st, err)
		}
		if err := adopted[0].Host.Stop(); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(l.seen(), "stop tenant-a") {
			t.Fatalf("no stop: %v", l.seen())
		}
	})
	t.Run("gone", func(t *testing.T) {
		_, records, l := setup(t)
		l.fail["open"] = hostproc.ErrGone
		if adopted := AdoptHosts(context.Background(), HostConfig{RecordDir: records, Launcher: l}); len(adopted) != 0 {
			t.Fatalf("adopted %+v", adopted)
		}
		if got := l.seen(); !slices.Equal(got, []string{"open tenant-a", "stop tenant-a"}) {
			t.Fatalf("launcher calls %v", got)
		}
	})
	t.Run("silent", func(t *testing.T) {
		_, records, l := setup(t)
		// No controller answers.
		if adopted := AdoptHosts(context.Background(), HostConfig{RecordDir: records, Launcher: l}); len(adopted) != 0 {
			t.Fatalf("adopted %+v", adopted)
		}
		if got := l.seen(); !slices.Equal(got, []string{"open tenant-a", "stop tenant-a"}) || l.proc.killed() {
			t.Fatalf("launcher calls %v, killed by the agent %v", got, l.proc.killed())
		}
	})
}

func TestSweepLaunched(t *testing.T) {
	l := newFakeJailLauncher("/r")
	l.groups = []string{"kept", "left", "../bad", "warm-1"}
	n := SweepLeftovers(Leftovers{Launcher: l, Keep: map[string]bool{"kept": true},
		// The single-mode places are never touched with a launcher.
		JailCgroupRoot: "/sys/fs/cgroup/never", JailChrootBase: "/never"})
	if n != 2 || !slices.Equal(l.seen(), []string{"stop left", "stop warm-1"}) {
		t.Fatalf("swept %d: %v", n, l.seen())
	}
	l = newFakeJailLauncher("/r")
	l.groups = []string{"a"}
	l.fail["stop"] = errors.New("boom")
	if n := SweepLeftovers(Leftovers{Launcher: l}); n != 0 {
		t.Fatalf("counted a failed stop: %d", n)
	}
	l.fail["groups"] = errors.New("boom")
	if n := SweepLeftovers(Leftovers{Launcher: l}); n != 0 {
		t.Fatalf("swept with no list: %d", n)
	}
}
