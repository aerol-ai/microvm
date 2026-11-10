package hostproc

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeProc points ProcRoot at a temp dir holding one fake process.
func fakeProc(t *testing.T, pid int, stat, cmdline string) {
	t.Helper()
	root := t.TempDir()
	old := ProcRoot
	ProcRoot = root
	t.Cleanup(func() { ProcRoot = old })
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if stat != "" {
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if cmdline != "" {
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/kernel/random"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/kernel/random/boot_id"), []byte("boot-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cgFDSupported: only Linux asks the clone for a cgroup.
func cgFDSupported() bool { return runtime.GOOS == "linux" }

func TestProcFilesParse(t *testing.T) {
	// The command name holds spaces and a ')': the fields start past the
	// last one.
	stat := "42 (sand box) x) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10\n"
	fakeProc(t, 42, stat, "sandboxd\x00--wasm-worker\x00/run/x.sock\x00")
	ticks, err := StartTicks(42)
	if err != nil || ticks != 98765 {
		t.Fatalf("StartTicks = %d, %v", ticks, err)
	}
	argv, err := Cmdline(42)
	if err != nil || len(argv) != 3 || argv[1] != "--wasm-worker" {
		t.Fatalf("Cmdline = %q, %v", argv, err)
	}
	boot, err := BootID()
	if err != nil || boot != "boot-1" {
		t.Fatalf("BootID = %q, %v", boot, err)
	}
	if _, err := StartTicks(7); err == nil {
		t.Fatal("StartTicks of a missing pid succeeded")
	}
	if _, err := Cmdline(7); err == nil {
		t.Fatal("Cmdline of a missing pid succeeded")
	}
}

func TestProcFilesMalformed(t *testing.T) {
	cases := map[string]string{
		"no paren":  "42 sandboxd S 1",
		"short":     "42 (x) S 1 2 3",
		"not a num": "42 (x) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 zz 1000 10",
	}
	for name, stat := range cases {
		t.Run(name, func(t *testing.T) {
			fakeProc(t, 42, stat, "")
			if _, err := StartTicks(42); err == nil {
				t.Fatal("malformed stat parsed")
			}
		})
	}
	// A kernel thread has an empty cmdline.
	fakeProc(t, 43, "", "\x00")
	argv, err := Cmdline(43)
	if err != nil || argv != nil {
		t.Fatalf("empty cmdline = %q, %v", argv, err)
	}
	old := ProcRoot
	ProcRoot = t.TempDir()
	defer func() { ProcRoot = old }()
	if _, err := BootID(); err == nil {
		t.Fatal("BootID without procfs succeeded")
	}
}

func TestReadPIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup.procs")
	if pids, err := ReadPIDs(path); err != nil || pids != nil {
		t.Fatalf("missing procs = %v, %v", pids, err)
	}
	if err := os.WriteFile(path, []byte("12\n0\nx\n34\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pids, err := ReadPIDs(path)
	if err != nil || len(pids) != 2 || pids[0] != 12 || pids[1] != 34 {
		t.Fatalf("pids = %v, %v", pids, err)
	}
	if _, err := ReadPIDs(dir); err == nil {
		t.Fatal("reading a directory succeeded")
	}
	var nilCg *Cgroup
	if pids, err := nilCg.PIDs(); err != nil || pids != nil {
		t.Fatalf("nil cgroup pids = %v, %v", pids, err)
	}
	cg := NewCgroup(nil, dir, "", "tests")
	if pids, err := cg.PIDs(); err != nil || len(pids) != 2 {
		t.Fatalf("cgroup pids = %v, %v", pids, err)
	}
}

// TestCgroupOffAndDisable: a root without cgroup v2 turns the cgroup off,
// logs once, and every start is a plain one.
func TestCgroupOffAndDisable(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	cg := NewCgroup(logger, t.TempDir(), "aerolvm-test", "test workers")
	if cg.Path() == "" || filepath.Base(cg.Path()) != "aerolvm-test" {
		t.Fatalf("Path = %q", cg.Path())
	}
	if cg.Active() {
		t.Fatal("cgroup active without a cgroup v2 root")
	}
	if _, ok := cg.FD(); ok {
		t.Fatal("FD without a cgroup")
	}
	cg.Disable(errors.New("again"))
	if n := strings.Count(logged.String(), "test workers run in sandboxd's cgroup"); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, logged.String())
	}
	var nilCg *Cgroup
	if nilCg.Path() != "" || nilCg.Active() {
		t.Fatal("nil cgroup is not empty")
	}
	nilCg.Disable(errors.New("x"))
	if NewCgroup(nil, "", "n", "w").root != CgroupRoot {
		t.Fatal("empty root does not default")
	}

	var started int
	old := startCmd
	startCmd = func(*exec.Cmd) error { started++; return nil }
	defer func() { startCmd = old }()
	cmd, err := cg.Start(func() (*exec.Cmd, error) { return exec.Command("true"), nil })
	if err != nil || cmd == nil || started != 1 {
		t.Fatalf("plain start = %v, %v, starts %d", cmd, err, started)
	}
	if inCgroup(cmd) {
		t.Fatal("plain start asked for a cgroup")
	}
	if _, err := cg.Start(func() (*exec.Cmd, error) { return nil, errors.New("build") }); err == nil {
		t.Fatal("a failed build started")
	}
}

// TestCgroupStartFallsBack: when the clone into the cgroup fails and a plain
// start works, the cgroup was the problem: it goes off for good.
func TestCgroupStartFallsBack(t *testing.T) {
	cg := NewCgroup(slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)), t.TempDir(), "aerolvm-test", "test workers")
	// Stand in an open cgroup directory.
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cg.setup.Do(func() {})
	cg.dir = dir

	var mu sync.Mutex
	var attempts []bool
	old := startCmd
	defer func() { startCmd = old }()
	startCmd = func(cmd *exec.Cmd) error {
		mu.Lock()
		defer mu.Unlock()
		inCg := inCgroup(cmd)
		attempts = append(attempts, inCg)
		if inCg {
			return syscall.EINVAL
		}
		return nil
	}
	if _, ok := cg.FD(); !ok && cgFDSupported() {
		t.Fatal("stand-in cgroup not active")
	}
	cmd, err := cg.Start(func() (*exec.Cmd, error) { return exec.Command("true"), nil })
	if err != nil || cmd == nil {
		t.Fatalf("Start = %v, %v", cmd, err)
	}
	if cgFDSupported() {
		if len(attempts) != 2 || !attempts[0] || attempts[1] {
			t.Fatalf("attempts (in cgroup?) = %v, want [true false]", attempts)
		}
		if cg.Active() {
			t.Fatal("cgroup still active after its clone failed")
		}
	}

	// Both starts fail: the command is the problem, and the error is its.
	cg2 := NewCgroup(nil, t.TempDir(), "x", "w")
	cg2.setup.Do(func() {})
	cg2.dir = dir
	startCmd = func(*exec.Cmd) error { return errors.New("no such program") }
	if _, err := cg2.Start(func() (*exec.Cmd, error) { return exec.Command("true"), nil }); err == nil || !strings.Contains(err.Error(), "no such program") {
		t.Fatalf("Start = %v", err)
	}
	// The second build fails.
	builds := 0
	startCmd = func(cmd *exec.Cmd) error {
		if inCgroup(cmd) {
			return syscall.EINVAL
		}
		return nil
	}
	cg3 := NewCgroup(nil, t.TempDir(), "x", "w")
	cg3.setup.Do(func() {})
	cg3.dir = dir
	_, err = cg3.Start(func() (*exec.Cmd, error) {
		builds++
		if builds > 1 {
			return nil, errors.New("second build")
		}
		return exec.Command("true"), nil
	})
	if cgFDSupported() && (err == nil || !strings.Contains(err.Error(), "second build")) {
		t.Fatalf("Start = %v, want the second build's error", err)
	}
}

// fakeProcess is a Process a test controls.
type fakeProcess struct {
	pid     int
	done    chan struct{}
	signals []syscall.Signal
	exitOn  syscall.Signal
	closed  bool
	mu      sync.Mutex
}

func (p *fakeProcess) Pid() int { return p.pid }
func (p *fakeProcess) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signals = append(p.signals, sig)
	if sig == p.exitOn {
		select {
		case <-p.done:
		default:
			close(p.done)
		}
	}
	return nil
}
func (p *fakeProcess) Done() <-chan struct{} { return p.done }
func (p *fakeProcess) Close() error          { p.closed = true; return nil }

func TestStopEscalates(t *testing.T) {
	Stop(nil, time.Millisecond)
	polite := &fakeProcess{done: make(chan struct{}), exitOn: syscall.SIGTERM}
	Stop(polite, time.Second)
	if len(polite.signals) != 1 || !polite.closed {
		t.Fatalf("polite stop: signals %v closed %v", polite.signals, polite.closed)
	}
	stubborn := &fakeProcess{done: make(chan struct{}), exitOn: syscall.SIGKILL}
	Stop(stubborn, 10*time.Millisecond)
	if len(stubborn.signals) != 2 || stubborn.signals[1] != syscall.SIGKILL || !stubborn.closed {
		t.Fatalf("stubborn stop: signals %v closed %v", stubborn.signals, stubborn.closed)
	}
}

func TestOpenPIDMissing(t *testing.T) {
	fakeProc(t, 42, "", "")
	if _, _, err := OpenPID(42); !errors.Is(err, ErrGone) {
		t.Fatalf("OpenPID of a pid with no stat = %v, want ErrGone", err)
	}
}
