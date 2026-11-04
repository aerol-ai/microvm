package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeProcess is a liveProcess that exits on the signals it is told to.
type fakeProcess struct {
	mu      sync.Mutex
	signals []syscall.Signal
	exitOn  map[syscall.Signal]bool
	done    chan struct{}
	once    sync.Once
	closes  int
}

func newFakeProcess(exitOn ...syscall.Signal) *fakeProcess {
	p := &fakeProcess{exitOn: map[syscall.Signal]bool{}, done: make(chan struct{})}
	for _, sig := range exitOn {
		p.exitOn[sig] = true
	}
	return p
}

func (p *fakeProcess) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	p.signals = append(p.signals, sig)
	exit := p.exitOn[sig]
	p.mu.Unlock()
	if exit {
		p.exit()
	}
	return nil
}

func (p *fakeProcess) exit()                 { p.once.Do(func() { close(p.done) }) }
func (p *fakeProcess) Done() <-chan struct{} { return p.done }
func (p *fakeProcess) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return nil
}

func (p *fakeProcess) sent() []syscall.Signal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.signals)
}

// vmmHost stands in for the host: process start times, the boot, the VM
// cgroup and the processes adoption opens and kills.
type vmmHost struct {
	mu        sync.Mutex
	boot      string
	bootErr   error
	startErr  error
	procs     map[int]*fakeProcess
	cgroup    []int
	cgroupErr error
	killErr   map[int]error
	killed    []int
	cmdlines  map[int][]string
}

func stubVMMHost(t *testing.T) *vmmHost {
	t.Helper()
	h := &vmmHost{boot: "boot-1", procs: map[int]*fakeProcess{}, killErr: map[int]error{}, cmdlines: map[int][]string{}}
	saved := []any{moveVMMToCgroup, listVMMCgroup, processStart, hostBootID, openProcess, killStrayVMM, processCmdline}
	processCmdline = func(pid int) ([]string, error) {
		if args, ok := h.cmdlines[pid]; ok {
			return args, nil
		}
		return nil, errors.New("no such process")
	}
	processStart = func(pid int) (uint64, error) {
		if h.startErr != nil {
			return 0, h.startErr
		}
		return uint64(pid) * 10, nil
	}
	hostBootID = func() (string, error) { return h.boot, h.bootErr }
	openProcess = func(pid int, ticks uint64) (liveProcess, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		p, ok := h.procs[pid]
		if !ok || ticks != uint64(pid)*10 {
			return nil, errProcessGone
		}
		return p, nil
	}
	listVMMCgroup = func() ([]int, error) { return h.cgroup, h.cgroupErr }
	killStrayVMM = func(pid int) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.killed = append(h.killed, pid)
		return h.killErr[pid]
	}
	t.Cleanup(func() {
		moveVMMToCgroup = saved[0].(func(int) error)
		listVMMCgroup = saved[1].(func() ([]int, error))
		processStart = saved[2].(func(int) (uint64, error))
		hostBootID = saved[3].(func() (string, error))
		openProcess = saved[4].(func(int, uint64) (liveProcess, error))
		killStrayVMM = saved[5].(func(int) error)
		processCmdline = saved[6].(func(int) ([]string, error))
	})
	return h
}

// adoptDriver is a driver whose run dir is a temp dir and whose clients are
// fakes, one per API socket, kept for inspection.
func adoptDriver(t *testing.T) (*Driver, map[string]*fakeClient, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	d := New(Config{RunDir: t.TempDir()}, slog.New(slog.NewTextHandler(&logs, nil)))
	clients := map[string]*fakeClient{}
	d.SetClientFactory(func(socket string) VMMClient {
		c := newFakeClient()
		clients[socket] = c
		return c
	})
	return d, clients, &logs
}

func readRecord(t *testing.T, d *Driver, id string) (vmmRecord, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.vmmRecordDir(), id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return vmmRecord{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var rec vmmRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return rec, true
}

func writeRecord(t *testing.T, d *Driver, rec vmmRecord) {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d.vmmRecordDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.vmmRecordDir(), rec.SandboxID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A registered VM leaves a record naming its process, socket and CID, and
// unregistering it removes the record with the driver's own state.
func TestRegisterRecordsTheVMForTheNextSandboxd(t *testing.T) {
	stubVMMHost(t)
	d, _, _ := adoptDriver(t)
	handle := &fakeVMM{pid: 4242, apiSocket: "/run/vm/api.sock", runDir: filepath.Join(d.cfg.RunDir, "sb-a")}
	d.register("sb-a", newFakeClient(), handle, 9, true)

	rec, ok := readRecord(t, d, "sb-a")
	want := vmmRecord{SandboxID: "sb-a", PID: 4242, StartTicks: 42420, BootID: "boot-1",
		APISocket: "/run/vm/api.sock", RunDir: handle.runDir, VsockCID: 9, OwnsRunDir: true}
	if !ok || rec != want {
		t.Fatalf("record = %+v (present %v), want %+v", rec, ok, want)
	}
	if d.vmms["sb-a"] != handle || d.guestCID["sb-a"] != 9 || d.clients["sb-a"] == nil {
		t.Fatal("register did not fill the driver's maps")
	}

	got, had := d.unregister("sb-a")
	if !had || got != handle {
		t.Fatalf("unregister = %v, %v", got, had)
	}
	if _, ok := readRecord(t, d, "sb-a"); ok {
		t.Fatal("unregister left the record")
	}
	if len(d.vmms)+len(d.clients)+len(d.guestCID) != 0 {
		t.Fatal("unregister left driver state")
	}
	if _, had := d.unregister("sb-a"); had {
		t.Fatal("a second unregister found a VM")
	}
}

func TestRegisterWithoutARecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		runDir   bool
		pid      int
		startErr error
		bootErr  error
		blockDir bool
		warns    bool
	}{
		{name: "no pid", runDir: true, pid: 0},
		{name: "no run dir", pid: 7},
		{name: "a host VMs cannot outlive sandboxd on", runDir: true, pid: 7, startErr: errVMMAdoptionUnsupported},
		{name: "start time unreadable", runDir: true, pid: 7, startErr: errors.New("no /proc"), warns: true},
		{name: "boot id unreadable", runDir: true, pid: 7, bootErr: errors.New("no boot id"), warns: true},
		{name: "record dir unwritable", runDir: true, pid: 7, blockDir: true, warns: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := stubVMMHost(t)
			host.startErr, host.bootErr = tc.startErr, tc.bootErr
			d, _, logs := adoptDriver(t)
			if !tc.runDir {
				d.cfg.RunDir = ""
			}
			if tc.blockDir {
				if err := os.WriteFile(filepath.Join(d.cfg.RunDir, vmmRecordDirName), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d.register("sb-b", newFakeClient(), &fakeVMM{pid: tc.pid}, 3, true)
			if d.vmms["sb-b"] == nil {
				t.Fatal("the VM was not registered")
			}
			if tc.runDir && !tc.blockDir {
				if _, ok := readRecord(t, d, "sb-b"); ok {
					t.Fatal("a record was written")
				}
			}
			if warned := strings.Contains(logs.String(), "running VM not recorded"); warned != tc.warns {
				t.Fatalf("warned = %v, want %v: %s", warned, tc.warns, logs)
			}
			d.unregister("sb-b")
		})
	}
}

// A record that cannot be removed is logged; the VM is unregistered anyway.
func TestUnregisterLogsARecordItCannotRemove(t *testing.T) {
	stubVMMHost(t)
	d, _, logs := adoptDriver(t)
	if err := os.MkdirAll(filepath.Join(d.vmmRecordDir(), "sb-c.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	d.unregister("sb-c")
	if !strings.Contains(logs.String(), "VM record not removed") {
		t.Fatalf("no warning: %s", logs)
	}
}

func TestAdoptRunningVMs(t *testing.T) {
	host := stubVMMHost(t)
	d, clients, logs := adoptDriver(t)
	root := d.cfg.RunDir
	rec := func(id string, pid int, owns bool) vmmRecord {
		return vmmRecord{SandboxID: id, PID: pid, StartTicks: uint64(pid) * 10, BootID: "boot-1",
			APISocket: "/sock/" + id, RunDir: filepath.Join(root, id), VsockCID: uint32(pid), OwnsRunDir: owns}
	}
	keep := map[string]bool{"sb-keep": true, "sb-paused": true, "sb-warm": true}
	for id, pid := range map[string]int{"sb-keep": 101, "sb-paused": 102, "sb-stopped": 103, "sb-unknown": 106, "sb-warm": 107} {
		host.procs[pid] = newFakeProcess(syscall.SIGKILL)
		writeRecord(t, d, rec(id, pid, id != "sb-warm"))
	}
	if err := os.MkdirAll(filepath.Join(root, "sb-stopped"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, d, rec("sb-gone", 104, true)) // its process ended
	old := rec("sb-oldboot", 105, true)
	old.BootID = "boot-0"
	writeRecord(t, d, old)
	for name, body := range map[string]string{
		"bad.json":         "{",
		".record-123":      "{}",
		"sb-mismatch.json": `{"sandbox_id":"sb-other","pid":5}`,
		"sb-nopid.json":    `{"sandbox_id":"sb-nopid"}`,
	} {
		if err := os.WriteFile(filepath.Join(d.vmmRecordDir(), name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host.cgroup = []int{101, 102, 106, 107, 200, 201}
	host.killErr[201] = errors.New("operation not permitted")
	// The paused VM's client is made before adoption asks it.
	d.SetClientFactory(func(socket string) VMMClient {
		c := newFakeClient()
		if socket == "/sock/sb-paused" {
			c.instance = &firecracker.InstanceInfo{State: "Paused"}
		}
		clients[socket] = c
		return c
	})

	n := d.AdoptRunningVMs(context.Background(), func(_ context.Context, id string) (bool, error) {
		if id == "sb-unknown" {
			return false, errors.New("store locked")
		}
		return keep[id], nil
	})

	if n != 4 {
		t.Fatalf("adopted %d VMs, want 4 (%s)", n, logs)
	}
	for _, id := range []string{"sb-keep", "sb-paused", "sb-unknown", "sb-warm"} {
		if d.vmms[id] == nil || d.clients[id] == nil || d.guestCID[id] == 0 {
			t.Fatalf("%s was not adopted", id)
		}
		if _, ok := readRecord(t, d, id); !ok {
			t.Fatalf("%s lost its record", id)
		}
	}
	if got := clients["/sock/sb-paused"].vmStates; !reflect.DeepEqual(got, []string{firecracker.VMStateResumed}) {
		t.Fatalf("paused VM states = %v, want a resume", got)
	}
	if got := clients["/sock/sb-keep"].vmStates; len(got) != 0 {
		t.Fatalf("a running VM was patched: %v", got)
	}
	if got := host.procs[103].sent(); !reflect.DeepEqual(got, []syscall.Signal{syscall.SIGKILL}) {
		t.Fatalf("stopped sandbox's VM got %v, want SIGKILL", got)
	}
	if _, err := os.Stat(filepath.Join(root, "sb-stopped")); !os.IsNotExist(err) {
		t.Fatal("the stopped sandbox's run dir was left")
	}
	for _, id := range []string{"sb-stopped", "sb-gone", "sb-oldboot"} {
		if _, ok := readRecord(t, d, id); ok {
			t.Fatalf("%s kept its record", id)
		}
		if d.vmms[id] != nil {
			t.Fatalf("%s was adopted", id)
		}
	}
	entries, _ := os.ReadDir(d.vmmRecordDir())
	if len(entries) != 4 {
		t.Fatalf("record dir holds %d files, want the 4 adopted VMs' records", len(entries))
	}
	if !reflect.DeepEqual(host.killed, []int{200, 201}) {
		t.Fatalf("killed strays %v, want [200 201]", host.killed)
	}
	for _, want := range []string{"cannot tell whether a VM should run", "leftover VM not killed", "killed a VM no sandbox owns", "recorded VM is gone"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log lacks %q: %s", want, logs)
		}
	}
}

func TestAdoptRunningVMsEdges(t *testing.T) {
	t.Run("no boot id: nothing is adopted", func(t *testing.T) {
		host := stubVMMHost(t)
		d, _, _ := adoptDriver(t)
		host.procs[101] = newFakeProcess()
		writeRecord(t, d, vmmRecord{SandboxID: "sb-a", PID: 101, StartTicks: 1010, BootID: "boot-1"})
		host.bootErr = errors.New("no /proc")
		if n := d.AdoptRunningVMs(context.Background(), func(context.Context, string) (bool, error) { return true, nil }); n != 0 {
			t.Fatalf("adopted %d", n)
		}
		if _, ok := readRecord(t, d, "sb-a"); ok {
			t.Fatal("the record was kept")
		}
	})
	t.Run("no records and an unreadable cgroup", func(t *testing.T) {
		host := stubVMMHost(t)
		host.cgroupErr = errors.New("eperm")
		d, _, logs := adoptDriver(t)
		if n := d.AdoptRunningVMs(context.Background(), nil); n != 0 {
			t.Fatalf("adopted %d", n)
		}
		if !strings.Contains(logs.String(), "VM cgroup unreadable") {
			t.Fatalf("no warning: %s", logs)
		}
	})
	t.Run("no run dir", func(t *testing.T) {
		stubVMMHost(t)
		d, _, _ := adoptDriver(t)
		d.cfg.RunDir = ""
		if n := d.AdoptRunningVMs(context.Background(), nil); n != 0 {
			t.Fatalf("adopted %d", n)
		}
	})
	t.Run("an unreadable record dir", func(t *testing.T) {
		stubVMMHost(t)
		d, _, logs := adoptDriver(t)
		if err := os.WriteFile(d.vmmRecordDir(), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		d.AdoptRunningVMs(context.Background(), nil)
		if !strings.Contains(logs.String(), "VM records unreadable") {
			t.Fatalf("no warning: %s", logs)
		}
	})
	t.Run("a VM to stop whose run dir cannot go", func(t *testing.T) {
		host := stubVMMHost(t)
		d, _, logs := adoptDriver(t)
		host.procs[101] = newFakeProcess(syscall.SIGKILL)
		writeRecord(t, d, vmmRecord{SandboxID: "sb-a", PID: 101, StartTicks: 1010, BootID: "boot-1",
			RunDir: "/elsewhere/sb-a", OwnsRunDir: true})
		d.AdoptRunningVMs(context.Background(), func(context.Context, string) (bool, error) { return false, nil })
		if !strings.Contains(logs.String(), "run dir not removed") {
			t.Fatalf("no warning: %s", logs)
		}
	})
}

// errInfoClient answers InstanceInfo with an error or a paused VM whose
// resume fails.
type errInfoClient struct {
	*fakeClient
	infoErr error
}

func (c *errInfoClient) InstanceInfo(ctx context.Context) (*firecracker.InstanceInfo, error) {
	if c.infoErr != nil {
		return nil, c.infoErr
	}
	return c.fakeClient.InstanceInfo(ctx)
}

func TestResumeIfPausedFailures(t *testing.T) {
	d, _, logs := adoptDriver(t)
	d.resumeIfPaused(context.Background(), "sb-a", &errInfoClient{fakeClient: newFakeClient(), infoErr: errors.New("socket gone")})
	if !strings.Contains(logs.String(), "VM state unknown") {
		t.Fatalf("no warning: %s", logs)
	}
	paused := newFakeClient()
	paused.instance = &firecracker.InstanceInfo{State: "Paused"}
	paused.patchVMErr = errors.New("busy")
	d.resumeIfPaused(context.Background(), "sb-a", paused)
	if !strings.Contains(logs.String(), "paused VM not resumed") {
		t.Fatalf("no warning: %s", logs)
	}
}

func TestAdoptedVMM(t *testing.T) {
	root := t.TempDir()
	newHandle := func(p *fakeProcess, owns bool, runDir string) *adoptedVMM {
		return &adoptedVMM{rec: vmmRecord{PID: 77, APISocket: "/s", RunDir: runDir, OwnsRunDir: owns}, proc: p, cleanupRoot: root}
	}
	t.Run("identity", func(t *testing.T) {
		p := newFakeProcess()
		h := newHandle(p, true, "/r")
		if h.APISocket() != "/s" || h.RunDir() != "/r" || h.StderrTail() != "" || h.Pid() != 77 {
			t.Fatal("identity accessors")
		}
		if h.Start(context.Background()) == nil || h.WaitSocket(context.Background(), time.Second) != nil {
			t.Fatal("an adopted VM must refuse Start and be past WaitSocket")
		}
		p.exit()
		if h.Pid() != 0 {
			t.Fatal("an exited VM still reports a pid")
		}
	})
	t.Run("shutdown that SIGTERM ends", func(t *testing.T) {
		p := newFakeProcess(syscall.SIGTERM)
		h := newHandle(p, true, "")
		if err := h.Shutdown(context.Background(), time.Second); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.sent(), []syscall.Signal{syscall.SIGTERM}) || p.closes != 1 {
			t.Fatalf("signals %v closes %d", p.sent(), p.closes)
		}
		// Already exited: no signal, and the pidfd is not closed twice.
		if err := h.Shutdown(context.Background(), time.Second); err != nil || len(p.sent()) != 1 || p.closes != 1 {
			t.Fatalf("second shutdown: %v, signals %v, closes %d", err, p.sent(), p.closes)
		}
	})
	t.Run("shutdown that needs SIGKILL", func(t *testing.T) {
		p := newFakeProcess(syscall.SIGKILL)
		h := newHandle(p, true, "")
		if err := h.Shutdown(context.Background(), time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.sent(), []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
			t.Fatalf("signals %v", p.sent())
		}
	})
	t.Run("shutdown with the default grace, cut short by the context", func(t *testing.T) {
		p := newFakeProcess()
		h := newHandle(p, true, "")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := h.Shutdown(ctx, 0); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("kill", func(t *testing.T) {
		p := newFakeProcess(syscall.SIGKILL)
		h := newHandle(p, true, "")
		if err := h.Kill(); err != nil || p.closes != 1 {
			t.Fatalf("kill: %v closes %d", err, p.closes)
		}
	})
	t.Run("cleanup", func(t *testing.T) {
		owned := filepath.Join(root, "sb-a")
		if err := os.MkdirAll(owned, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := newHandle(newFakeProcess(), false, owned).Cleanup(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(owned); err != nil {
			t.Fatal("a run dir the pool owns was removed")
		}
		if err := newHandle(newFakeProcess(), true, owned).Cleanup(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(owned); !os.IsNotExist(err) {
			t.Fatal("the run dir was left")
		}
		if err := newHandle(newFakeProcess(), true, "").Cleanup(); err != nil {
			t.Fatal(err)
		}
		if err := newHandle(newFakeProcess(), true, "/etc").Cleanup(); err == nil {
			t.Fatal("a path outside the run dir root was accepted")
		}
		h := newHandle(newFakeProcess(), true, filepath.Join(root, "x"))
		h.cleanupRoot = ""
		if err := h.Cleanup(); err == nil {
			t.Fatal("an empty root was accepted")
		}
	})
}

// Destroy stops an adopted VM through its pidfd, removes its run dir and
// forgets its record, as for a VM this sandboxd started.
func TestDestroyStopsAnAdoptedVM(t *testing.T) {
	host := stubVMMHost(t)
	d, _, _ := adoptDriver(t)
	runDir := filepath.Join(d.cfg.RunDir, "sb-a")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	host.procs[101] = newFakeProcess(syscall.SIGTERM)
	writeRecord(t, d, vmmRecord{SandboxID: "sb-a", PID: 101, StartTicks: 1010, BootID: "boot-1",
		APISocket: "/sock", RunDir: runDir, VsockCID: 5, OwnsRunDir: true})
	host.cgroup = []int{101}
	if n := d.AdoptRunningVMs(context.Background(), func(context.Context, string) (bool, error) { return true, nil }); n != 1 {
		t.Fatalf("adopted %d", n)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-a"}); err != nil {
		t.Fatal(err)
	}
	if got := host.procs[101].sent(); !reflect.DeepEqual(got, []syscall.Signal{syscall.SIGTERM}) {
		t.Fatalf("signals %v", got)
	}
	if _, ok := readRecord(t, d, "sb-a"); ok {
		t.Fatal("the record outlived the VM")
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatal("the run dir was left")
	}
}

// vmm.Start moves the process it spawns out of sandboxd's cgroup, and a
// host where that fails is warned about once, not on every VM.
func TestVMMStartMovesTheVMOutOfSandboxdsCgroup(t *testing.T) {
	stubVMMHost(t)
	dir := t.TempDir()
	bin := writeFakeFirecracker(t, dir, fakeOpts{})
	var moved []int
	moveVMMToCgroup = func(pid int) error {
		moved = append(moved, pid)
		return errors.New("read-only cgroupfs")
	}
	cgroupWarnOnce = sync.Once{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	for _, id := range []string{"vm-a", "vm-b"} {
		v, err := newVMM(Config{FirecrackerBinary: bin, RunDir: dir}, id, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if moved[len(moved)-1] != v.Pid() {
			t.Fatalf("moved pid %d, want %d", moved[len(moved)-1], v.Pid())
		}
		_ = v.Kill()
	}
	if c := strings.Count(logs.String(), "stay in sandboxd's cgroup"); c != 1 {
		t.Fatalf("warned %d times, want once: %s", c, logs.String())
	}
	// Without a logger the warning goes to the default one.
	cgroupWarnOnce = sync.Once{}
	startAndKill := func(id string, logger *slog.Logger) {
		v, err := newVMM(Config{FirecrackerBinary: bin, RunDir: dir}, id, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		_ = v.Kill()
	}
	startAndKill("vm-c", nil)
	// A host that cannot keep VMs past sandboxd at all says nothing.
	moveVMMToCgroup = func(int) error { return errVMMAdoptionUnsupported }
	cgroupWarnOnce = sync.Once{}
	logs.Reset()
	startAndKill("vm-d", logger)
	if strings.Contains(logs.String(), "cgroup") {
		t.Fatalf("warned on a host without the feature: %s", logs.String())
	}
}

// A jailed VM's run dir is under the chroot base, so that is the root an
// adopted VM's cleanup is held to.
func TestRunDirRoot(t *testing.T) {
	d := New(Config{RunDir: "/run/x", JailerChrootBase: "/srv/jailer"}, nil)
	if d.runDirRoot() != "/run/x" {
		t.Fatal(d.runDirRoot())
	}
	d.cfg.UseJailer = true
	if d.runDirRoot() != "/srv/jailer" {
		t.Fatal(d.runDirRoot())
	}
}

// A VM with no record (started by a release before records, and moved out
// of sandboxd's cgroup by the installer) is found by its command line and
// adopted like a recorded one, then recorded.
func TestAdoptRunningVMsDiscoversUnrecordedVMs(t *testing.T) {
	host := stubVMMHost(t)
	d, _, logs := adoptDriver(t)
	d.cfg.FirecrackerBinary = "/usr/bin/firecracker"
	pool := newFakePool()
	d.SetPool(pool)
	slot, err := pool.Allocate(context.Background(), "sb-old", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	jailed := func(id string) []string {
		return []string{"/firecracker", "--id", id, "--start-time-us", "1", "--", "--api-sock", "api.socket"}
	}
	host.cmdlines[301] = jailed("sb-old")
	host.cmdlines[302] = []string{"/usr/bin/firecracker", "--api-sock", filepath.Join(d.cfg.RunDir, "sb-stopped", "api.sock")}
	host.cmdlines[303] = []string{"/usr/bin/rclone", "mount"}
	host.cmdlines[304] = jailed("sb-dup") // its sandbox's VM is recorded under another pid
	for _, pid := range []int{301, 302, 303, 304, 101} {
		host.procs[pid] = newFakeProcess(syscall.SIGKILL)
	}
	writeRecord(t, d, vmmRecord{SandboxID: "sb-dup", PID: 101, StartTicks: 1010, BootID: "boot-1", APISocket: "/s", VsockCID: 4})
	host.cgroup = []int{101, 301, 302, 303, 304, 305}
	keep := map[string]bool{"sb-old": true, "sb-dup": true}

	n := d.AdoptRunningVMs(context.Background(), func(_ context.Context, id string) (bool, error) { return keep[id], nil })
	if n != 2 {
		t.Fatalf("adopted %d, want sb-dup by record and sb-old by its command line (%s)", n, logs)
	}
	rec, ok := readRecord(t, d, "sb-old")
	want := vmmRecord{SandboxID: "sb-old", PID: 301, StartTicks: 3010, BootID: "boot-1",
		APISocket: filepath.Join(d.cfg.RunDir, "sb-old", "api.sock"), RunDir: filepath.Join(d.cfg.RunDir, "sb-old"),
		VsockCID: slot.VsockCID, OwnsRunDir: true}
	if !ok || rec != want {
		t.Fatalf("record %+v, want %+v", rec, want)
	}
	if d.guestCID["sb-old"] != slot.VsockCID {
		t.Fatalf("guest CID %d", d.guestCID["sb-old"])
	}
	// The stopped sandbox's VM is killed through its handle, the others
	// as strays; nothing touches the adopted ones.
	if !reflect.DeepEqual(host.procs[302].sent(), []syscall.Signal{syscall.SIGKILL}) {
		t.Fatalf("stopped sandbox's VM got %v", host.procs[302].sent())
	}
	if !reflect.DeepEqual(host.killed, []int{302, 303, 304, 305}) {
		t.Fatalf("killed %v", host.killed)
	}
	if _, ok := readRecord(t, d, "sb-stopped"); ok {
		t.Fatal("a killed VM was recorded")
	}
}

func TestVMSandboxFromArgs(t *testing.T) {
	run := "/run/sandboxd/firecracker"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"/firecracker", "--id", "sb-a", "--start-time-us", "9", "--api-sock", "api.socket"}, "sb-a"},
		{[]string{"firecracker", "--api-sock", run + "/sb-b/api.sock"}, "sb-b"},
		{[]string{"/usr/bin/firecracker", "--api-sock", "/elsewhere/sb-c/api.sock"}, ""},
		{[]string{"/firecracker", "--id", "../etc"}, ""},
		{[]string{"/firecracker", "--id"}, ""},
		{[]string{"/usr/bin/jailer", "--id", "sb-d"}, ""},
		{nil, ""},
	} {
		got, ok := vmSandboxFromArgs(tc.args, run)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%v: %q, %v; want %q", tc.args, got, ok, tc.want)
		}
	}
	if _, ok := vmSandboxFromArgs([]string{"firecracker", "--api-sock", "/sb-b/api.sock"}, ""); ok {
		t.Error("an unjailed VM was placed with no run dir configured")
	}
}

// A command line that names a sandbox the driver cannot lay out, or whose
// start time cannot be read, is not adopted.
func TestDiscoverVMFailures(t *testing.T) {
	host := stubVMMHost(t)
	d, _, _ := adoptDriver(t)
	d.cfg.FirecrackerBinary = "/usr/bin/firecracker"
	if _, ok := d.discoverVM(context.Background(), 9, "boot-1"); ok {
		t.Fatal("a process with no command line was discovered")
	}
	host.cmdlines[9] = []string{"/firecracker", "--id", "sb-a"}
	host.startErr = errors.New("gone")
	if _, ok := d.discoverVM(context.Background(), 9, "boot-1"); ok {
		t.Fatal("a process with no start time was discovered")
	}
	host.startErr = nil
	d.cfg.RunDir = ""
	if _, ok := d.discoverVM(context.Background(), 9, "boot-1"); ok {
		t.Fatal("a VM the driver cannot lay out was discovered")
	}
}
