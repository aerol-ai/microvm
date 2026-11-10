package isolate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// heldWorkerd is a workerd process a test holds.
type heldWorkerd struct {
	mu   sync.Mutex
	done chan struct{}
	sigs []syscall.Signal
}

func newHeldWorkerd() *heldWorkerd { return &heldWorkerd{done: make(chan struct{})} }

func (p *heldWorkerd) Pid() int { return 4321 }
func (p *heldWorkerd) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sigs = append(p.sigs, sig)
	if sig == syscall.SIGKILL {
		select {
		case <-p.done:
		default:
			close(p.done)
		}
	}
	return nil
}
func (p *heldWorkerd) Done() <-chan struct{} { return p.done }
func (p *heldWorkerd) Close() error          { return nil }
func (p *heldWorkerd) killed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sigs {
		if s == syscall.SIGKILL {
			return true
		}
	}
	return false
}

// withHostSeams stands in the host's process, start time and boot id.
func withHostSeams(t *testing.T, proc hostproc.Process, openErr error) {
	t.Helper()
	oldOpen, oldTicks, oldBoot := openHostProcess, hostStartTicks, hostBootID
	t.Cleanup(func() { openHostProcess, hostStartTicks, hostBootID = oldOpen, oldTicks, oldBoot })
	openHostProcess = func(int, uint64) (hostproc.Process, error) {
		if openErr != nil {
			return nil, openErr
		}
		return proc, nil
	}
	hostStartTicks = func(int) (uint64, error) { return 777, nil }
	hostBootID = func() (string, error) { return "boot-1", nil }
}

// fakeController serves the control socket a running workerd would.
func fakeController(t *testing.T, sock string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func readRecord(t *testing.T, path string) hostRecord {
	t.Helper()
	var rec hostRecord
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestHostRecordFollowsItsState: the record names the loaded sandboxes and
// their egress slots as they change, and goes away with the host.
func TestHostRecordFollowsItsState(t *testing.T) {
	withHostSeams(t, newHeldWorkerd(), nil)
	run := shortRunDir(t)
	records := filepath.Join(t.TempDir(), ".hosts")
	h, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "g1", RunDir: run, RecordDir: records, EgressPoolSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	if h.GroupKey() != "g1" || h.PID() != 0 {
		t.Fatalf("key %q pid %d", h.GroupKey(), h.PID())
	}
	path := filepath.Join(records, "g1.json")
	// Not started: no record.
	if err := h.Load("sb-0", testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("record written before the host started")
	}
	h.noteProcess(99)
	h.started.Store(true)
	if err := h.Load("sb-1", testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if err := h.ClaimEgressPolicy("sb-1", EgressPolicy{Allow: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	rec := readRecord(t, path)
	if rec.PID != 99 || rec.StartTicks != 777 || rec.BootID != "boot-1" || rec.RunDir != run || rec.EgressPoolSize != 4 {
		t.Fatalf("record = %+v", rec)
	}
	sort.Strings(rec.Loaded)
	if len(rec.Loaded) != 2 || rec.Loaded[1] != "sb-1" || rec.Slots["sb-1"] != 0 {
		t.Fatalf("record loaded %v slots %v", rec.Loaded, rec.Slots)
	}
	h.SetEgressPolicy("sb-1", EgressPolicy{BlockAll: true})
	if rec := readRecord(t, path); len(rec.Slots) != 0 {
		t.Fatalf("slot kept after block-all: %v", rec.Slots)
	}
	h.Unload("sb-0")
	if rec := readRecord(t, path); len(rec.Loaded) != 1 {
		t.Fatalf("loaded after unload = %v", rec.Loaded)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("record left after Stop")
	}
	// A record dir that cannot be made: logged, not fatal.
	bad, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "g2", RunDir: run, RecordDir: filepath.Join(path, "x", "y")})
	bad.started.Store(true)
	bad.writeRecord()
	(&Host{}).writeRecord() // no record dir: no-op
	// noteProcess off Linux (or for a gone pid) names nothing.
	hostStartTicks = func(int) (uint64, error) { return 0, hostproc.ErrUnsupported }
	off := &Host{}
	off.noteProcess(1)
	hostStartTicks = func(int) (uint64, error) { return 1, nil }
	hostBootID = func() (string, error) { return "", errors.New("no procfs") }
	off.noteProcess(1)
	if off.PID() != 0 {
		t.Fatal("a process was named without its start time and boot")
	}
}

// TestAdoptHostsTakesOverALiveHost: a recorded host whose workerd still
// answers is taken over: its bundle and egress listeners come back on the
// same sockets, each recorded slot is held by the same sandbox, and Stop
// later kills workerd through its pidfd.
func TestAdoptHostsTakesOverALiveHost(t *testing.T) {
	proc := newHeldWorkerd()
	withHostSeams(t, proc, nil)
	run := shortRunDir(t)
	records := filepath.Join(t.TempDir(), ".hosts")
	if err := writeRecordFile(filepath.Join(records, "g1.json"), hostRecord{
		GroupKey: "g1", PID: 4321, StartTicks: 777, BootID: "boot-1", RunDir: run, EgressPoolSize: 4,
		Slots: map[string]int{"sb-1": 2, "sb-bad": 9}, Loaded: []string{"sb-1", "sb-2"},
	}); err != nil {
		t.Fatal(err)
	}
	// Stale socket files the previous sandboxd left behind.
	for _, name := range []string{hostSocketName, egressDenySocketName} {
		if err := os.WriteFile(filepath.Join(run, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fakeController(t, filepath.Join(run, controlSocketName))
	adopted := AdoptHosts(context.Background(), HostConfig{RecordDir: records})
	if len(adopted) != 1 {
		t.Fatalf("adopted %d hosts", len(adopted))
	}
	h := adopted[0].Host
	if len(adopted[0].Loaded) != 2 || !h.started.Load() || h.PID() != 4321 {
		t.Fatalf("adopted = %+v started=%v pid=%d", adopted[0], h.started.Load(), h.PID())
	}
	if h.slotByID["sb-1"] != 2 || h.idBySlot[2] != "sb-1" || h.slotSrv[2] == nil {
		t.Fatalf("slot 2 not held by sb-1: %v %v", h.slotByID, h.idBySlot)
	}
	if _, held := h.slotByID["sb-bad"]; held {
		t.Fatal("an out-of-range slot was held")
	}
	// The bundle server answers on the old socket again.
	resp, err := unixHTTPClient(h.hostSock).Get("http://host/bundle/nope")
	if err != nil {
		t.Fatalf("bundle server not back: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bundle status = %d", resp.StatusCode)
	}
	// An adopted host takes requests like a started one.
	req, _ := http.NewRequest(http.MethodGet, "http://ctrl/", nil)
	if resp, err := h.Invoke(context.Background(), "sb-1", req); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if !proc.killed() {
		t.Fatal("Stop did not kill the adopted workerd")
	}
	if _, err := os.Stat(filepath.Join(records, "g1.json")); !os.IsNotExist(err) {
		t.Fatal("record left after Stop")
	}
}

// TestAdoptHostsRefusesWhatItCannotTrust: a record from another boot, a
// workerd that is gone or does not answer, and a file that is no record
// are all dropped; a workerd that does not answer is killed.
func TestAdoptHostsRefusesWhatItCannotTrust(t *testing.T) {
	if AdoptHosts(context.Background(), HostConfig{}) != nil {
		t.Fatal("adopted without a record dir")
	}
	records := filepath.Join(t.TempDir(), ".hosts")
	write := func(rec hostRecord) {
		t.Helper()
		if err := writeRecordFile(filepath.Join(records, rec.GroupKey+".json"), rec); err != nil {
			t.Fatal(err)
		}
	}
	run := shortRunDir(t)
	// Another boot.
	withHostSeams(t, newHeldWorkerd(), nil)
	write(hostRecord{GroupKey: "old", PID: 1, StartTicks: 1, BootID: "boot-0", RunDir: run})
	if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records}); len(got) != 0 {
		t.Fatal("adopted a record from another boot")
	}
	// The process is gone.
	withHostSeams(t, nil, hostproc.ErrGone)
	write(hostRecord{GroupKey: "gone", PID: 1, StartTicks: 1, BootID: "boot-1", RunDir: run})
	if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records}); len(got) != 0 {
		t.Fatal("adopted a gone workerd")
	}
	// It runs but does not answer: killed.
	quiet := newHeldWorkerd()
	withHostSeams(t, quiet, nil)
	write(hostRecord{GroupKey: "quiet", PID: 1, StartTicks: 1, BootID: "boot-1", RunDir: run})
	if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records}); len(got) != 0 {
		t.Fatal("adopted a workerd that does not answer")
	}
	if !quiet.killed() {
		t.Fatal("a workerd that does not answer was left running")
	}
	// Not records: a temp file, a record named for another key, bad JSON,
	// and a record whose jailed run dir does not fit its chroot.
	if err := os.WriteFile(filepath.Join(records, ".record-123"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(hostRecord{GroupKey: "other", PID: 1, RunDir: run})
	if err := os.Rename(filepath.Join(records, "other.json"), filepath.Join(records, "mismatch.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(records, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(hostRecord{GroupKey: "badjail", PID: 1, StartTicks: 1, BootID: "boot-1", RunDir: run, Jailed: true, ChrootDir: "/srv/jail/badjail"})
	if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records}); len(got) != 0 {
		t.Fatal("adopted a non-record")
	}
	entries, _ := os.ReadDir(records)
	if len(entries) != 0 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("records left: %v", names)
	}
	if readHostRecords(filepath.Join(records, "missing")) != nil {
		t.Fatal("records read from a missing dir")
	}
}

// TestRecordedJailForTeardown: an adopted jailed host tears down the jail
// its record names.
func TestRecordedJailForTeardown(t *testing.T) {
	r := recordedJail(hostRecord{ChrootDir: "/srv/jail/g", CgroupDir: "/sys/fs/cgroup/aerolvm-isolate/aerolvm-isolate-g"})
	if r.chrootBase != "/srv/jail" || r.cgroup.root != "/sys/fs/cgroup/aerolvm-isolate" || len(r.noexecMounts) != 2 {
		t.Fatalf("jail = %+v", r)
	}
	if bare := recordedJail(hostRecord{}); bare.cgroupDir != "" || len(bare.noexecMounts) != 0 {
		t.Fatalf("bare jail = %+v", bare)
	}
}

// TestSweepLeftovers kills processes and removes jails no adopted host owns,
// and keeps what one does.
func TestSweepLeftovers(t *testing.T) {
	root := t.TempDir()
	hostsDir := filepath.Join(root, "cg", "aerolvm-isolate-hosts")
	jailCg := filepath.Join(root, "cg", "aerolvm-isolate")
	chroots := filepath.Join(root, "jail")
	mk := func(dir string, procs string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if procs != "" {
			if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(procs), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk(hostsDir, "5\n6\n")
	mk(filepath.Join(jailCg, "aerolvm-isolate-keep"), "8\n")
	mk(filepath.Join(jailCg, "aerolvm-isolate-gone"), "7\n")
	mk(filepath.Join(jailCg, "unrelated"), "")
	mk(filepath.Join(chroots, jailBaseName), "")
	mk(filepath.Join(chroots, "keep", "run"), "")
	mk(filepath.Join(chroots, "gone", "run"), "")

	var killed []int
	var unmounted []string
	oldOpen, oldUnmount := sweepOpenPID, sweepUnmount
	t.Cleanup(func() { sweepOpenPID, sweepUnmount = oldOpen, oldUnmount })
	sweepOpenPID = func(pid int) (hostproc.Process, error) {
		if pid == 9 {
			return nil, hostproc.ErrGone
		}
		killed = append(killed, pid)
		return newHeldWorkerd(), nil
	}
	sweepUnmount = func(dirs []string) { unmounted = append(unmounted, dirs...) }

	n := SweepLeftovers(Leftovers{
		HostsCgroup:    hostproc.NewCgroup(nil, filepath.Join(root, "cg"), "aerolvm-isolate-hosts", "hosts"),
		JailCgroupRoot: jailCg,
		JailChrootBase: chroots,
		Keep:           map[string]bool{"keep": true},
		KeepPIDs:       map[int]bool{6: true},
	})
	sort.Ints(killed)
	if n != 2 || len(killed) != 2 || killed[0] != 5 || killed[1] != 7 {
		t.Fatalf("killed %d %v, want [5 7]", n, killed)
	}
	for _, gone := range []string{filepath.Join(jailCg, "aerolvm-isolate-gone"), filepath.Join(chroots, "gone")} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s left: %v", gone, err)
		}
	}
	for _, kept := range []string{filepath.Join(jailCg, "aerolvm-isolate-keep"), filepath.Join(chroots, "keep"), filepath.Join(chroots, jailBaseName), filepath.Join(jailCg, "unrelated")} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s removed: %v", kept, err)
		}
	}
	if len(unmounted) != 2 || filepath.Base(filepath.Dir(unmounted[0])) != "gone" {
		t.Fatalf("unmounted %v", unmounted)
	}
	// A pid that is gone by the time it is opened is not counted.
	if n := killPIDs([]int{9}, nil); n != 0 {
		t.Fatalf("killed a gone pid: %d", n)
	}
	if SweepLeftovers(Leftovers{}) != 0 {
		t.Fatal("empty sweep killed something")
	}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// blockPath makes path a non-empty directory, so a socket or file cannot
// take its place.
func blockPath(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestAdoptHostListenerFailures: a host whose bundle or deny socket cannot
// be bound again is not taken over and its workerd is killed; a slot whose
// socket cannot be bound is left free (that sandbox egresses through the
// deny service until its policy is set again).
func TestAdoptHostListenerFailures(t *testing.T) {
	for _, name := range []string{hostSocketName, egressDenySocketName} {
		t.Run(name, func(t *testing.T) {
			proc := newHeldWorkerd()
			withHostSeams(t, proc, nil)
			run := shortRunDir(t)
			records := filepath.Join(t.TempDir(), ".hosts")
			if err := writeRecordFile(filepath.Join(records, "g1.json"), hostRecord{GroupKey: "g1", PID: 1, StartTicks: 1, BootID: "boot-1", RunDir: run}); err != nil {
				t.Fatal(err)
			}
			blockPath(t, filepath.Join(run, name))
			if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records, Logger: testLogger()}); len(got) != 0 {
				t.Fatal("adopted a host whose listener cannot bind")
			}
			if !proc.killed() {
				t.Fatal("workerd left running")
			}
		})
	}
	proc := newHeldWorkerd()
	withHostSeams(t, proc, nil)
	run := shortRunDir(t)
	records := filepath.Join(t.TempDir(), ".hosts")
	if err := writeRecordFile(filepath.Join(records, "g1.json"), hostRecord{GroupKey: "g1", PID: 1, StartTicks: 1, BootID: "boot-1", RunDir: run,
		EgressPoolSize: 2, Slots: map[string]int{"sb-1": 1}}); err != nil {
		t.Fatal(err)
	}
	blockPath(t, filepath.Join(run, egressSlotSocketName(1)))
	fakeController(t, filepath.Join(run, controlSocketName))
	got := AdoptHosts(context.Background(), HostConfig{RecordDir: records})
	if len(got) != 1 {
		t.Fatalf("adopted %d", len(got))
	}
	if _, held := got[0].Host.slotByID["sb-1"]; held {
		t.Fatal("a slot whose socket cannot bind was held")
	}
	_ = got[0].Host.Stop()
}

// TestAdoptJailedHost: a jailed host's record names its chroot and cgroup;
// a refused one has its jail torn down, and one whose sockets cannot be
// handed to the jail uid (not root here) is killed.
func TestAdoptJailedHost(t *testing.T) {
	if _, err := sweepOpenPID(-1); err == nil {
		t.Fatal("opened pid -1")
	}
	base := filepath.Join(shortRunDir(t), "jail")
	chroot := filepath.Join(base, "jg")
	run := filepath.Join(chroot, JailRunDirName)
	if len(filepath.Join(run, hostSocketName)) > 100 {
		t.Skip("socket path too long here")
	}
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(t.TempDir(), ".hosts")
	rec := hostRecord{GroupKey: "jg", PID: 1, StartTicks: 1, BootID: "boot-0", RunDir: run, Jailed: true, ChrootDir: chroot,
		CgroupDir: filepath.Join(t.TempDir(), "elsewhere", "aerolvm-isolate-jg"), UID: 65534, GID: 65534}
	if err := writeRecordFile(filepath.Join(records, "jg.json"), rec); err != nil {
		t.Fatal(err)
	}
	withHostSeams(t, newHeldWorkerd(), nil)
	if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records, Logger: testLogger()}); len(got) != 0 {
		t.Fatal("adopted a jailed host from another boot")
	}
	if _, err := os.Stat(chroot); !os.IsNotExist(err) {
		t.Fatalf("refused host's chroot left: %v", err)
	}
	if os.Geteuid() == 0 {
		return // root can hand sockets to the jail uid; the rest needs a real jail
	}
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	rec.BootID = "boot-1"
	if err := writeRecordFile(filepath.Join(records, "jg.json"), rec); err != nil {
		t.Fatal(err)
	}
	proc := newHeldWorkerd()
	withHostSeams(t, proc, nil)
	if got := AdoptHosts(context.Background(), HostConfig{RecordDir: records}); len(got) != 0 {
		t.Fatal("adopted a jailed host whose sockets cannot be handed over")
	}
	if !proc.killed() {
		t.Fatal("workerd left running")
	}
}

// TestRecordFileFailures: the record write fails whole (never half) and
// its failures are reported, not fatal.
func TestRecordFileFailures(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRecordFile(filepath.Join(file, "g.json"), hostRecord{GroupKey: "g"}); err == nil {
		t.Fatal("record written under a file")
	}
	blocked := filepath.Join(dir, "g.json")
	blockPath(t, blocked)
	if err := writeRecordFile(blocked, hostRecord{GroupKey: "g"}); err == nil {
		t.Fatal("record replaced a directory")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" && e.Name() != "file" {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
	// removeRecord of a path that is a directory logs and goes on.
	h, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "g", RunDir: dir, RecordDir: dir, Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	h.removeRecord()
	// A jailed host names its cgroup in the record.
	withHostSeams(t, newHeldWorkerd(), nil)
	records := t.TempDir()
	jh, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "j", RunDir: dir, RecordDir: records})
	jh.jail = &jailRealized{cgroupDir: "/sys/fs/cgroup/aerolvm-isolate/aerolvm-isolate-j"}
	jh.started.Store(true)
	jh.writeRecord()
	if rec := readRecord(t, filepath.Join(records, "j.json")); rec.CgroupDir == "" {
		t.Fatal("jailed record has no cgroup")
	}
}

// TestUnjailedHostStartsThroughItsCgroup: an unjailed host starts workerd
// through the hosts' cgroup; where the cgroup is off it starts in place.
func TestUnjailedHostStartsThroughItsCgroup(t *testing.T) {
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no `false` binary")
	}
	cg := hostproc.NewCgroup(testLogger(), t.TempDir(), "aerolvm-isolate-hosts", "hosts")
	h, err := NewHost(HostConfig{WorkerdPath: falsePath, GroupKey: "cg", RunDir: shortRunDir(t), Cgroup: cg, StartTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("Start = %v, want workerd's exit", err)
	}
	if cg.Active() {
		t.Fatal("a cgroup off a cgroup v2 root is active")
	}
	// A workerd that cannot be started at all is reported as such.
	h2, _ := NewHost(HostConfig{WorkerdPath: filepath.Join(t.TempDir(), "none"), GroupKey: "cg2", RunDir: shortRunDir(t), Cgroup: cg})
	if err := h2.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "start workerd") {
		t.Fatalf("Start = %v", err)
	}
}
