package worker

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/hostproc"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestParseConfinement(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Confinement
		ok   bool
	}{
		{"61000:61000", Confinement{UID: 61000, GID: 61000}, true},
		{" 7:8 ", Confinement{UID: 7, GID: 8}, true},
		{"61000", Confinement{}, false},
		{"x:1", Confinement{}, false},
		{"1:y", Confinement{}, false},
		{"0:1", Confinement{}, false},
		{"1:0", Confinement{}, false},
		{"", Confinement{}, false},
	} {
		got, err := parseConfinement(tc.raw)
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("parseConfinement(%q) = %+v, %v; want %+v ok=%v", tc.raw, got, err, tc.want, tc.ok)
		}
	}
}

func TestConfinementFor(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	for _, tc := range []struct {
		name string
		drop bool
		euid int
		want bool
	}{
		{"drop off", false, 0, false},
		{"not root", true, 1000, false},
		{"root", true, 0, confinementSupported},
	} {
		geteuid = func() int { return tc.euid }
		c := ConfinementFor(tc.drop, 61000, 61001)
		if c.Enabled() != tc.want {
			t.Fatalf("%s: ConfinementFor = %+v, want enabled=%v", tc.name, c, tc.want)
		}
		if c.Enabled() && (c.UID != 61000 || c.GID != 61001) {
			t.Fatalf("%s: ids = %+v", tc.name, c)
		}
	}
}

func TestConfineSpawner(t *testing.T) {
	base := func(context.Context, string) (*exec.Cmd, error) { return exec.Command("true"), nil }
	if got := Confine(base, Confinement{}); got == nil {
		t.Fatal("disabled Confine dropped the spawner")
	}
	if Confine(nil, Confinement{UID: 1, GID: 1}) != nil {
		t.Fatal("Confine invented a spawner")
	}
	spawn := Confine(base, Confinement{UID: 61000, GID: 61000})
	cmd, err := spawn(context.Background(), "/tmp/x.sock")
	if err != nil {
		t.Fatal(err)
	}
	// An inherited environment is kept, with the drop added.
	if !slices.Contains(cmd.Env, confineEnv+"=61000:61000") || len(cmd.Env) < 2 {
		t.Fatalf("env = %v", cmd.Env)
	}
	assertOwnPIDNamespace(t, cmd)
	failing := Confine(func(context.Context, string) (*exec.Cmd, error) { return nil, errors.New("boom") }, Confinement{UID: 1, GID: 1})
	if _, err := failing(context.Background(), "s"); err == nil {
		t.Fatal("spawn error lost")
	}
	// The default spawners carry the explicit environment through.
	cmd, err = Confine(DefaultSpawner, Confinement{UID: 5, GID: 6})(WithCompileCache(context.Background(), "/cache/o1"), "/tmp/y.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cmd.Env, confineEnv+"=5:6") || !slices.Contains(cmd.Env, cacheDirEnv+"=/cache/o1") {
		t.Fatalf("default spawner env = %v", cmd.Env)
	}
}

func TestCompileCacheOnContext(t *testing.T) {
	if CompileCacheOf(nil) != "" || CompileCacheOf(context.Background()) != "" {
		t.Fatal("cache without one set")
	}
	ctx := WithCompileCache(nil, " /c/o ")
	if CompileCacheOf(ctx) != "/c/o" {
		t.Fatalf("cache = %q", CompileCacheOf(ctx))
	}
	// The node-wide cache never reaches a worker; its owner's does.
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "/shared")
	env := workerEnvironment(ctx)
	if slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, "AEROL_WASM_COMPILE_CACHE_DIR=") }) {
		t.Fatalf("shared cache passed to a worker: %v", env)
	}
	if !slices.Contains(env, cacheDirEnv+"=/c/o") {
		t.Fatalf("owner cache missing: %v", env)
	}
	if slices.ContainsFunc(workerEnvironment(context.Background()), func(e string) bool { return strings.HasPrefix(e, cacheDirEnv+"=") }) {
		t.Fatal("a worker without an owner got a cache")
	}
}

// A crashed worker comes back with the cache it was started with.
func TestSupervisorRespawnKeepsCompileCache(t *testing.T) {
	var caches []string
	s := NewSupervisor(func(ctx context.Context, _ string) (*exec.Cmd, error) {
		caches = append(caches, CompileCacheOf(ctx))
		return exec.Command("true"), nil
	})
	if err := s.Ensure(WithCompileCache(context.Background(), "/c/owner-1"), "sb-cache", filepath.Join(t.TempDir(), "w.sock")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.SpawnCount("sb-cache") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	_ = s.Stop("sb-cache")
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(caches) < 2 || caches[0] != "/c/owner-1" || caches[1] != "/c/owner-1" {
		t.Fatalf("caches = %v", caches)
	}
}

func TestHeldDirAndOpenWorkerDirs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", filepath.Join(dir, "missing"), file} {
		if got := heldDir(p); got != "" {
			t.Fatalf("heldDir(%q) = %q", p, got)
		}
	}
	via := heldDir(dir)
	if runtime.GOOS == "linux" {
		if !strings.HasPrefix(via, "/proc/self/fd/") {
			t.Fatalf("heldDir = %q", via)
		}
	} else if via != dir {
		t.Fatalf("heldDir off linux = %q", via)
	}
	if _, err := os.Stat(via); err != nil {
		t.Fatalf("held dir unreachable: %v", err)
	}

	cache, spill := t.TempDir(), t.TempDir()
	t.Setenv(cacheDirEnv, cache)
	t.Setenv("SB_AUDIT_SPILL_DIR", spill)
	t.Cleanup(func() {
		spillDirOverride.Store(nil)
		wasmengine.SetCompileCacheDir("")
	})
	openWorkerDirs()
	if got := workerEgressSpillDir(); got == spill && runtime.GOOS == "linux" || got == "" {
		t.Fatalf("spill dir = %q", got)
	}
	if st, err := os.Stat(workerEgressSpillDir()); err != nil || !st.IsDir() {
		t.Fatalf("spill dir unreachable: %v", err)
	}
}

func TestConfineFromEnv(t *testing.T) {
	t.Setenv(confineEnv, "")
	if err := confineFromEnv(); err != nil {
		t.Fatalf("no confinement asked: %v", err)
	}
	t.Setenv(confineEnv, "nope")
	if err := confineFromEnv(); err == nil {
		t.Fatal("bad confinement accepted")
	}
	if runtime.GOOS != "linux" {
		t.Setenv(confineEnv, "61000:61000")
		if err := confineFromEnv(); err == nil {
			t.Fatal("a worker off linux served after it was asked to drop")
		}
	}
}

// The filter allows what a Go worker needs, kills the escape primitives,
// and every name it uses exists on the architecture (or is a legacy
// x86-64 name absent on arm64).
func TestWorkerSeccompPolicy(t *testing.T) {
	p := workerSeccompPolicy()
	allowed := map[string]bool{}
	for _, name := range p.Allow {
		if allowed[name] {
			t.Fatalf("%s allowed twice", name)
		}
		allowed[name] = true
	}
	for _, name := range workerSeccompKill {
		if allowed[name] {
			t.Fatalf("%s is both allowed and killed", name)
		}
		if p.Actions[name] != hostproc.SeccompRetKillProcess {
			t.Fatalf("%s is not killed", name)
		}
	}
	for _, must := range []string{"ptrace", "mount", "bpf", "execve", "setuid", "unshare", "setns", "io_uring_setup", "process_vm_writev"} {
		if p.Actions[must] != hostproc.SeccompRetKillProcess {
			t.Fatalf("%s not on the kill list", must)
		}
	}
	for _, must := range []string{"mmap", "mprotect", "futex", "clone", "openat", "recvmsg", "sendmsg", "connect", "tgkill", "kill"} {
		if !allowed[must] {
			t.Fatalf("%s not allowed", must)
		}
	}
	if p.Actions["clone3"] != hostproc.SeccompRetErrno(errnoENOSYS) || p.Default != hostproc.SeccompRetErrno(errnoEPERM) || p.RuleDeny != hostproc.SeccompRetKillProcess {
		t.Fatalf("clone3/default/rule deny = %#x %#x %#x", p.Actions["clone3"], p.Default, p.RuleDeny)
	}
	if len(p.Rules) != 2 || p.Rules[0].Syscall != "clone" || p.Rules[0].DenyIfAll[0].Mask&0x10000000 == 0 {
		t.Fatalf("clone rule = %+v", p.Rules)
	}
	// socket keeps IPv4, IPv6 and route netlink only; anything else fails
	// with EAFNOSUPPORT, not a kill (the Go runtime probes families).
	sock := p.Rules[1]
	if sock.Syscall != "socket" || sock.Deny != hostproc.SeccompRetErrno(errnoEAFNOSUPPORT) || len(sock.AllowIfAny) != 3 {
		t.Fatalf("socket rule = %+v", sock)
	}
	families := map[uint32]bool{}
	for _, entry := range sock.AllowIfAny {
		families[entry[0].Value] = true
		if entry[0].Value == linuxAFNetlink && (len(entry) != 2 || entry[1] != (hostproc.SeccompArgEq{Arg: 2, Value: linuxNetlinkRoute})) {
			t.Fatalf("netlink not narrowed to route: %+v", entry)
		}
	}
	for _, f := range []uint32{1 /* AF_UNIX */, 17 /* AF_PACKET */, 38 /* AF_ALG */, 40 /* AF_VSOCK */} {
		if families[f] {
			t.Fatalf("family %d allowed", f)
		}
	}
	for _, arch := range []uint32{hostproc.AuditArchX86_64, hostproc.AuditArchAARCH64} {
		if _, _, err := hostproc.BuildSeccomp(arch, map[string]int{"read": 0}, p); err != nil {
			t.Fatal(err)
		}
	}
	if table := hostproc.SyscallTable(); table != nil {
		_, unknown, err := hostproc.BuildSeccomp(hostproc.SeccompArch(), table, p)
		if err != nil {
			t.Fatal(err)
		}
		legacy := map[string]bool{"open": true, "stat": true, "lstat": true, "poll": true, "select": true, "dup2": true, "pipe": true,
			"eventfd": true, "getdents": true, "readlink": true, "access": true, "epoll_wait": true, "arch_prctl": true, "pause": true,
			"getpgrp": true, "mkdir": true, "rmdir": true, "unlink": true, "rename": true, "link": true, "symlink": true, "chmod": true,
			"iopl": true, "ioperm": true, "mknod": true}
		for _, name := range unknown {
			if runtime.GOARCH != "arm64" || !legacy[name] {
				t.Fatalf("%s is not in the %s syscall table", name, runtime.GOARCH)
			}
		}
	}
}

// runWorker without a drop: it reads its guards, listens, opens its dirs,
// builds its mediator and serves until its listener closes.
func TestRunWorkerServesAndStops(t *testing.T) {
	t.Setenv(confineEnv, "")
	t.Setenv(cacheDirEnv, "")
	t.Setenv(egresspolicy.DenyFloorEnv, "")
	t.Setenv(egresspolicy.PrivateRangesEnv, "")
	t.Setenv(egresspolicy.FloorFileEnv, "")
	t.Cleanup(func() { wasmengine.SetCompileCacheDir("") })
	prev := listenWorker
	t.Cleanup(func() { listenWorker = prev })
	prevGo := net.DefaultResolver.PreferGo
	t.Cleanup(func() { net.DefaultResolver.PreferGo = prevGo })
	lns := make(chan net.Listener, 1)
	listenWorker = func(path string) (net.Listener, error) {
		ln, err := prev(path)
		if err == nil {
			lns <- ln
		}
		return ln, err
	}
	sock := filepath.Join(shortTempDir(t), "w.sock")
	done := make(chan error, 1)
	go func() { done <- RunCLI([]string{sock}) }()
	ln := <-lns
	if err := NewClient(sock).Ping("sb"); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// Item 3: the worker resolves names with Go's own resolver, so no C
	// library name-service code runs under its syscall filter.
	if !net.DefaultResolver.PreferGo {
		t.Fatal("worker resolves names through the C library")
	}
	_ = ln.Close()
	if err := <-done; err == nil {
		t.Fatal("runWorker returned nil after its listener closed")
	}
	// A worker asked to drop that cannot (not root, or not Linux) never serves.
	t.Setenv(confineEnv, "61000:61000")
	if os.Geteuid() != 0 || runtime.GOOS != "linux" {
		err := RunCLIResident([]string{filepath.Join(shortTempDir(t), "r.sock")})
		if err == nil {
			t.Fatal("a worker served after failing to drop")
		}
	}
}

// shortTempDir keeps socket paths under sun_path's limit on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// R3: a confined worker spills into a folder of its own, made by sandboxd
// inside the shared one and owned by the worker uid; the shared folder is
// never in its environment.
func TestConfinePrivateSpillFolder(t *testing.T) {
	root := t.TempDir()
	c := Confinement{UID: os.Getuid(), GID: os.Getgid()}
	if os.Geteuid() == 0 {
		c = Confinement{UID: 65534, GID: 65534}
	}
	base := func(context.Context, string) (*exec.Cmd, error) {
		cmd := exec.Command("true")
		cmd.Env = []string{"PATH=/bin", spillEnv + "=" + root}
		return cmd, nil
	}
	spawn := Confine(base, c)
	cmd, err := spawn(WithSpillLabel(context.Background(), "sb-alpha"), "/run/x/.sockets/sb-alpha.sock")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "sb-alpha")
	if !slices.Contains(cmd.Env, spillEnv+"="+want) || slices.Contains(cmd.Env, spillEnv+"="+root) {
		t.Fatalf("env = %v", cmd.Env)
	}
	if st, err := os.Stat(want); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("spill folder = %v, %v", st, err)
	}
	// Without a label (a warm or resident worker) the folder is named for
	// its socket; a bad label is not used.
	cmd, _ = spawn(WithSpillLabel(context.Background(), "../escape"), "/run/x/pool/1/worker.sock")
	var got string
	for _, e := range cmd.Env {
		if v, ok := strings.CutPrefix(e, spillEnv+"="); ok {
			got = v
		}
	}
	if filepath.Dir(got) != root || !strings.HasPrefix(filepath.Base(got), "w-") {
		t.Fatalf("unlabelled spill folder = %q", got)
	}
	// A folder that cannot be made leaves the worker without one, never
	// with the shared folder.
	blocked := Confine(func(context.Context, string) (*exec.Cmd, error) {
		cmd := exec.Command("true")
		cmd.Env = []string{spillEnv + "=" + filepath.Join(root, "sb-alpha", "nested", "deeper")}
		return cmd, nil
	}, c)
	cmd, _ = blocked(context.Background(), "s")
	if slices.ContainsFunc(cmd.Env, func(e string) bool { return strings.HasPrefix(e, spillEnv+"=") }) {
		t.Fatalf("worker got a spill folder it could not have: %v", cmd.Env)
	}
	// A sandbox kept root (its mounts predate the drop) is not confined.
	cmd, _ = spawn(WithoutConfinement(context.Background()), "s")
	if slices.ContainsFunc(cmd.Env, func(e string) bool { return strings.HasPrefix(e, confineEnv+"=") }) || cmd.SysProcAttr != nil {
		t.Fatalf("root-only worker confined: %v", cmd.Env)
	}

	// The folder goes with its sandbox once nothing is left to drain.
	t.Setenv(spillEnv, root)
	if err := os.WriteFile(filepath.Join(want, "secrets.jsonl.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(want, "secrets.spill.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Records left to drain stay, under a name no new worker gets.
	RemoveSpillFolder("sb-alpha")
	retired := filepath.Join(root, "gone-sb-alpha")
	if _, err := os.Stat(filepath.Join(retired, "secrets.spill.jsonl")); err != nil {
		t.Fatalf("records left to drain not kept for the drain: %v", err)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("the live name stayed: %v", err)
	}
	if err := os.Mkdir(want, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(want, "secrets.jsonl.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	RemoveSpillFolder("bad/label")
	RemoveSpillFolder("sb-alpha")
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("drained folder kept: %v", err)
	}
	t.Setenv(spillEnv, "")
	RemoveSpillFolder("sb-alpha") // no spill root: nothing to do
}

// A worker stopped for good takes its spill folder with it: warm-pool
// slots and resident hosts must not each leave one behind.
func TestSupervisorStopRemovesSpillFolder(t *testing.T) {
	root := t.TempDir()
	t.Setenv(spillEnv, root)
	for _, tc := range []struct {
		name string
		ctx  context.Context
		gone bool
	}{
		{"warm slot", context.Background(), true},
		{"sandbox", WithSpillLabel(context.Background(), "sb-one"), true},
		{"kept root", WithoutConfinement(WithSpillLabel(context.Background(), "sb-two")), false},
	} {
		sock := filepath.Join(t.TempDir(), "w.sock")
		label := spillLabel(specFrom(tc.ctx), sock)
		dir := filepath.Join(root, label)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		s := NewSupervisor(func(context.Context, string) (*exec.Cmd, error) { return exec.Command("sleep", "60"), nil })
		if err := s.Ensure(tc.ctx, "k", sock); err != nil {
			t.Fatal(err)
		}
		if err := s.Stop("k"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir); os.IsNotExist(err) != tc.gone {
			t.Fatalf("%s: folder after stop = %v, want gone=%v", tc.name, err, tc.gone)
		}
	}
}

// What sandboxd decided for a worker survives a respawn after a crash.
func TestSupervisorRespawnKeepsSpawnSpec(t *testing.T) {
	var specs []spawnSpec
	s := NewSupervisor(func(ctx context.Context, _ string) (*exec.Cmd, error) {
		specs = append(specs, specFrom(ctx))
		return exec.Command("true"), nil
	})
	ctx := WithoutConfinement(WithSpillLabel(WithCompileCache(context.Background(), "/c"), "sb-x"))
	if err := s.Ensure(ctx, "sb-x", filepath.Join(t.TempDir(), "w.sock")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.SpawnCount("sb-x") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	_ = s.Stop("sb-x")
	s.mu.Lock()
	defer s.mu.Unlock()
	want := spawnSpec{cacheDir: "/c", spillLabel: "sb-x", rootOnly: true}
	if len(specs) < 2 || specs[0] != want || specs[1] != want {
		t.Fatalf("specs = %+v", specs)
	}
}

// A folder heldDir opened stays reachable after garbage collections: the
// *os.File behind it must not be left to its finalizer.
func TestHeldDirSurvivesGC(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	via := heldDir(dir)
	for range 3 {
		runtime.GC()
	}
	time.Sleep(10 * time.Millisecond)
	runtime.GC()
	if _, err := os.Stat(filepath.Join(via, "marker")); err != nil {
		t.Fatalf("held folder lost after GC: %v", err)
	}
}

// A worker that would drop is not started while the confine gate refuses
// (the WASM worker fence is not in); one kept root is not asked.
func TestConfineGate(t *testing.T) {
	t.Cleanup(func() { SetConfineGate(nil) })
	starts := 0
	base := func(context.Context, string) (*exec.Cmd, error) {
		starts++
		return exec.Command("true"), nil
	}
	spawn := Confine(base, Confinement{UID: 4242, GID: 4242})
	refusal := errors.New("wasm worker fence: not installed")
	SetConfineGate(func() error { return refusal })
	if _, err := spawn(context.Background(), "s"); !errors.Is(err, refusal) || starts != 0 {
		t.Fatalf("spawn past a closed gate = %v, starts=%d", err, starts)
	}
	if _, err := spawn(WithoutConfinement(context.Background()), "s"); err != nil || starts != 1 {
		t.Fatalf("root-only spawn = %v, starts=%d", err, starts)
	}
	SetConfineGate(func() error { return nil })
	if _, err := spawn(context.Background(), "s"); err != nil || starts != 2 {
		t.Fatalf("spawn past an open gate = %v", err)
	}
	SetConfineGate(nil)
	if _, err := spawn(context.Background(), "s"); err != nil || starts != 3 {
		t.Fatalf("spawn with no gate = %v", err)
	}
}
