package supervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootswap"
)

// This test binary is also the root helper these tests swap: run with
// testHelperEnv set to a folder, it serves the helper's real server
// (internal/rootd, its own calls and folders) on the socket the keeper
// passed it, as aerolvm-rootd does, and leaves its record in that folder.
const testHelperEnv = "AEROLVM_SUPERVISOR_TEST_HELPER"

// What a test helper does, from its environment.
const (
	helperDelayEnv      = "AEROLVM_TEST_HELPER_DELAY"       // every call takes this long
	helperSlowRemoveEnv = "AEROLVM_TEST_HELPER_SLOW_REMOVE" // RemoveContainerFiles waits for SIGTERM, then this long
	helperGraceEnv      = "AEROLVM_TEST_HELPER_GRACE"       // its drain deadline
)

func TestMain(m *testing.M) {
	if dir := os.Getenv(testHelperEnv); dir != "" {
		os.Exit(testHelperMain(dir))
	}
	os.Exit(m.Run())
}

// testHelperMain is the helper. It holds a lock on serving.lock for its
// whole life and takes it without waiting: a helper that finds it taken
// would serve beside another, so it leaves overlap.<pid> and exits. The
// lock is the proof the handover is exclusive.
func testHelperMain(dir string) int {
	logf, err := os.OpenFile(filepath.Join(dir, "helpers.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 2
	}
	defer logf.Close()
	log := slog.New(slog.NewTextHandler(logf, nil)).With("pid", os.Getpid())
	lock, err := os.OpenFile(filepath.Join(dir, "serving.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		log.Error("lock", "error", err)
		return 2
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = os.WriteFile(filepath.Join(dir, "overlap."+strconv.Itoa(os.Getpid())), nil, 0o644)
		return 3
	}
	dur := func(k string, def time.Duration) time.Duration {
		if d, err := time.ParseDuration(os.Getenv(k)); err == nil {
			return d
		}
		return def
	}
	delay, slowRemove, grace := dur(helperDelayEnv, 0), dur(helperSlowRemoveEnv, 0), dur(helperGraceEnv, 5*time.Second)
	cfg, err := rootd.ConfigFromEnv(os.Getenv)
	if err != nil {
		log.Error("config", "error", err)
		return 2
	}
	ln, err := rootswap.InheritedListener(os.Getenv)
	if err != nil || ln == nil {
		log.Error("no inherited socket", "error", err)
		return 2
	}
	var served atomic.Int64
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	slow := grpc.ChainUnaryInterceptor(func(cctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		served.Add(1)
		time.Sleep(delay)
		if slowRemove > 0 && info.FullMethod == rootdpb.RootHelper_RemoveContainerFiles_FullMethodName {
			// The test's first remove, in any helper, is still running
			// when the swap begins, and after: it lands as late as an old
			// helper can make it.
			if f, err := os.OpenFile(filepath.Join(dir, "removing"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
				_ = f.Close()
				<-ctx.Done()
				time.Sleep(slowRemove)
			}
		}
		return next(cctx, req)
	})
	srv, err := rootd.New(cfg, rootd.Options{
		Containerd:    func(any, grpc.ServerStream) error { return status.Error(codes.Unimplemented, "no containerd here") },
		Peer:          func(net.Conn) error { return nil },
		Listener:      ln,
		ServerOptions: []grpc.ServerOption{slow},
	}, log)
	if err != nil {
		log.Error("server", "error", err)
		return 2
	}
	drained := make(chan struct{})
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), grace)
		srv.Shutdown(sctx)
		cancel()
		close(drained)
	}()
	if err := rootswap.NotifyReady(os.Getenv); err != nil {
		log.Error("ready", "error", err)
	}
	log.Info("serving")
	if err := srv.Serve(); err != nil {
		log.Error("serve", "error", err)
	}
	<-drained
	_ = os.WriteFile(filepath.Join(dir, "served."+strconv.Itoa(os.Getpid())), []byte(strconv.FormatInt(served.Load(), 10)), 0o644)
	log.Info("stopped", "served", served.Load())
	return 0
}

// execChild is a helper started with os/exec, on any platform.
type execChild struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (c *execChild) Signal(sig syscall.Signal) error { return c.cmd.Process.Signal(sig) }
func (c *execChild) Done() <-chan struct{}           { return c.done }

func execStart(bin string, env []string, files []*os.File) (Child, error) {
	cmd := exec.Command(bin)
	cmd.Env, cmd.ExtraFiles = env, files
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &execChild{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(c.done) }()
	return c, nil
}

// starters: os/exec everywhere, and on Linux the supervisor's own, which
// follows the helper by pidfd.
func starters() map[string]func(string, []string, []*os.File) (Child, error) {
	s := map[string]func(string, []string, []*os.File) (Child, error){"exec": execStart}
	if runtime.GOOS == "linux" {
		s["pidfd"] = func(bin string, env []string, files []*os.File) (Child, error) {
			return StartHelper("", bin, env, files)
		}
	}
	return s
}

// procRig runs a keeper whose helpers are real processes: this test binary,
// signed with a throwaway key at whatever version the test stages.
type procRig struct {
	*keeperRig
	dir    string // the helpers' records
	self   []byte // this binary: every release's bytes
	client *rootclient.Client
	files  string   // the helpers' own folders
	bins   []string // every copy started, in order (keeperRig.mu)
}

func (r *procRig) started() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bins...)
}

func newProcRig(t *testing.T, start func(string, []string, []*os.File) (Child, error), helperEnv ...string) *procRig {
	t.Helper()
	if testing.Short() {
		t.Skip("runs real helper processes")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	r := &procRig{keeperRig: newKeeperRig(t, func(k *HelperKeeper) {
		k.Tick, k.ReadyWait, k.KillAfter, k.RetryFailed = 20*time.Millisecond, 30*time.Second, 20*time.Second, time.Hour
	}), dir: shortDir(t), self: self, files: shortDir(t)}
	r.k.Start = func(bin string, env []string, files []*os.File) (Child, error) {
		r.mu.Lock()
		r.bins = append(r.bins, bin)
		r.mu.Unlock()
		return start(bin, env, files)
	}
	r.k.Env = append(os.Environ(),
		testHelperEnv+"="+r.dir,
		"SB_ROOTD_SOCKET="+r.k.Socket,
		"SB_ROOTD_SOCKET_GROUP="+strconv.Itoa(os.Getgid()),
		"SB_ROOTD_AGENT_UID=54321",
		"SB_HOST_MEMORY_MB=1024",
		"SB_CONTAINERD_SOCKET="+filepath.Join(r.files, "containerd", "containerd.sock"),
		"SB_ROOTD_STATE_DIR="+filepath.Join(r.files, "state"),
		"SB_ROOTD_FIFO_DIR="+filepath.Join(r.files, "run", "fifo"),
		"SB_ROOTD_READY_DIR="+filepath.Join(r.files, "run", "ready"),
		"SB_MOUNTS_CRED_DIR="+filepath.Join(r.files, "agent"),
	)
	r.k.Env = append(r.k.Env, helperEnv...)
	// A test machine running other packages' tests can be slow to start a
	// race-built helper; the client's timeout bounds how long a dropped
	// call waits for the next one, so it is generous here.
	r.client = rootclient.New(rootclient.Config{Socket: r.k.Socket, Timeout: 5 * time.Second, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = r.client.Close() })
	return r
}

// release stages this binary as version and waits until the keeper says
// that version serves.
func (r *procRig) release(version string) {
	r.t.Helper()
	before := strings.Count(r.logs.String(), "the root helper serves")
	r.rel.stage(r.self, version)
	eventually(r.t, version+" serving", func() bool {
		l := r.logs.String()
		return strings.Count(l, "the root helper serves") > before && strings.Contains(l, "version="+version)
	})
}

func (r *procRig) records(prefix string) map[string]string {
	r.t.Helper()
	ents, err := os.ReadDir(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			b, _ := os.ReadFile(filepath.Join(r.dir, e.Name()))
			out[e.Name()] = string(b)
		}
	}
	return out
}

// dump is what the keeper and the helpers logged, for a failure's message.
func (r *procRig) dump() string {
	helpers, _ := os.ReadFile(filepath.Join(r.dir, "helpers.log"))
	return "keeper:\n" + r.logs.String() + "helpers:\n" + string(helpers)
}

func (r *procRig) checkExclusive() {
	r.t.Helper()
	if o := r.records("overlap."); len(o) != 0 {
		logs, _ := os.ReadFile(filepath.Join(r.dir, "helpers.log"))
		r.t.Fatalf("two helpers served at once: %v\n%s", o, logs)
	}
}

func (r *procRig) hostnameFile(id string) string {
	return filepath.Join(r.files, "state", "hosts", id, "hostname")
}

func ensureHost(ctx context.Context, c *rootclient.Client, id string) error {
	_, err := c.EnsureHostFiles(ctx, &rootdpb.EnsureHostFilesRequest{ContainerId: id, Hostname: id})
	return err
}

// TestSwapUnderLoadLosesNoCall is the plan's D4 test: 100 callers make and
// remove their containers' files through a swap. No call fails, the old
// helper and the new one both served, never at once (each holds
// serving.lock for its life), and every container ends as its last call
// left it.
func TestSwapUnderLoadLosesNoCall(t *testing.T) {
	for name, start := range starters() {
		t.Run(name, func(t *testing.T) {
			r := newProcRig(t, start, helperDelayEnv+"=2ms")
			r.run()
			r.release("v1.0.0")
			const callers = 100
			var calls, failed atomic.Int64
			var firstErr atomic.Value
			var swapped atomic.Bool
			var wg sync.WaitGroup
			progress := make([]atomic.Int64, callers)
			for i := range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					id := fmt.Sprintf("sb-%d", i)
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					// Keep going until the swap is over, then a few more,
					// ending on a make.
					for n := 0; !swapped.Load() || n%2 == 0 || progress[i].Load() < 4; n++ {
						var err error
						if n%2 == 0 {
							err = ensureHost(ctx, r.client, id)
						} else {
							err = r.client.RemoveContainerFiles(ctx, id)
						}
						calls.Add(1)
						progress[i].Add(1)
						if err != nil {
							failed.Add(1)
							firstErr.CompareAndSwap(nil, fmt.Errorf("%s call %d: %w", id, n, err))
						}
					}
				}()
			}
			eventually(t, "every caller under way", func() bool {
				for i := range progress {
					if progress[i].Load() < 2 {
						return false
					}
				}
				return true
			})
			r.release("v1.0.1")
			for i := range progress {
				progress[i].Store(0) // a few more calls each, all on the new helper
			}
			swapped.Store(true)
			wg.Wait()
			if failed.Load() != 0 {
				t.Fatalf("%d of %d calls failed; first: %v\n%s", failed.Load(), calls.Load(), firstErr.Load(), r.dump())
			}
			for i := range callers {
				if _, err := os.Stat(r.hostnameFile(fmt.Sprintf("sb-%d", i))); err != nil {
					t.Fatalf("sb-%d ended without its files: %v", i, err)
				}
			}
			r.stop()
			r.checkExclusive()
			served := r.records("served.")
			if len(served) != 2 {
				t.Fatalf("helpers that served: %v, want the old and the new", served)
			}
			for pid, n := range served {
				if n == "0" {
					t.Fatalf("helper %s served no call: %v", pid, served)
				}
			}
			t.Logf("%d calls through the swap, served %v", calls.Load(), served)
		})
	}
}

// TestRemoveThenMakeStraddlingASwap is the plan's O6 test: a container's
// remove is in flight on the old helper when the swap begins, and its make
// follows. The container ends made: the old helper's remove is over before
// the new helper serves, whether the drain let it finish or cut its
// connection (the agent then sends it again, to the new helper).
func TestRemoveThenMakeStraddlingASwap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		grace string
	}{
		{"the drain lets the remove finish", "10s"},
		{"the drain cuts the remove", "100ms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newProcRig(t, starters()["exec"], helperSlowRemoveEnv+"=500ms", helperGraceEnv+"="+tc.grace)
			r.run()
			r.release("v1.0.0")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := ensureHost(ctx, r.client, "sb-1"); err != nil {
				t.Fatal(err)
			}
			removed := make(chan error, 1)
			go func() { removed <- r.client.RemoveContainerFiles(ctx, "sb-1") }()
			eventually(t, "the remove in flight", func() bool { return len(r.records("removing")) == 1 })
			r.rel.stage(r.self, "v1.0.1")
			if err := <-removed; err != nil {
				t.Fatalf("the remove that straddled the swap = %v\n%s", err, r.dump())
			}
			if err := ensureHost(ctx, r.client, "sb-1"); err != nil {
				t.Fatalf("the make after it = %v\n%s", err, r.dump())
			}
			eventually(t, "v1.0.1 serving", func() bool { return strings.Contains(r.logs.String(), "version=v1.0.1") })
			time.Sleep(time.Second) // longer than the old remove could still take
			if _, err := os.Stat(r.hostnameFile("sb-1")); err != nil {
				t.Fatalf("sb-1 ended removed: %v", err)
			}
			r.stop()
			r.checkExclusive()
		})
	}
}

// TestStagedFileReplacedAfterTheCheck is outside review O3 at the
// supervisor: once a helper runs from root's copy, whatever the agent does
// to the staged binary changes nothing that runs. Writing into it under
// the running release's manifest is not even read (that release runs
// already); under a newer manifest it is refused (the copy's hash), and so
// is a link in its place. What runs keeps the signed bytes and serves.
func TestStagedFileReplacedAfterTheCheck(t *testing.T) {
	r := newProcRig(t, starters()["exec"])
	r.run()
	r.release("v1.0.0")
	starts := len(r.started())
	copyPath := r.started()[0]
	staged := filepath.Join(r.rel.dir, rootswap.BinaryName)
	tampered := make([]byte, len(r.self))
	copy(tampered, "#!/bin/sh\necho swapped\n")
	if err := os.WriteFile(staged, tampered, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * r.k.Tick)

	// A newer release's manifest and signature, over the tampered binary.
	signed := r.rel.sign(r.self, "v1.0.1")
	for _, n := range []string{rootswap.ManifestName, rootswap.SignatureName} {
		b, err := os.ReadFile(filepath.Join(signed, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r.rel.dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "the hash refusal", func() bool { return strings.Contains(r.logs.String(), "reason="+rootswap.ReasonHash) })
	_ = os.Remove(staged)
	if err := os.Symlink(filepath.Join(signed, rootswap.BinaryName), staged); err != nil { // the signed bytes, behind a link
		t.Fatal(err)
	}
	eventually(t, "the link refusal", func() bool { return strings.Contains(r.logs.String(), "reason="+rootswap.ReasonNotFile) })

	if n := len(r.started()); n != starts {
		t.Fatalf("%d starts after the staged file changed, want %d", n, starts)
	}
	got, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(r.self) {
		t.Fatal("root's copy changed with the staged file")
	}
	if err := ensureHost(context.Background(), r.client, "sb-1"); err != nil {
		t.Fatalf("the signed helper stopped serving: %v", err)
	}
	r.stop()
	r.checkExclusive()
}

// TestRunStartsTheStagedHelper: Run with a staged folder set starts the
// helper in the runtime's own group, with the cgroup parent it worked out,
// and stops it with the supervisor; with no release key built in it does
// not start at all.
func TestRunStartsTheStagedHelper(t *testing.T) {
	l := fakeCgroup(t, "/kubepods/pod1/ctr", "12884901888", "1")
	dir := shortDir(t)
	rel := newReleaser(t, filepath.Join(dir, "stage"))
	rel.stage([]byte("helper v1"), "v1.0.0")
	s := Settings{ContainerdBinary: "/opt/containerd", ContainerdConfig: filepath.Join(dir, "config.toml"), ParentFile: filepath.Join(dir, "cgroup-parent"),
		NetnsDir: filepath.Join(dir, "netns"), RootdStageDir: rel.dir, RootdBinDir: filepath.Join(dir, "root", "rootd"),
		RootdSocket: filepath.Join(dir, "sock", "root.sock"), RootdSocketGroup: strconv.Itoa(os.Getgid())}
	_ = os.WriteFile(s.ContainerdConfig, []byte("version = 3"), 0o644)
	old := helperTick
	helperTick = 10 * time.Millisecond
	t.Cleanup(func() { helperTick = old })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var startedIn string
	var env []string
	var child *fakeChild
	sys := OS{
		CgroupRoot: l.Root,
		ReadFile: func(p string) ([]byte, error) {
			if p == "/proc/self/cgroup" {
				return []byte("0::/kubepods/pod1/ctr\n"), nil
			}
			return []byte{}, nil
		},
		LowerOOM:     func() error { return nil },
		BecomeReaper: func() error { return nil },
		StartInGroup: func(string, []string) (int, error) { return 4242, nil },
		Terminate:    func(int) {},
		Unmount:      func(string) error { return nil },
		Reap:         func(*atomic.Int64, chan<- int, *slog.Logger) {},
		StartHelper: func(d, bin string, e []string, files []*os.File) (Child, error) {
			w, err := dupFile(files[1])
			if err != nil {
				return nil, err
			}
			c := &fakeChild{bin: bin, exitOn: []syscall.Signal{syscall.SIGTERM}, ready: w, done: make(chan struct{})}
			c.serve()
			mu.Lock()
			startedIn, env, child = d, e, c
			mu.Unlock()
			return c, nil
		},
		ReleaseKeys: func() ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{rel.pub}, nil },
		Environ:     func() []string { return []string{"PATH=/bin", "SB_CONTAINERD_CGROUP_PARENT=/stale"} },
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, sys, quiet()) }()
	eventually(t, "the helper started", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return child != nil
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if startedIn != l.RuntimeDir() {
		t.Fatalf("helper started in %s, want %s", startedIn, l.RuntimeDir())
	}
	if !slicesContains(env, "SB_CONTAINERD_CGROUP_PARENT=/kubepods/pod1/ctr/sandboxes") || slicesContains(env, "SB_CONTAINERD_CGROUP_PARENT=/stale") {
		t.Fatalf("helper env %v", env)
	}
	if !child.exited() {
		t.Fatal("the helper outlived the supervisor")
	}

	sys.ReleaseKeys = func() ([]ed25519.PublicKey, error) { return nil, nil }
	if err := Run(context.Background(), s, sys, quiet()); err == nil || !strings.Contains(err.Error(), "no release key") {
		t.Fatalf("Run with no release key = %v", err)
	}
}

func slicesContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// The keeper's errors from a helper that cannot start are not a crash of
// the supervisor; this only checks the test's own helper refuses to serve
// without the supervisor's socket.
func TestTestHelperNeedsTheSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a helper process")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortDir(t)
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), testHelperEnv+"="+dir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	err = cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("a helper with no config or socket = %v, want exit 2", err)
	}
}
