package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootswap"
)

// syncBuffer is a log the keeper's goroutines and the test share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// shortDir is a folder with no link on the way (macOS: /var is one), short
// enough for a socket path.
func shortDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "sv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// releaser signs helpers with a throwaway key, standing in for a release,
// and stages them as the agent does.
type releaser struct {
	t    testing.TB
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	dir  string
}

func newReleaser(t testing.TB, stage string) *releaser {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	return &releaser{t: t, pub: pub, priv: priv, dir: stage}
}

// stage signs body as version, for this machine, and stages it.
func (r *releaser) stage(body []byte, version string) {
	r.t.Helper()
	r.stageFor(body, version, runtime.GOOS, runtime.GOARCH, r.priv)
}

func (r *releaser) stageFor(body []byte, version, goos, goarch string, priv ed25519.PrivateKey) {
	r.t.Helper()
	if err := rootswap.Stage(r.signFor(body, version, goos, goarch, priv), r.dir); err != nil {
		r.t.Fatal(err)
	}
}

// sign writes a signed release of body for this machine to a folder of its
// own, as the release lays it out, without staging it.
func (r *releaser) sign(body []byte, version string) string {
	r.t.Helper()
	return r.signFor(body, version, runtime.GOOS, runtime.GOARCH, r.priv)
}

func (r *releaser) signFor(body []byte, version, goos, goarch string, priv ed25519.PrivateKey) string {
	r.t.Helper()
	dir := shortDir(r.t)
	m, err := rootswap.NewManifest(bytes.NewReader(body), version, 1, goos, goarch)
	if err != nil {
		r.t.Fatal(err)
	}
	manifest, sig, err := rootswap.Sign(priv, m)
	if err != nil {
		r.t.Fatal(err)
	}
	for name, b := range map[string][]byte{rootswap.BinaryName: body, rootswap.ManifestName: manifest, rootswap.SignatureName: sig} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
			r.t.Fatal(err)
		}
	}
	return dir
}

// fakeChild is a helper process. It exits on the signals in exitOn, and
// counts as alive until it exits. What it leaves in its group (leave)
// runs on after it exits, until the group is emptied.
type fakeChild struct {
	bin    string
	exitOn []syscall.Signal
	ready  *os.File // the write end of its ready pipe

	mu      sync.Mutex
	signals []syscall.Signal
	left    bool // a process it started still runs in the group
	done    chan struct{}
	once    sync.Once
}

// leave starts a process in the helper's group that outlives the helper,
// as a CNI plugin's IPAM plugin does.
func (c *fakeChild) leave() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.left = true
}

func (c *fakeChild) leftover() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.left
}

func (c *fakeChild) Signal(sig syscall.Signal) error {
	c.mu.Lock()
	c.signals = append(c.signals, sig)
	c.mu.Unlock()
	if slices.Contains(c.exitOn, sig) {
		c.exit()
	}
	return nil
}

func (c *fakeChild) Done() <-chan struct{} { return c.done }

func (c *fakeChild) exit() {
	c.once.Do(func() {
		_ = c.ready.Close()
		close(c.done)
	})
}

func (c *fakeChild) serve() {
	_, _ = c.ready.Write([]byte{'1'})
	_ = c.ready.Close()
}

func (c *fakeChild) got() []syscall.Signal {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.signals)
}

func (c *fakeChild) exited() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// keeperRig runs a HelperKeeper whose helpers are fakes. behave says what
// the nth start (from 0) does; by default a helper serves and stops on
// SIGTERM. Every start checks no helper before it is still alive.
type keeperRig struct {
	t      *testing.T
	k      *HelperKeeper
	rel    *releaser
	logs   syncBuffer
	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	children []*fakeChild
	envs     [][]string
	overlap  string
	startErr func(n int) error
	behave   func(n int, c *fakeChild)
	// The helpers' group (rigGroup): Empty's calls, the nth failing when
	// emptyErr says so, and Remove's.
	empties, removes int
	emptyErr         func(n int) error
	removeErr        error
}

// rigGroup is the helpers' cgroup in a keeperRig: what a helper left
// stays in it until Empty kills it, unless emptyErr says it cannot.
type rigGroup struct{ r *keeperRig }

func (g rigGroup) Empty() error {
	r := g.r
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.empties
	r.empties++
	for _, c := range r.children {
		if !c.exited() {
			r.overlap = fmt.Sprintf("emptied the group while %s ran", c.bin)
		}
	}
	if r.emptyErr != nil {
		if err := r.emptyErr(n); err != nil {
			return err
		}
	}
	for _, c := range r.children {
		c.mu.Lock()
		c.left = false
		c.mu.Unlock()
	}
	return nil
}

func (g rigGroup) Remove() error {
	g.r.mu.Lock()
	defer g.r.mu.Unlock()
	g.r.removes++
	return g.r.removeErr
}

func newKeeperRig(t *testing.T, tune func(k *HelperKeeper)) *keeperRig {
	t.Helper()
	dir := shortDir(t)
	r := &keeperRig{t: t, rel: newReleaser(t, filepath.Join(dir, "stage"))}
	r.k = &HelperKeeper{
		StageDir: r.rel.dir, BinDir: filepath.Join(dir, "root", "rootd"),
		Socket: filepath.Join(dir, "sock", "root.sock"), SocketGID: os.Getgid(),
		Keys: []ed25519.PublicKey{r.rel.pub}, Env: []string{"SB_TEST=1"},
		Log:  slog.New(slog.NewTextHandler(&r.logs, nil)),
		Tick: 5 * time.Millisecond, ReadyWait: time.Second, KillAfter: 200 * time.Millisecond,
		RetryFailed: time.Hour, MinBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, HealthyAfter: time.Hour,
	}
	r.k.Start = r.start
	r.k.Group = rigGroup{r}
	if tune != nil {
		tune(r.k)
	}
	return r
}

func (r *keeperRig) start(bin string, env []string, files []*os.File) (Child, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.children)
	for _, c := range r.children {
		if !c.exited() {
			r.overlap = fmt.Sprintf("start %d (%s) while %s still ran", n, bin, c.bin)
		}
		if c.leftover() {
			r.overlap = fmt.Sprintf("start %d (%s) while what %s started still ran", n, bin, c.bin)
		}
	}
	if r.startErr != nil {
		if err := r.startErr(n); err != nil {
			r.children = append(r.children, &fakeChild{bin: "(failed)", done: closedChan(), ready: files[1]})
			return nil, err
		}
	}
	// The pipe end passed is the keeper's to close; the child holds a copy.
	w, err := dupFile(files[1])
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(files[0].Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		r.overlap = fmt.Sprintf("descriptor 3 is not the socket: %v", err)
	}
	c := &fakeChild{bin: bin, exitOn: []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}, ready: w, done: make(chan struct{})}
	r.children = append(r.children, c)
	r.envs = append(r.envs, env)
	behave := r.behave
	if behave == nil {
		behave = func(_ int, c *fakeChild) { c.serve() }
	}
	go behave(n, c)
	return c, nil
}

func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

func dupFile(f *os.File) (*os.File, error) {
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}

func (r *keeperRig) run() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go func() { defer close(r.done); r.k.Run(ctx) }()
	r.t.Cleanup(r.stop)
}

func (r *keeperRig) stop() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		r.t.Fatal("the keeper did not stop")
	}
	r.cancel = nil
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.overlap != "" {
		r.t.Fatalf("two helpers at once: %s", r.overlap)
	}
}

func (r *keeperRig) starts() []*fakeChild {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.children)
}

func (r *keeperRig) waitStarts(n int) []*fakeChild {
	r.t.Helper()
	eventually(r.t, fmt.Sprintf("%d starts", n), func() bool { return len(r.starts()) >= n })
	return r.starts()
}

func copyName(t *testing.T, version string, body []byte) string {
	t.Helper()
	m, err := rootswap.NewManifest(bytes.NewReader(body), version, 1, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s-%s-%s", rootswap.BinaryName, version, m.SHA256[:16])
}

// TestHelperFirstStart: a signed staged helper runs from root's copy, never
// from the staged folder, with the socket the supervisor made as its
// descriptor 3 and the handover named in its environment; the keeper
// stopping drains it and removes the socket.
func TestHelperFirstStart(t *testing.T) {
	r := newKeeperRig(t, nil)
	body := []byte("helper v1")
	r.rel.stage(body, "v1.0.0")
	r.run()
	c := r.waitStarts(1)[0]
	if c.bin != filepath.Join(r.k.BinDir, copyName(t, "v1.0.0", body)) {
		t.Fatalf("ran %s, want root's copy", c.bin)
	}
	env := strings.Join(r.envs[0], " ")
	for _, want := range []string{"SB_TEST=1", "SB_ROOTD_LISTEN_FD=3", "SB_ROOTD_READY_FD=4"} {
		if !strings.Contains(env, want) {
			t.Fatalf("env %q lacks %s", env, want)
		}
	}
	fi, err := os.Lstat(r.k.Socket)
	if err != nil || fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket %v, %v", fi, err)
	}
	eventually(t, "the serving line", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
	r.stop()
	if got := c.got(); !slices.Equal(got, []syscall.Signal{syscall.SIGTERM}) {
		t.Fatalf("signals %v, want one SIGTERM", got)
	}
	if _, err := os.Lstat(r.k.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
	if n := len(r.starts()); n != 1 {
		t.Fatalf("%d starts, want 1", n)
	}
}

// TestHelperSwapIsExclusive is outside review O6: the old helper is told to
// stop and has exited before the new one starts on the same socket; once
// the new one serves, the old copy goes.
func TestHelperSwapIsExclusive(t *testing.T) {
	r := newKeeperRig(t, nil)
	old := []byte("helper v1")
	r.rel.stage(old, "v1.0.0")
	r.run()
	first := r.waitStarts(1)[0]
	eventually(t, "v1 serving", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
	r.rel.stage([]byte("helper v2"), "v1.0.1")
	second := r.waitStarts(2)[1]
	if !first.exited() {
		t.Fatal("v2 started while v1 ran")
	}
	if !strings.Contains(second.bin, "v1.0.1") {
		t.Fatalf("second start ran %s", second.bin)
	}
	eventually(t, "v1's copy removed", func() bool {
		_, err := os.Stat(first.bin)
		return errors.Is(err, os.ErrNotExist)
	})
	eventually(t, "the swap logged", func() bool {
		return strings.Contains(r.logs.String(), "swapping the root helper") && strings.Count(r.logs.String(), "the root helper serves") >= 2
	})
	// The same release staged again is what runs: nothing happens.
	r.rel.stage([]byte("helper v2"), "v1.0.1")
	time.Sleep(50 * time.Millisecond)
	if n := len(r.starts()); n != 2 {
		t.Fatalf("%d starts after staging the running release again", n)
	}
}

// TestHelperSwapKillsAnOldOneThatWillNotStop: an old helper that ignores
// SIGTERM is killed after KillAfter, and the new one starts only after it
// has exited.
func TestHelperSwapKillsAnOldOneThatWillNotStop(t *testing.T) {
	r := newKeeperRig(t, nil)
	r.behave = func(n int, c *fakeChild) {
		if n == 0 {
			c.exitOn = []syscall.Signal{syscall.SIGKILL}
		}
		c.serve()
	}
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	r.run()
	first := r.waitStarts(1)[0]
	r.rel.stage([]byte("helper v2"), "v1.0.1")
	r.waitStarts(2)
	if got := first.got(); !slices.Equal(got, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("v1 got %v, want SIGTERM then SIGKILL", got)
	}
	if !strings.Contains(r.logs.String(), "did not stop in time") {
		t.Fatal("the kill was not logged")
	}
}

// TestHelperRollback: a new helper that does not start (exec fails, it
// exits first, it closes its pipe without a word, or it never says it
// serves) is stopped, its copy removed, and the old copy runs again. The
// same staged helper is not tried again until RetryFailed has passed.
func TestHelperRollback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		behave   func(n int, c *fakeChild)
		startErr func(n int) error
		want     string
	}{
		{"exec fails", nil, func(n int) error {
			if n == 1 {
				return errors.New("exec format error")
			}
			return nil
		}, "exec format error"},
		{"exits before it serves", func(n int, c *fakeChild) {
			if n == 1 {
				c.exit()
				return
			}
			c.serve()
		}, nil, "exited before it served"},
		{"closes its pipe without a word", func(n int, c *fakeChild) {
			if n == 1 {
				_ = c.ready.Close()
				return
			}
			c.serve()
		}, nil, "exited before it served"},
		{"never serves", func(n int, c *fakeChild) {
			if n != 1 {
				c.serve()
			}
		}, nil, "did not serve within"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newKeeperRig(t, func(k *HelperKeeper) { k.ReadyWait = 100 * time.Millisecond })
			r.behave, r.startErr = tc.behave, tc.startErr
			v1 := []byte("helper v1")
			r.rel.stage(v1, "v1.0.0")
			r.run()
			first := r.waitStarts(1)[0]
			r.rel.stage([]byte("helper v2"), "v1.0.1")
			third := r.waitStarts(3)[2]
			if third.bin != first.bin {
				t.Fatalf("after the failed swap ran %s, want v1's copy %s", third.bin, first.bin)
			}
			logs := r.logs.String()
			if !strings.Contains(logs, "the new root helper did not start") || !strings.Contains(logs, tc.want) {
				t.Fatalf("logs:\n%s", logs)
			}
			eventually(t, "v2's copy removed", func() bool {
				ents, _ := os.ReadDir(r.k.BinDir)
				return len(ents) == 1 && ents[0].Name() == filepath.Base(first.bin)
			})
			time.Sleep(50 * time.Millisecond) // many ticks: v2 waits for RetryFailed
			if n := len(r.starts()); n != 3 {
				t.Fatalf("%d starts; the failed helper was tried again at once", n)
			}
		})
	}
}

// TestHelperThatServedIsKept: a new helper that says it serves, however
// late, has taken the agent's calls and told it what it offers, so the
// supervisor never goes back to the older copy after that: it starts the
// newer one again instead (review T3-1).
func TestHelperThatServedIsKept(t *testing.T) {
	const wait = 40 * time.Millisecond
	for _, tc := range []struct {
		name   string
		behave func(c *fakeChild)
	}{
		{"says it serves while it is being stopped", func(c *fakeChild) {
			c.mu.Lock()
			c.exitOn = nil
			c.mu.Unlock()
			for !slices.Contains(c.got(), syscall.SIGTERM) {
				time.Sleep(time.Millisecond)
			}
			c.serve()
			c.exit()
		}},
		{"serves, then exits at once", func(c *fakeChild) {
			c.serve()
			c.exit()
		}},
		{"says it serves as the wait runs out", func(c *fakeChild) {
			// Like the real helper, it finishes starting before it
			// handles SIGTERM, then drains and exits.
			c.mu.Lock()
			c.exitOn = []syscall.Signal{syscall.SIGKILL}
			c.mu.Unlock()
			time.Sleep(wait)
			c.serve()
			for !slices.Contains(c.got(), syscall.SIGTERM) {
				select {
				case <-c.done:
					return
				case <-time.After(time.Millisecond):
				}
			}
			c.exit()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				r := newKeeperRig(t, func(k *HelperKeeper) { k.ReadyWait = wait })
				r.behave = func(n int, c *fakeChild) {
					if n == 1 {
						tc.behave(c)
						return
					}
					c.serve()
				}
				r.rel.stage([]byte("helper v1"), "v1.0.0")
				r.run()
				first := r.waitStarts(1)[0]
				r.rel.stage([]byte("helper v2"), "v1.0.1")
				second := r.waitStarts(2)[1]
				// Long enough for a rollback, a restart, or both.
				time.Sleep(4 * wait)
				for n, c := range r.starts()[2:] {
					if c.bin == first.bin {
						t.Fatalf("start %d ran v1's copy again after v2 said it serves; logs:\n%s", n+2, r.logs.String())
					}
					if c.bin != second.bin {
						t.Fatalf("start %d ran %s, want v2's copy %s", n+2, c.bin, second.bin)
					}
				}
				if strings.Contains(r.logs.String(), "the old one runs again") {
					t.Fatalf("rolled back; logs:\n%s", r.logs.String())
				}
				r.stop()
			}
		})
	}
}

// TestHelperRetriesAFailedSwapLater: after RetryFailed the same staged
// helper is tried again, and this time it runs.
func TestHelperRetriesAFailedSwapLater(t *testing.T) {
	r := newKeeperRig(t, func(k *HelperKeeper) { k.RetryFailed = 100 * time.Millisecond })
	r.behave = func(n int, c *fakeChild) {
		if n == 1 {
			c.exit()
			return
		}
		c.serve()
	}
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	r.run()
	r.waitStarts(1)
	r.rel.stage([]byte("helper v2"), "v1.0.1")
	fourth := r.waitStarts(4)[3]
	if !strings.Contains(fourth.bin, "v1.0.1") {
		t.Fatalf("the retry ran %s", fourth.bin)
	}
}

// TestHelperRestartsAfterACrash: a helper that dies after it served is
// started again from the same copy; sandboxes are not its children, so
// nothing else happens.
func TestHelperRestartsAfterACrash(t *testing.T) {
	r := newKeeperRig(t, nil)
	r.behave = func(n int, c *fakeChild) {
		c.serve()
		if n < 2 {
			time.Sleep(10 * time.Millisecond)
			c.exit()
		}
	}
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	r.run()
	all := r.waitStarts(3)
	for _, c := range all[1:] {
		if c.bin != all[0].bin {
			t.Fatalf("restart ran %s, want %s", c.bin, all[0].bin)
		}
	}
	if !strings.Contains(r.logs.String(), "sandboxes keep running") {
		t.Fatal("the crash was not logged")
	}
}

// TestHelperStartFailsUntilItCan: with no helper to go back to, a start
// that fails is tried again with a growing wait; so is a socket that
// cannot be made yet.
func TestHelperStartFailsUntilItCan(t *testing.T) {
	r := newKeeperRig(t, nil)
	r.startErr = func(n int) error {
		if n < 2 {
			return errors.New("text file busy")
		}
		return nil
	}
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	r.run()
	r.waitStarts(3)
	if !strings.Contains(r.logs.String(), "could not start the root helper") {
		t.Fatal("the failed start was not logged")
	}

	r2 := newKeeperRig(t, nil)
	if err := os.MkdirAll(r2.k.Socket, 0o755); err != nil { // a folder where the socket goes
		t.Fatal(err)
	}
	r2.rel.stage([]byte("helper v1"), "v1.0.0")
	r2.run()
	eventually(t, "the socket error", func() bool { return strings.Contains(r2.logs.String(), "the helper's socket") })
	if n := len(r2.starts()); n != 0 {
		t.Fatalf("%d starts with no socket", n)
	}
}

// TestHelperLook: a staged set is judged once it stayed the same for a
// tick, and once; a refusal is logged once; an older release is kept out
// quietly; an error in root's own folder is tried again.
func TestHelperLook(t *testing.T) {
	r := newKeeperRig(t, nil)
	r.k.defaults()
	if r.k.look() != nil {
		t.Fatal("an empty staged folder gave a helper")
	}
	r.rel.stage([]byte("helper v2"), "v2.0.0")
	if r.k.look() != nil {
		t.Fatal("a set seen for the first time was judged")
	}
	inst := r.k.look()
	if inst == nil || inst.Manifest.Version != "v2.0.0" {
		t.Fatalf("look = %+v", inst)
	}
	if r.k.look() != nil {
		t.Fatal("a judged set was judged again")
	}
	r.k.cur = inst

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name   string
		stage  func()
		reason string
		level  string
	}{
		{"older", func() { r.rel.stage([]byte("helper v1"), "v1.0.0") }, rootswap.ReasonOlder, "WARN"},
		{"signed by another key", func() { r.rel.stageFor([]byte("helper v3"), "v3.0.0", runtime.GOOS, runtime.GOARCH, other) }, rootswap.ReasonBadSignature, "ERROR"},
		{"for another machine", func() { r.rel.stageFor([]byte("helper v3"), "v3.0.0", "linux", "s390x", r.rel.priv) }, rootswap.ReasonPlatform, "ERROR"},
		{"unsigned", func() {
			r.rel.stage([]byte("helper v3"), "v3.0.0")
			_ = os.Remove(filepath.Join(r.rel.dir, rootswap.SignatureName))
		}, rootswap.ReasonUnsigned, "ERROR"},
		{"truncated", func() {
			r.rel.stage([]byte("helper v3"), "v3.0.0")
			_ = os.WriteFile(filepath.Join(r.rel.dir, rootswap.BinaryName), []byte("help"), 0o755)
		}, rootswap.ReasonTruncated, "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := r.logs.String()
			tc.stage()
			for range 5 {
				if got := r.k.look(); got != nil {
					t.Fatalf("look installed %+v", got.Manifest)
				}
			}
			added := strings.TrimPrefix(r.logs.String(), before)
			if strings.Count(added, "reason="+tc.reason) != 1 || !strings.Contains(added, "level="+tc.level) {
				t.Fatalf("want one %s line for %s, got:\n%s", tc.level, tc.reason, added)
			}
		})
	}

	t.Run("root's folder fails", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes a read-only folder")
		}
		r.rel.stage([]byte("helper v4"), "v4.0.0")
		_ = os.Chmod(r.k.BinDir, 0o500)
		t.Cleanup(func() { _ = os.Chmod(r.k.BinDir, 0o700) })
		before := r.logs.String()
		for range 5 {
			if r.k.look() != nil {
				t.Fatal("installed into a read-only folder")
			}
		}
		if added := strings.TrimPrefix(r.logs.String(), before); strings.Count(added, "could not check the staged root helper") != 1 {
			t.Fatalf("want one line, got:\n%s", added)
		}
		_ = os.Chmod(r.k.BinDir, 0o700)
		if inst := r.k.look(); inst == nil || inst.Manifest.Version != "v4.0.0" {
			t.Fatalf("after the folder came back: %+v", inst)
		}
	})
	t.Run("the staged folder is gone", func(t *testing.T) {
		_ = os.RemoveAll(r.rel.dir)
		before := r.logs.String()
		for range 3 {
			_ = r.k.look()
		}
		if added := strings.TrimPrefix(r.logs.String(), before); strings.Count(added, "cannot read the staged root helper folder") != 1 {
			t.Fatalf("want one line, got:\n%s", added)
		}
	})
}

// TestNewHelperKeeper: bad settings and an image with no release key stop
// the supervisor before it touches the machine.
func TestNewHelperKeeper(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := func() ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{pub}, nil }
	good := Settings{RootdStageDir: "/run/aerolvm-stage", RootdBinDir: defaultRootdBinDir, RootdSocket: defaultRootdSocket, RootdSocketGroup: "4242"}
	k, err := newHelperKeeper(good, keys, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if k.SocketGID != 4242 || k.StageDir != good.RootdStageDir || len(k.Keys) != 1 {
		t.Fatalf("%+v", k)
	}
	for _, tc := range []struct {
		name string
		mut  func(s *Settings)
		keys func() ([]ed25519.PublicKey, error)
		want string
	}{
		{"relative staged folder", func(s *Settings) { s.RootdStageDir = "stage" }, keys, "SB_ROOTD_STAGE_DIR"},
		{"unclean bin folder", func(s *Settings) { s.RootdBinDir = "/var/lib/../rootd" }, keys, "SB_ROOTD_BIN_DIR"},
		{"socket at /", func(s *Settings) { s.RootdSocket = "/" }, keys, "SB_ROOTD_SOCKET"},
		{"bin folder in the staged one", func(s *Settings) { s.RootdBinDir = "/run/aerolvm-stage/bin" }, keys, "overlap"},
		{"staged folder in the bin one", func(s *Settings) { s.RootdStageDir = defaultRootdBinDir + "/stage" }, keys, "overlap"},
		{"socket in the staged folder", func(s *Settings) { s.RootdSocket = "/run/aerolvm-stage/root.sock" }, keys, "overlap"},
		{"unknown group", func(s *Settings) { s.RootdSocketGroup = "no-such-group-aerolvm" }, keys, "SB_ROOTD_SOCKET_GROUP"},
		{"no release key", nil, func() ([]ed25519.PublicKey, error) { return nil, nil }, "no release key"},
		{"a broken key file", nil, func() ([]ed25519.PublicKey, error) { return nil, errors.New("bad key file") }, "bad key file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := good
			if tc.mut != nil {
				tc.mut(&s)
			}
			if _, err := newHelperKeeper(s, tc.keys, quiet()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newHelperKeeper = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLookupGroup(t *testing.T) {
	if gid, err := lookupGroup("123"); err != nil || gid != 123 {
		t.Fatalf("numeric: %d %v", gid, err)
	}
	// Every Unix machine names gid 0.
	if name := map[string]string{"linux": "root", "darwin": "wheel"}[runtime.GOOS]; name != "" {
		if gid, err := lookupGroup(name); err != nil || gid != 0 {
			t.Fatalf("%s: %d %v", name, gid, err)
		}
	}
	if _, err := lookupGroup("no-such-group-aerolvm"); err == nil {
		t.Fatal("an unknown group resolved")
	}
}

// TestHelperEnv: the helper gets the supervisor's own environment with the
// cgroup parent the supervisor worked out, and no handover left over.
func TestHelperEnv(t *testing.T) {
	got := helperEnv([]string{"PATH=/bin", "SB_CONTAINERD_CGROUP_PARENT=/agent/said", "SB_ROOTD_LISTEN_FD=9", "SB_ROOTD_READY_FD=8", "SB_X=1"}, "/kubepods/pod/ctr/sandboxes")
	want := []string{"PATH=/bin", "SB_X=1", "SB_CONTAINERD_CGROUP_PARENT=/kubepods/pod/ctr/sandboxes"}
	if !slices.Equal(got, want) {
		t.Fatalf("helperEnv = %v, want %v", got, want)
	}
}
