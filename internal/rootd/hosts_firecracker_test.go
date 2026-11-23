package rootd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

const firecracker = rootdpb.HostKind_HOST_KIND_FIRECRACKER

// tinyBase is a chroot base short enough for the API socket's path under
// it (macOS's temp folders are long).
func tinyBase(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "fc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o755); err != nil {
		t.Fatal(err)
	}
	return real
}

// testFirecrackerConfig is a Firecracker config on this test's own user:
// the jailer's user and the agent are both the test's (only root gives a
// file away; tests stand fchown in).
func testFirecrackerConfig(t *testing.T) *FirecrackerHostsConfig {
	t.Helper()
	base := tinyBase(t)
	kernel := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	if gid == 0 {
		gid = 4242 // as root: the helper refuses root's group for the jailer
	}
	return &FirecrackerHostsConfig{JailerBinary: "/usr/local/bin/jailer", FirecrackerBinary: "/usr/local/bin/firecracker",
		ChrootBase: base, UID: os.Getuid(), GID: gid, Kernel: kernel, Mkfs4Bin: "/sbin/mkfs.ext4",
		Shim: "/usr/local/bin/aerolvm-rootd", AgentUID: uint32(os.Getuid()), SocketWait: time.Second,
		TapBase: "172.16.0.0/20", TapPoolSize: 256}
}

// chownLog records what the hosts gave away.
type chownLog struct {
	mu  sync.Mutex
	got []string
}

func (c *chownLog) fchown(fd, uid, gid int) error {
	var st unix.Stat_t
	_ = unix.Fstat(fd, &st)
	c.mu.Lock()
	c.got = append(c.got, strings.Join([]string{modeKind(uint32(st.Mode)), itoa(uid), itoa(gid)}, ":"))
	c.mu.Unlock()
	return nil
}

func modeKind(m uint32) string {
	if m&unix.S_IFMT == unix.S_IFDIR {
		return "dir"
	}
	return "file"
}

func itoa(n int) string { return strconv.Itoa(n) }

func newTestFirecracker(t *testing.T) (*firecrackerHosts, *chownLog) {
	t.Helper()
	c := testFirecrackerConfig(t)
	f := newFirecrackerHosts(c, filepath.Join(t.TempDir(), "hosts.log"), os.Getgid())
	cl := &chownLog{}
	f.fchown = cl.fchown
	f.checkKernel = func(string) error { return nil }
	return f, cl
}

func stageFile(t *testing.T, stage, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(stage, name), []byte(name), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFirecrackerPrepare(t *testing.T) {
	f, cl := newTestFirecracker(t)
	resp, err := f.prepare("sb-1", false, &rootdpb.PrepareHostRequest{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-1")
	if resp.GetRunDir() != dir+"/root" || resp.GetStageDir() != dir+"/stage" {
		t.Fatalf("prepare = %+v", resp)
	}
	setgid := os.ModeSetgid
	if runtime.GOOS != "linux" {
		setgid = 0 // BSD folders pass their group down anyway, and drop the bit
	}
	for p, want := range map[string]os.FileMode{dir: 0o711, filepath.Dir(dir): 0o711, dir + "/stage": 0o700,
		dir + "/root": 0o750 | setgid} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm()|fi.Mode()&os.ModeSetgid != want {
			t.Errorf("%s: %v %v, want %v", p, fi.Mode(), err, want)
		}
	}
	// The kernel is in the chroot, the helper's own file, given to root.
	if in, err := os.Stat(dir + "/root/" + rootpolicy.FirecrackerKernel); err != nil || in.Mode().Perm() != 0o640 {
		t.Fatalf("kernel: %v %v", in, err)
	}
	if !slices.Contains(cl.got, "file:0:"+itoa(f.cfg.GID)) {
		t.Fatalf("kernel not given to root and the jailer's group: %v", cl.got)
	}

	// The agent's disks move into the chroot for the jailer's user.
	stageFile(t, dir+"/stage", rootpolicy.FirecrackerRootfs)
	stageFile(t, dir+"/stage", rootpolicy.FirecrackerOverlay)
	spec := &rootdpb.PrepareHostRequest{Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerRootfs, rootpolicy.FirecrackerOverlay}}}
	if _, err := f.prepare("sb-1", false, spec); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{rootpolicy.FirecrackerRootfs, rootpolicy.FirecrackerOverlay} {
		fi, err := os.Lstat(dir + "/root/" + name)
		if err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
			t.Errorf("%s in the chroot: %v %v", name, fi, err)
		}
		if _, err := os.Lstat(dir + "/stage/" + name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left in the stage folder: %v", name, err)
		}
	}
	if !slices.Contains(cl.got, "file:"+itoa(f.cfg.UID)+":"+itoa(f.cfg.GID)) {
		t.Fatalf("disks not given to the jailer: %v", cl.got)
	}
	// Again while the VM runs (the disks move in after the jailer has
	// started firecracker): already moved, nothing to do.
	if _, err := f.prepare("sb-1", true, spec); err != nil {
		t.Fatalf("a second prepare: %v", err)
	}
}

func TestFirecrackerPrepareRefusals(t *testing.T) {
	f, _ := newTestFirecracker(t)
	if _, err := f.prepare("sb-2", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-2", "stage")
	spec := func(names ...string) *rootdpb.PrepareHostRequest {
		return &rootdpb.PrepareHostRequest{Firecracker: &rootdpb.FirecrackerHostSpec{Stage: names}}
	}
	// Not a disk name the agent may stage.
	for _, name := range []string{rootpolicy.FirecrackerKernel, "../x", "api.socket", "firecracker"} {
		if _, err := f.prepare("sb-2", false, spec(name)); err == nil {
			t.Errorf("staged %q", name)
		}
	}
	// Not in the stage folder.
	if _, err := f.prepare("sb-2", false, spec(rootpolicy.FirecrackerRootfs)); status.Code(errOf(err)) != codes.InvalidArgument {
		t.Errorf("a missing disk: %v", err)
	}
	// A link, even to a file of the agent's own: never followed.
	own := filepath.Join(t.TempDir(), "own.ext4")
	stageFile(t, filepath.Dir(own), "own.ext4")
	if err := os.Symlink(own, filepath.Join(stage, rootpolicy.FirecrackerRootfs)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepare("sb-2", false, spec(rootpolicy.FirecrackerRootfs)); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("staged a symlink: %v", err)
	}
	_ = os.Remove(filepath.Join(stage, rootpolicy.FirecrackerRootfs))
	// A file with a second name: it may be another's file the agent linked.
	stageFile(t, stage, rootpolicy.FirecrackerOverlay)
	if err := os.Link(filepath.Join(stage, rootpolicy.FirecrackerOverlay), filepath.Join(t.TempDir(), "other")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepare("sb-2", false, spec(rootpolicy.FirecrackerOverlay)); err == nil || !strings.Contains(err.Error(), "names") {
		t.Errorf("staged a file with two names: %v", err)
	}
	// A folder is no disk.
	if err := os.Mkdir(filepath.Join(stage, rootpolicy.FirecrackerRootfs), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepare("sb-2", false, spec(rootpolicy.FirecrackerRootfs)); err == nil {
		t.Error("staged a folder")
	}
	// Not the agent's.
	f.cfg.AgentUID++
	_ = os.Remove(filepath.Join(stage, rootpolicy.FirecrackerRootfs))
	stageFile(t, stage, rootpolicy.FirecrackerRootfs)
	if _, err := f.prepare("sb-2", false, spec(rootpolicy.FirecrackerRootfs)); err == nil || !strings.Contains(err.Error(), "not the agent") {
		t.Errorf("staged a file that is not the agent's: %v", err)
	}
	f.cfg.AgentUID--
	// A kernel the helper may not trust stops the jail.
	f.checkKernel = func(string) error { return errors.New("folder belongs to uid 65531") }
	if _, err := f.prepare("sb-2", false, &rootdpb.PrepareHostRequest{}); err == nil || !strings.Contains(err.Error(), "65531") {
		t.Errorf("a kernel in the agent's folder: %v", err)
	}
	// An id that is not a sandbox ID.
	if _, err := f.prepare("../x", false, &rootdpb.PrepareHostRequest{}); err == nil {
		t.Error("a jail up the tree")
	}
}

// errOf is err as a status error, for its code.
func errOf(err error) error {
	var fe *fileError
	if errors.As(err, &fe) {
		return status.Error(fe.code, fe.msg)
	}
	return err
}

func TestFirecrackerKernelIsRoots(t *testing.T) {
	f, _ := newTestFirecracker(t)
	// A test is not root: its own temp file is refused.
	if err := f.kernelIsRoots(f.cfg.Kernel); err == nil && os.Geteuid() != 0 {
		t.Error("a kernel that is not root's")
	}
	if err := f.kernelIsRoots("/no/such/kernel"); err == nil {
		t.Error("a missing kernel")
	}
}

func TestFirecrackerCommand(t *testing.T) {
	f, _ := newTestFirecracker(t)
	if _, _, err := f.command(context.Background(), "sb-3", &rootdpb.SpawnHostRequest{}); status.Code(errOf(err)) != codes.FailedPrecondition {
		t.Fatalf("a VM with no jail: %v", err)
	}
	if _, err := f.prepare("sb-3", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-3", "root")
	if err := os.WriteFile(filepath.Join(root, "api.socket"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, done, err := f.command(context.Background(), "sb-3", &rootdpb.SpawnHostRequest{})
	if err != nil {
		t.Fatal(err)
	}
	done()
	want := []string{f.cfg.Shim, FirecrackerJailerExecFlag, f.cfg.JailerBinary, "--id", "sb-3", "--exec-file", f.cfg.FirecrackerBinary,
		"--uid", itoa(f.cfg.UID), "--gid", itoa(f.cfg.GID), "--chroot-base-dir", f.cfg.ChrootBase, "--", "--api-sock", "api.socket"}
	if !slices.Equal(cmd.Args, want) || cmd.Path != f.cfg.Shim || len(cmd.Env) != 1 {
		t.Fatalf("command %v env %v, want %v", cmd.Args, cmd.Env, want)
	}
	if _, err := os.Lstat(filepath.Join(root, "api.socket")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an old API socket left: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, rootpolicy.FirecrackerKernel)); err != nil {
		t.Fatalf("no kernel in the chroot the jailer gets: %v", err)
	}
	// A kernel the helper may not trust stops the spawn too.
	f.checkKernel = func(string) error { return errors.New("folder belongs to uid 65531") }
	if _, _, err := f.command(context.Background(), "sb-3", &rootdpb.SpawnHostRequest{}); err == nil || !strings.Contains(err.Error(), "65531") {
		t.Fatalf("a kernel in the agent's folder: %v", err)
	}
	f.checkKernel = func(string) error { return nil }
	if _, _, err := f.command(context.Background(), "../x", &rootdpb.SpawnHostRequest{}); err == nil {
		t.Fatal("a jail up the tree")
	}
	if firecrackerIDOf(cmd) != "sb-3" || firecrackerIDOf(exec.Command("x")) != "" {
		t.Fatal("firecrackerIDOf")
	}
	if _, ok := f.limits(rootpolicy.HostLimits{Pids: 1}); ok || f.socket("sb-3") != "" {
		t.Fatal("a VM takes no limits and serves no socket of the helper's")
	}
}

// TestFirecrackerJailIsMadeFresh: a VM with no process in its group gets
// its chroot made again from nothing, by PrepareHost and by SpawnHost.
// firecracker runs as the jailer's user, who owns the chroot, so it could
// leave a link at the name the jailer copies firecracker to, as root (the
// review of #1423, with the real jailer v1.10.1). Here the jailer's copy
// lands in the new chroot, and the file the link named is left as it was.
// The agent's stage folder is kept, and a running VM's chroot is never
// touched.
func TestFirecrackerJailIsMadeFresh(t *testing.T) {
	f, _ := newTestFirecracker(t)
	if _, err := f.prepare("sb-7", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-7")
	root, stage := filepath.Join(dir, "root"), filepath.Join(dir, "stage")
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("ORIG"), 0o600); err != nil {
		t.Fatal(err)
	}
	// What a VM's firecracker could leave in its chroot.
	left := []string{"firecracker", "dev", "left"}
	leave := func() {
		t.Helper()
		_ = os.Remove(filepath.Join(root, "firecracker"))
		if err := os.Symlink(victim, filepath.Join(root, "firecracker")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(victim), filepath.Join(root, "dev")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "left"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fresh := func(step string) {
		t.Helper()
		for _, name := range left {
			if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: %s is left in the chroot (%v)", step, name, err)
			}
		}
		if _, err := os.Lstat(filepath.Join(root, rootpolicy.FirecrackerKernel)); err != nil {
			t.Errorf("%s: no kernel in the new chroot: %v", step, err)
		}
		// The jailer's first write in its chroot: firecracker, by its name,
		// following whatever is there.
		if err := os.WriteFile(filepath.Join(root, "firecracker"), []byte("ELF"), 0o755); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(victim); err != nil || string(b) != "ORIG" {
			t.Fatalf("%s: the jailer wrote through a link left in the chroot: %q %v", step, b, err)
		}
	}
	stageFile(t, stage, rootpolicy.FirecrackerOverlay)

	leave()
	if _, err := f.prepare("sb-7", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	fresh("PrepareHost")

	// SpawnHost on a VM whose firecracker died, with no PrepareHost first.
	leave()
	if _, done, err := f.command(context.Background(), "sb-7", &rootdpb.SpawnHostRequest{}); err != nil {
		t.Fatal(err)
	} else {
		done()
	}
	fresh("SpawnHost")

	// The agent's disk waited in its stage folder, and moves into the new
	// chroot once firecracker runs.
	spec := &rootdpb.PrepareHostRequest{Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerOverlay}}}
	if _, err := f.prepare("sb-7", true, spec); err != nil {
		t.Fatalf("stage the overlay: %v", err)
	}

	// A running VM's chroot is left as it is.
	leave()
	if _, err := f.prepare("sb-7", true, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(left, rootpolicy.FirecrackerOverlay) {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Errorf("a running VM's %s was removed: %v", name, err)
		}
	}
}

func TestFirecrackerStarted(t *testing.T) {
	f, _ := newTestFirecracker(t)
	if _, err := f.prepare("sb-4", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	if f.started(context.Background(), exec.Command("x")) != nil {
		t.Fatal("a command never started is not waited for")
	}
	cmd := exec.Command("sleep", "5")
	cmd.Args = append(cmd.Args, "--id", "sb-4")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	// No socket within the wait: an error, naming the hosts' log.
	f.cfg.SocketWait = 30 * time.Millisecond
	if err := f.started(context.Background(), cmd); err == nil || !strings.Contains(err.Error(), f.log) {
		t.Fatalf("no socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.cfg.SocketWait = time.Second
	if err := f.started(ctx, cmd); !errors.Is(err, context.Canceled) {
		t.Fatalf("a call that ended: %v", err)
	}
	if runtime.GOOS != "linux" {
		return // a socket is an O_PATH handle away on Linux only
	}
	root := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-4", "root")
	go func() {
		time.Sleep(50 * time.Millisecond)
		ln, err := net.Listen("unix", filepath.Join(root, "api.socket"))
		if err == nil {
			t.Cleanup(func() { _ = ln.Close() })
		}
	}()
	if err := f.started(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(root, "api.socket")); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("API socket %v %v, want 0660", fi, err)
	}
	// Something that is not a socket at the name is not shared.
	if err := os.WriteFile(filepath.Join(root, "vsock.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepare("sb-4", true, &rootdpb.PrepareHostRequest{}); err == nil {
		t.Fatal("shared a file that is not a socket")
	}
}

func TestFirecrackerTeardownAndPresent(t *testing.T) {
	f, _ := newTestFirecracker(t)
	if ids, err := f.present(); err != nil || len(ids) != 0 {
		t.Fatalf("present with no jail: %v %v", ids, err)
	}
	if err := f.teardown("sb-5"); err != nil {
		t.Fatalf("teardown of no jail: %v", err)
	}
	for _, id := range []string{"sb-5", "sb-6"} {
		if _, err := f.prepare(id, false, &rootdpb.PrepareHostRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(f.cfg.ChrootBase, "firecracker", "_not-a-sandbox"), 0o700); err != nil {
		t.Fatal(err)
	}
	if ids, err := f.present(); err != nil || !slices.Equal(ids, []string{"sb-5", "sb-6"}) {
		t.Fatalf("present = %v %v", ids, err)
	}
	stage := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-5", "stage")
	outside := t.TempDir()
	stageFile(t, outside, "keep")
	if err := os.Symlink(outside, filepath.Join(stage, "link")); err != nil {
		t.Fatal(err)
	}
	if err := f.teardown("sb-5"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-5")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jail left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatalf("teardown followed a link out of the jail: %v", err)
	}
	if err := f.teardown("../x"); err == nil {
		t.Fatal("teardown up the tree")
	}
}

func TestMakeFilesystemRefusals(t *testing.T) {
	f, _ := newTestFirecracker(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		req  *rootdpb.MakeFilesystemRequest
	}{
		{"an id up the tree", &rootdpb.MakeFilesystemRequest{Id: "../x", Name: rootpolicy.FirecrackerOverlay}},
		{"the kernel", &rootdpb.MakeFilesystemRequest{Id: "sb-7", Name: rootpolicy.FirecrackerKernel}},
		{"a relative source", &rootdpb.MakeFilesystemRequest{Id: "sb-7", Name: rootpolicy.FirecrackerRootfs, Source: "bundle", SizeMib: 10}},
		{"a source with no size", &rootdpb.MakeFilesystemRequest{Id: "sb-7", Name: rootpolicy.FirecrackerRootfs, Source: "/tmp/b"}},
		{"a source past a disk's cap", &rootdpb.MakeFilesystemRequest{Id: "sb-7", Name: rootpolicy.FirecrackerRootfs, Source: "/tmp/b", SizeMib: 1 << 40}},
		{"a size for an empty one", &rootdpb.MakeFilesystemRequest{Id: "sb-7", Name: rootpolicy.FirecrackerOverlay, SizeMib: 10}},
	} {
		if _, err := f.makeFilesystem(ctx, tc.req); status.Code(errOf(err)) != codes.InvalidArgument {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if runtime.GOOS != "linux" {
		if _, err := f.makeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: "sb-7", Name: rootpolicy.FirecrackerOverlay}); err == nil {
			t.Error("a filesystem in a user namespace off Linux")
		}
	}
}

// fakeTaps records the TAPs made and removed.
type fakeTaps struct {
	mu      sync.Mutex
	ensured []taphost.Slot
	removed []string
	err     error
}

func (f *fakeTaps) Ensure(_ context.Context, s taphost.Slot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, s)
	return f.err
}

func (f *fakeTaps) Remove(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	return f.err
}

// fakeTables is iptables for the guests' NAT and isolation.
type fakeTables struct {
	mu    sync.Mutex
	rules []string
	err   error
}

func (f *fakeTables) Exists(table, chain string, spec ...string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.rules, table+"/"+chain+" "+strings.Join(spec, " ")), f.err
}

func (f *fakeTables) Append(table, chain string, spec ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, table+"/"+chain+" "+strings.Join(spec, " "))
	return f.err
}

func (f *fakeTables) Insert(table, chain string, _ int, spec ...string) error {
	return f.Append(table, chain, spec...)
}

func (f *fakeTables) ChainExists(string, string) (bool, error) { return true, f.err }
func (f *fakeTables) NewChain(string, string) error            { return f.err }

func firecrackerRig(t *testing.T) (*rig, *fakeTaps, *fakeTables) {
	t.Helper()
	taps, tables := &fakeTaps{}, &fakeTables{}
	fc := testFirecrackerConfig(t)
	fc.UID += 1000 // a user of its own: the helper checks it is not the agent's
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(t.TempDir(), "hosts.log"), Firecracker: fc}
		o.HostKernel = newFakeHostKernel()
		o.TapDevices = taps
		o.TapTables = func() (taphost.IsolationBackend, error) { return tables, nil }
		o.TapSysctls = func() error { return nil } // a test may not write /proc/sys
	})
	return r, taps, tables
}

func TestTapCalls(t *testing.T) {
	r, taps, tables := firecrackerRig(t)
	c := hostClient(r)
	ctx := callCtx(t)
	resp, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap3"})
	if err != nil {
		t.Fatal(err)
	}
	want := taphost.Slot{TapName: "fctap3", CIDR: "172.16.0.12/30", HostIP: "172.16.0.13", GuestIP: "172.16.0.14", VsockCID: 6}
	if resp.GetHostIp() != want.HostIP || resp.GetGuestIp() != want.GuestIP || resp.GetCidr() != want.CIDR || resp.GetVsockCid() != 6 ||
		len(taps.ensured) != 1 || taps.ensured[0] != want {
		t.Fatalf("EnsureTap = %v, made %+v", resp, taps.ensured)
	}
	// NAT and isolation went in once, for the helper's own TAP base.
	if _, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap4"}); err != nil {
		t.Fatal(err)
	}
	nat := 0
	for _, rule := range tables.rules {
		if strings.Contains(rule, "MASQUERADE") {
			nat++
		}
		if !strings.Contains(rule, "172.16.0.0/20") && !strings.Contains(rule, "-j "+taphost.IsolationChain) {
			t.Errorf("a rule not for the TAP base: %s", rule)
		}
	}
	if nat != 1 {
		t.Fatalf("NAT rules %d in %v", nat, tables.rules)
	}
	if _, err := c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap3"}); err != nil || !slices.Equal(taps.removed, []string{"fctap3"}) {
		t.Fatalf("RemoveTap: %v, removed %v", err, taps.removed)
	}
	// Names that are not the pool's: refused, nothing made or removed.
	for _, name := range []string{"eth0", "lo", "fctap256", "fctap01", "", "docker0"} {
		_, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: name})
		if reason, refused := rootdpb.RefusalReason(err); !refused || reason != string(rootpolicy.RuleTap) {
			t.Errorf("EnsureTap(%q) = %v", name, err)
		}
		_, err = c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: name})
		if reason, refused := rootdpb.RefusalReason(err); !refused || reason != string(rootpolicy.RuleTap) {
			t.Errorf("RemoveTap(%q) = %v", name, err)
		}
	}
	if len(taps.ensured) != 2 || len(taps.removed) != 1 {
		t.Fatalf("a refused call reached the device: %v %v", taps.ensured, taps.removed)
	}
	taps.err = errors.New("tuntap add: busy")
	if _, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap5"}); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("a device that fails: %v", err)
	}
	if _, err := c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap5"}); err == nil {
		t.Fatal("a remove that fails")
	}
}

func TestTapNetworkFailsClosed(t *testing.T) {
	taps := &fakeTaps{}
	fc := testFirecrackerConfig(t)
	tc := newTapCalls(fc, Options{TapDevices: taps, TapTables: func() (taphost.IsolationBackend, error) {
		return nil, errors.New("no iptables")
	}}, &keyedLocks{}, slog.New(slog.DiscardHandler))
	tc.sysctls = func() error { return nil }
	_, err := tc.ensureTap(context.Background(), &rootdpb.EnsureTapRequest{Name: "fctap0"})
	if status.Code(errOf(err)) != codes.Unavailable || len(taps.ensured) != 0 {
		t.Fatalf("no isolation: %v, made %v", err, taps.ensured)
	}
	tc.sysctls = func() error { return errors.New("read-only /proc") }
	if _, err := tc.ensureTap(context.Background(), &rootdpb.EnsureTapRequest{Name: "fctap0"}); err == nil {
		t.Fatal("no forwarding")
	}
	tables := &fakeTables{err: errors.New("iptables: boom")}
	tc.sysctls = func() error { return nil }
	tc.ipt = func() (taphost.IsolationBackend, error) { return tables, nil }
	if _, err := tc.ensureTap(context.Background(), &rootdpb.EnsureTapRequest{Name: "fctap0"}); err == nil || len(taps.ensured) != 0 {
		t.Fatalf("a NAT that fails: %v", err)
	}
	// Once in, the isolation is put back on its tick.
	tables.err = nil
	tc.reTick = 5 * time.Millisecond
	if _, err := tc.ensureTap(context.Background(), &rootdpb.EnsureTapRequest{Name: "fctap0"}); err != nil {
		t.Fatal(err)
	}
	tables.mu.Lock()
	tables.rules = nil
	tables.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		tables.mu.Lock()
		n := len(tables.rules)
		tables.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolation not put back")
		}
		time.Sleep(5 * time.Millisecond)
	}
	tc.close()
	var none *tapCalls
	none.close()
}

func TestFirecrackerThroughTheHelper(t *testing.T) {
	r, _, _ := firecrackerRig(t)
	c := hostClient(r)
	ctx := callCtx(t)
	v, err := c.Version(ctx, &rootdpb.VersionRequest{})
	if err != nil || !slices.Contains(v.GetHosts(), "firecracker") || !slices.Contains(v.GetFeatures(), rootdpb.FeatureEnsureTap) ||
		!slices.Contains(v.GetFeatures(), rootdpb.FeatureMakeFilesystem) {
		t.Fatalf("Version = %v, %v", v, err)
	}
	// A Firecracker spec on another kind is refused.
	_, err = c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: workerd, Id: "g", Firecracker: &rootdpb.FirecrackerHostSpec{}})
	if status.Code(err) == codes.OK {
		t.Fatal("a Firecracker spec on a workerd host")
	}
	// The real launcher makes the jail; its disks need root to give away.
	_, err = c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: firecracker, Id: "../x"})
	if reason, refused := rootdpb.RefusalReason(err); !refused || reason != string(rootpolicy.RuleHost) {
		t.Fatalf("a jail up the tree: %v", err)
	}
	_, err = c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: "sb-1", Name: "vmlinux"})
	if reason, refused := rootdpb.RefusalReason(err); !refused || reason != string(rootpolicy.RuleHost) {
		t.Fatalf("a filesystem in the kernel: %v", err)
	}
}

func TestFirecrackerCallsOnAHelperWithout(t *testing.T) {
	r := newRig(t, nil)
	c := hostClient(r)
	ctx := callCtx(t)
	if _, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap0"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("EnsureTap: %v", err)
	}
	if _, err := c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap0"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("RemoveTap: %v", err)
	}
	if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: "sb-1", Name: "overlay.ext4"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("MakeFilesystem: %v", err)
	}
}
