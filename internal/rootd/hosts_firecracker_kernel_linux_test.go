//go:build linux

package rootd

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The Firecracker launcher on the kernel, as root (M1 PR 9b): the jail's
// owners and modes, a disk moved for the jailer's user, the kernel staged
// root's, a filesystem made in a user namespace, a TAP made and removed,
// and the guests' NAT and isolation. None of it needs KVM.

const (
	kAgentUID  = 65531
	kAgentGID  = 990
	kJailerUID = 1500
	kJailerGID = 1501
)

func fcNeedRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the helper's kernel work")
	}
}

// kernelFirecracker is a launcher with the real chown, on a chroot base and
// a kernel folder of root's.
func kernelFirecracker(t *testing.T) *firecrackerHosts {
	t.Helper()
	fcNeedRoot(t)
	base, err := os.MkdirTemp("/", "fcjail")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	kdir := filepath.Join(base, "kernel")
	if err := os.Mkdir(kdir, 0o755); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(kdir, "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &FirecrackerHostsConfig{JailerBinary: "/usr/local/bin/jailer", FirecrackerBinary: "/usr/local/bin/firecracker",
		ChrootBase: base, UID: kJailerUID, GID: kJailerGID, Kernel: kernel, Mkfs4Bin: mkfsPath(t), Shim: "/proc/self/exe",
		AgentUID: kAgentUID, SocketWait: 2 * time.Second, TapBase: "172.31.0.0/24", TapPoolSize: 16}
	return newFirecrackerHosts(c, filepath.Join(base, "hosts.log"), kAgentGID)
}

func mkfsPath(t *testing.T) string {
	for _, p := range []string{"/sbin/mkfs.ext4", "/usr/sbin/mkfs.ext4"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/sbin/mkfs.ext4"
}

func statOwner(t *testing.T, p string) (uid, gid uint32, mode os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid, fi.Mode()
}

func TestFirecrackerJailOnTheKernel(t *testing.T) {
	f := kernelFirecracker(t)
	if _, err := f.prepare("sb-k", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-k")
	for _, tc := range []struct {
		path     string
		uid, gid uint32
		mode     os.FileMode
	}{
		{dir, 0, 0, os.ModeDir | 0o711},
		{dir + "/stage", kAgentUID, kAgentGID, os.ModeDir | 0o700},
		{dir + "/root", kJailerUID, kAgentGID, os.ModeDir | os.ModeSetgid | 0o750},
		{dir + "/root/vmlinux", 0, kJailerGID, 0o640},
	} {
		uid, gid, mode := statOwner(t, tc.path)
		if uid != tc.uid || gid != tc.gid || mode != tc.mode {
			t.Errorf("%s: %d:%d %v, want %d:%d %v", tc.path, uid, gid, mode, tc.uid, tc.gid, tc.mode)
		}
	}
	// The agent builds a disk in the stage folder; the helper moves it in
	// for the jailer's user.
	disk := filepath.Join(dir, "stage", rootpolicy.FirecrackerRootfs)
	if err := os.WriteFile(disk, []byte("ext4"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(disk, kAgentUID, kAgentGID); err != nil {
		t.Fatal(err)
	}
	spec := &rootdpb.PrepareHostRequest{Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerRootfs}}}
	if _, err := f.prepare("sb-k", false, spec); err != nil {
		t.Fatal(err)
	}
	if uid, gid, mode := statOwner(t, dir+"/root/"+rootpolicy.FirecrackerRootfs); uid != kJailerUID || gid != kJailerGID || mode != 0o600 {
		t.Fatalf("disk in the chroot: %d:%d %v", uid, gid, mode)
	}
	// A root file the agent hard-linked into its stage folder is not the
	// agent's: refused, and left as it was.
	secret := filepath.Join(f.cfg.ChrootBase, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(dir, "stage", rootpolicy.FirecrackerOverlay)); err != nil {
		t.Fatal(err)
	}
	spec.Firecracker.Stage = []string{rootpolicy.FirecrackerOverlay}
	if _, err := f.prepare("sb-k", false, spec); err == nil {
		t.Fatal("moved a root file the agent linked")
	}
	if uid, _, mode := statOwner(t, secret); uid != 0 || mode != 0o600 {
		t.Fatalf("the linked file changed: %d %v", uid, mode)
	}
	// The real kernel check: a kernel in a folder others write is refused.
	if err := os.Chmod(filepath.Dir(f.cfg.Kernel), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := f.kernelIsRoots(f.cfg.Kernel); err == nil {
		t.Fatal("a kernel in a folder anyone writes")
	}
	_ = os.Chmod(filepath.Dir(f.cfg.Kernel), 0o755)
	if err := f.kernelIsRoots(f.cfg.Kernel); err != nil {
		t.Fatalf("root's kernel: %v", err)
	}
	// A socket firecracker bound is given to the agent's group.
	ln, err := net.Listen("unix", filepath.Join(dir, "root", "vsock.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := f.prepare("sb-k", true, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, gid, mode := statOwner(t, filepath.Join(dir, "root", "vsock.sock")); gid != kAgentGID || mode.Perm() != 0o660 {
		t.Fatalf("vsock socket: gid %d %v", gid, mode)
	}
	if err := f.teardown("sb-k"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("jail left: %v", err)
	}
}

// TestMakeFilesystemInAUserNamespace: mkfs.ext4 runs as the agent seen as
// root. The image's files are root's, the image is the agent's, and a file
// the agent cannot read stops it.
func TestMakeFilesystemInAUserNamespace(t *testing.T) {
	f := kernelFirecracker(t)
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("needs debugfs (e2fsprogs)")
	}
	if _, err := f.prepare("sb-m", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(f.cfg.ChrootBase, "bundle")
	if err := os.MkdirAll(filepath.Join(src, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "etc", "hostname"), []byte("vm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{src, filepath.Join(src, "etc"), filepath.Join(src, "etc", "hostname")} {
		if err := os.Chown(p, kAgentUID, kAgentGID); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if _, err := f.makeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: "sb-m", Name: rootpolicy.FirecrackerRootfs, Source: src, SizeMib: 16}); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-m", "stage", rootpolicy.FirecrackerRootfs)
	if uid, _, _ := statOwner(t, img); uid != kAgentUID {
		t.Fatalf("image owned by %d, want the agent", uid)
	}
	out, err := exec.Command("debugfs", "-R", "stat /etc/hostname", img).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "User:     0") {
		t.Fatalf("the image's file is not root's: %v\n%s", err, out)
	}
	// An empty filesystem in a file the agent made: its root is root's.
	ov := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-m", "stage", rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, 8<<20); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(ov, kAgentUID, kAgentGID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.makeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: "sb-m", Name: rootpolicy.FirecrackerOverlay}); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command("debugfs", "-R", "stat /", ov).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "User:     0") {
		t.Fatalf("the overlay's root is not root's: %v\n%s", err, out)
	}
	// A folder the agent cannot read: mkfs.ext4 cannot either.
	locked := filepath.Join(f.cfg.ChrootBase, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "shadow"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.makeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: "sb-m", Name: rootpolicy.FirecrackerRootfs, Source: locked, SizeMib: 16}); err == nil {
		t.Fatal("mkfs.ext4 read a folder the agent cannot")
	}
}

// TestTapOnTheKernel: a pool TAP made for the jailer's user, with its
// slot's address and strict reverse path filtering, the guests' NAT and
// isolation in place; removed; a name outside the pool refused.
func TestTapOnTheKernel(t *testing.T) {
	fcNeedRoot(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("needs iptables")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("needs /dev/net/tun")
	}
	c := &FirecrackerHostsConfig{UID: kJailerUID, GID: kJailerGID, TapBase: "172.31.0.0/24", TapPoolSize: 16}
	tc := newTapCalls(c, Options{}, &keyedLocks{}, slog.New(slog.DiscardHandler))
	defer tc.close()
	ctx := context.Background()
	resp, err := tc.ensureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap3"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = tc.removeTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap3"}) }()
	if resp.GetHostIp() != "172.31.0.13" || resp.GetGuestIp() != "172.31.0.14" {
		t.Fatalf("slot %v", resp)
	}
	out, err := exec.Command("ip", "-d", "addr", "show", "fctap3").CombinedOutput()
	owner := "user " + strconv.Itoa(kJailerUID)
	if u, uerr := user.LookupId(strconv.Itoa(kJailerUID)); uerr == nil {
		owner = "user " + u.Username // ip names a uid the node knows
	}
	if err != nil || !strings.Contains(string(out), "172.31.0.13/30") || !strings.Contains(string(out), owner) {
		t.Fatalf("fctap3 (want %q):\n%s %v", owner, out, err)
	}
	if rp, _ := os.ReadFile("/proc/sys/net/ipv4/conf/fctap3/rp_filter"); strings.TrimSpace(string(rp)) != "1" {
		t.Fatalf("rp_filter %q", rp)
	}
	nat, _ := exec.Command("iptables", "-t", "nat", "-S", "POSTROUTING").CombinedOutput()
	iso, _ := exec.Command("iptables", "-t", "mangle", "-S", taphost.IsolationChain).CombinedOutput()
	if !strings.Contains(string(nat), "172.31.0.0/24") || !strings.Contains(string(iso), "172.31.0.0/24") {
		t.Fatalf("NAT:\n%s\nisolation:\n%s", nat, iso)
	}
	if _, err := tc.removeTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap3"}); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "link", "show", "fctap3").CombinedOutput(); err == nil {
		t.Fatalf("fctap3 left:\n%s", out)
	}
	// lo is no pool TAP: refused, and still there.
	if _, err := tc.removeTap(ctx, &rootdpb.RemoveTapRequest{Name: "lo"}); err == nil {
		t.Fatal("removed lo")
	}
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Fatalf("lo: %v", err)
	}
}

// TestJailerShimUmask: the shim gives the jailer, and so firecracker, its
// umask.
func TestJailerShimUmask(t *testing.T) {
	if os.Getenv("AEROL_TEST_JAILER_SHIM") != "" {
		err := RunFirecrackerJailerShim([]string{"/bin/sh", "-c", "umask > " + os.Getenv("AEROL_TEST_JAILER_SHIM")})
		t.Fatalf("the shim returned: %v", err)
	}
	out := filepath.Join(t.TempDir(), "umask")
	cmd := exec.Command(os.Args[0], "-test.run", "^TestJailerShimUmask$")
	cmd.Env = append(os.Environ(), "AEROL_TEST_JAILER_SHIM="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if b, _ := os.ReadFile(out); strings.TrimSpace(string(b)) != "0027" {
		t.Fatalf("umask %q, want 0027", b)
	}
	if err := RunFirecrackerJailerShim([]string{"jailer"}); err == nil {
		t.Fatal("a relative jailer")
	}
}

// TestMakeFilesystemAttrBoundsTheUID: a uid that would not fit an int on a
// 32-bit build maps no user namespace.
func TestMakeFilesystemAttrBoundsTheUID(t *testing.T) {
	if err := makeFilesystemAttr(exec.Command("true"), 1<<31, 990); err == nil {
		t.Fatal("a uid past MaxInt32")
	}
	if err := makeFilesystemAttr(exec.Command("true"), 0, 990); err == nil {
		t.Fatal("root's uid")
	}
	if err := makeFilesystemAttr(exec.Command("true"), 65531, 990); err != nil {
		t.Fatal(err)
	}
}
