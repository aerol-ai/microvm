//go:build linux && kerneltest

package netns

// Real-kernel check and cost of the in-process namespace steps
// (host_linux.go), in a privileged Linux container with iproute2 and, for
// the full build, the bridge + host-local CNI plugins (AEROL_KT_CNI_DIR or
// /opt/cni/bin):
//
//	go test -tags kerneltest -run KernelHost -bench KernelNetns ./internal/network/netns/

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

func nsInode(t testing.TB, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Ino
}

func ipOut(t testing.TB, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
	return string(out)
}

// sharedMount reports whether the topmost mount at dir propagates (a
// "shared:N" tag in mountinfo), as `ip netns add` leaves /run/netns.
func sharedMount(t testing.TB, dir string) bool {
	t.Helper()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	shared := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || fields[4] != dir {
			continue
		}
		shared = false
		for _, opt := range fields[6:] {
			if opt == "-" {
				break
			}
			if strings.HasPrefix(opt, "shared:") {
				shared = true
			}
		}
	}
	return shared
}

// TestKernelHostNetnsLifecycle: the production Host makes, sets up and
// removes a namespace the way `ip netns` does. iproute2 lists it and sees
// lo up, /run/netns is a shared mount, the caller's thread never leaves the
// host namespace, every step is idempotent, and `ip` and the Host each
// remove what the other made.
func TestKernelHostNetnsLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	ctx := context.Background()
	h := &Host{} // the production root, /run/netns, which `ip netns` uses too
	name := fmt.Sprintf("l5-kt-%d", os.Getpid())
	path := filepath.Join(h.netnsRoot(), name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hostNS := nsInode(t, "/proc/thread-self/ns/net")

	if err := h.createNetns(ctx, name); err != nil {
		t.Fatalf("create: %v", err)
	}
	ino := nsInode(t, path)
	if ino == hostNS {
		t.Fatal("the netns file is bound to the host namespace")
	}
	if got := nsInode(t, "/proc/thread-self/ns/net"); got != hostNS {
		t.Fatal("create moved the calling thread out of the host namespace")
	}
	if err := h.createNetns(ctx, name); err != nil {
		t.Fatalf("second create: %v", err)
	}
	if nsInode(t, path) != ino {
		t.Fatal("second create replaced the namespace")
	}
	if out := ipOut(t, "netns", "list"); !strings.Contains(out, name) {
		t.Fatalf("ip netns list does not show %s:\n%s", name, out)
	}
	if !sharedMount(t, h.netnsRoot()) {
		t.Fatalf("%s is not a shared mount", h.netnsRoot())
	}

	if out := ipOut(t, "-n", name, "link", "show", "lo"); strings.Contains(out, ",UP") {
		t.Fatalf("lo is up before bringLoopbackUp: %s", out)
	}
	for i := 0; i < 2; i++ {
		if err := h.bringLoopbackUp(ctx, name); err != nil {
			t.Fatalf("loopback up %d: %v", i+1, err)
		}
	}
	if out := ipOut(t, "-n", name, "link", "show", "lo"); !strings.Contains(out, ",UP") {
		t.Fatalf("lo is not up: %s", out)
	}

	for i := 0; i < 2; i++ {
		if err := h.deleteNetns(ctx, name); err != nil {
			t.Fatalf("delete %d: %v", i+1, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("netns file still there: %v", err)
	}
	if out := ipOut(t, "netns", "list"); strings.Contains(out, name) {
		t.Fatalf("ip netns list still shows %s:\n%s", name, out)
	}

	// Same shape on disk as iproute2's, both ways.
	ipOut(t, "netns", "add", name)
	if err := h.bringLoopbackUp(ctx, name); err != nil {
		t.Fatalf("loopback in an `ip netns add` namespace: %v", err)
	}
	if err := h.deleteNetns(ctx, name); err != nil {
		t.Fatalf("delete of an `ip netns add` namespace: %v", err)
	}
	if err := h.createNetns(ctx, name); err != nil {
		t.Fatal(err)
	}
	ipOut(t, "netns", "del", name)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ip netns del left the Host's namespace file: %v", err)
	}
}

// failingAddRunner fails every CNI ADD, after the namespace exists.
type failingAddRunner struct{ cni.Runner }

func (failingAddRunner) Add(context.Context, string, string) (cni.Result, error) {
	return cni.Result{}, errors.New("cni add: no address left")
}

// TestKernelHostFailedRefillLeavesNoNamespace: a prewarm whose CNI ADD
// fails leaves no namespace on the node and its slot free: the real-kernel
// half of TestFailedRefillOnClaimLeavesNoHalfMadeNamespace.
func TestKernelHostFailedRefillLeavesNoNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	ctx := context.Background()
	host := &Host{Runner: failingAddRunner{Runner: cni.NewFakeRunner()}}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", slotNamePrefix+"0").Run() })
	p := testPool(t, 1)
	if err := p.Prewarm(ctx, host, timeNow()); err == nil {
		t.Fatal("prewarm with a failing CNI ADD: want an error")
	}
	if _, err := os.Stat(filepath.Join(host.netnsRoot(), slotNamePrefix+"0")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed prewarm left its namespace: %v", err)
	}
	stats, err := p.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Free != 1 {
		t.Fatalf("slot not free after a failed prewarm: %+v", stats)
	}
}

func runIP(args ...string) error {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %v: %v: %s", args, err, out)
	}
	return nil
}

// BenchmarkKernelNetnsBuild prices the namespace steps of one build, the
// way main ran them (two `ip` processes to create and set lo up, one to
// delete) and in-process. Each sub-benchmark times only its own step; the
// other one runs with the timer stopped.
func BenchmarkKernelNetnsBuild(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root in a privileged container")
	}
	ctx := context.Background()
	h := &Host{}
	type steps struct{ create, del func(name string) error }
	modes := []struct {
		name string
		steps
	}{
		{"ip", steps{
			create: func(name string) error {
				if err := runIP("netns", "add", name); err != nil {
					return err
				}
				return runIP("-n", name, "link", "set", "lo", "up")
			},
			del: func(name string) error { return runIP("netns", "del", name) },
		}},
		{"in_process", steps{
			create: func(name string) error {
				if err := h.createNetns(ctx, name); err != nil {
					return err
				}
				return h.bringLoopbackUp(ctx, name)
			},
			del: func(name string) error { return h.deleteNetns(ctx, name) },
		}},
	}
	for _, m := range modes {
		b.Run(m.name+"/create+lo", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				name := fmt.Sprintf("l5-bench-%d", i)
				if err := m.create(name); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if err := m.del(name); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
		b.Run(m.name+"/delete", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				name := fmt.Sprintf("l5-bench-%d", i)
				b.StopTimer()
				if err := m.create(name); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if err := m.del(name); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkKernelNetnsRealize prices one whole namespace build, the work a
// create does inline on a warm queue miss: create, lo up, IPv6 off twice
// and CNI ADD (the real bridge + host-local plugins when the image has
// them). Remove runs with the timer stopped.
func BenchmarkKernelNetnsRealize(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root in a privileged container")
	}
	orig := disableIPv6InNetns
	disableIPv6InNetns = hostnet.DisableIPv6InNetns
	b.Cleanup(func() { disableIPv6InNetns = orig })
	ctx := context.Background()
	host := &Host{Runner: kernelRunner(b)}
	for i := 0; i < b.N; i++ {
		// Not aerol-netns-<i>: the restore test leaves that id's CNI NAT
		// chain behind, and a second ADD/DEL of it fails in iptables.
		id := fmt.Sprintf("l5-realize-%d", i)
		path, ip, err := host.Realize(ctx, Slot{SlotID: id, SandboxID: id})
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := host.Remove(ctx, Slot{SlotID: id, SandboxID: id, NetnsPath: path, ContainerIP: ip}); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// The thread that made a namespace is back in its own before it is
// unlocked (bindNewNetnsOnThread reports home).
func TestKernelHostBindReturnsTheThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bound")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(path, unix.MNT_DETACH) })
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before := nsInode(t, "/proc/thread-self/ns/net")
	home, err := bindNewNetnsOnThread(path)
	if err != nil || !home {
		t.Fatalf("bind = home %v, %v", home, err)
	}
	if got := nsInode(t, "/proc/thread-self/ns/net"); got != before {
		t.Fatal("the thread that made the namespace was left in it")
	}
	if nsInode(t, path) == before {
		t.Fatal("the file is bound to the thread's own namespace, not a new one")
	}
}

// Go never ends the main thread: a locked goroutine that ended there,
// inside a new namespace, wedged it there for good, and /proc/<pid>/ns/net
// (the main thread's) then named a sandbox's network. With one P, the
// goroutine a create starts runs on the thread that started it, which here
// is often the main thread; many creates must leave every thread of the
// process in the namespace it started in.
func TestKernelHostCreatesLeaveEveryThreadHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	host := nsInode(t, "/proc/self/ns/net")
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	root := t.TempDir()
	// Cleanups run last first: the root's mount goes after its namespaces.
	t.Cleanup(func() { _ = unix.Unmount(root, unix.MNT_DETACH) })
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("home-%d", i)
		if err := createNamedNetns(root, name); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		t.Cleanup(func() { _ = deleteNamedNetns(root, name) })
	}
	tasks, err := filepath.Glob("/proc/self/task/*/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range tasks {
		var st unix.Stat_t
		if unix.Stat(p, &st) != nil {
			continue // the thread ended meanwhile
		}
		if st.Ino != host {
			t.Fatalf("%s is in another namespace after the creates (the main thread is task %d)", p, os.Getpid())
		}
	}
}
