//go:build linux && kerneltest

package netns

// Real-kernel reproduction of UC-316 (restore onto a fresh machine), in a
// privileged Linux container:
//
//	go test -tags kerneltest -run KernelRestored ./internal/network/netns/
//
// It drives the production Host (real `ip netns`, real IPv6 sysctls, real
// address read) and, when the image has them, the real bridge + host-local
// CNI plugins, so the rebuilt slot's address comes from host-local exactly
// as on a node.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

// dummyRunner stands in for the CNI plugins where the image has none, with
// what this test needs of them: ADD puts the next address of a fresh range
// on an eth0 inside the netns; DEL takes it away.
type dummyRunner struct {
	mu   sync.Mutex
	next int
}

func (r *dummyRunner) Add(ctx context.Context, netnsPath, _ string) (cni.Result, error) {
	r.mu.Lock()
	r.next++
	ip := fmt.Sprintf("10.88.0.%d", r.next+1)
	r.mu.Unlock()
	name := filepath.Base(netnsPath)
	for _, args := range [][]string{
		{"-n", name, "link", "add", "eth0", "type", "dummy"},
		{"-n", name, "addr", "add", ip + "/16", "dev", "eth0"},
		{"-n", name, "link", "set", "eth0", "up"},
	} {
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			return cni.Result{}, fmt.Errorf("ip %v: %v: %s", args, err, out)
		}
	}
	return cni.Result{IP4: ip}, nil
}

func (r *dummyRunner) Del(ctx context.Context, netnsPath, _ string) error {
	_ = exec.CommandContext(ctx, "ip", "-n", filepath.Base(netnsPath), "link", "del", "eth0").Run()
	return nil
}

// kernelRunner uses the real plugins from AEROL_KT_CNI_DIR (a checkout-
// relative dir works: the test runs in the package dir) or /opt/cni/bin.
func kernelRunner(t *testing.T) cni.Runner {
	t.Helper()
	pluginDir := "/opt/cni/bin"
	if d := os.Getenv("AEROL_KT_CNI_DIR"); d != "" {
		abs, err := filepath.Abs(d)
		if err != nil {
			t.Fatal(err)
		}
		pluginDir = abs
	}
	for _, p := range []string{"bridge", "host-local"} {
		if _, err := os.Stat(filepath.Join(pluginDir, p)); err != nil {
			t.Logf("no CNI plugin %s: using the dummy runner", p)
			return &dummyRunner{}
		}
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "aerolvm.conflist")
	if err := cni.EnsureBridgeConflist(conf, cni.ConflistOptions{Name: "aerolvm-kt", Bridge: "aerolvmkt0", Subnet: "10.88.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	r, err := cni.NewExecRunner(cni.Config{PluginDir: pluginDir, ConfPath: conf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "aerolvmkt0").Run()
		_ = os.RemoveAll("/var/lib/cni/networks/aerolvm-kt")
	})
	return r
}

// netnsIPv4 reads the address a task started in the netns at path would
// come up at, by asking iproute2 from outside: independent of the code
// under test.
func netnsIPv4(t *testing.T, path string) []string {
	t.Helper()
	out, err := exec.Command("ip", "-n", filepath.Base(path), "-4", "-o", "addr", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr in %s: %v: %s", path, err, out)
	}
	var addrs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" && !strings.HasPrefix(f[i+1], "127.") {
				addrs = append(addrs, strings.SplitN(f[i+1], "/", 2)[0])
			}
		}
	}
	return addrs
}

// TestKernelRestoredWarmSlotHoldsItsHandedAddress: a backup's database is
// restored onto a machine whose fresh install already prewarmed
// aerol-netns-0. The backup's warm row for that name records the old
// machine's address. After the boot reconcile, the address a create is
// handed is the one its namespace holds, and that namespace has IPv6 off.
// Before the fix the create was handed 10.88.2.111 for a namespace at
// 10.88.0.2, which the containerd driver refuses once the task is up.
func TestKernelRestoredWarmSlotHoldsItsHandedAddress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	orig := disableIPv6InNetns
	disableIPv6InNetns = hostnet.DisableIPv6InNetns
	t.Cleanup(func() { disableIPv6InNetns = orig })
	ctx := context.Background()
	host := &Host{Runner: kernelRunner(t)}
	t.Cleanup(func() {
		for i := 0; i < 4; i++ {
			_ = exec.Command("ip", "netns", "del", fmt.Sprintf("%s%d", slotNamePrefix, i)).Run()
		}
		_ = exec.Command("ip", "netns", "del", "sb-after-restore").Run()
	})

	// The fresh install's daemon, before the restore.
	fresh := testPool(t, 4)
	if err := fresh.Prewarm(ctx, host, time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("fresh prewarm: %v", err)
	}
	freshPath := filepath.Join(host.netnsRoot(), slotNamePrefix+"0")
	freshAddrs := netnsIPv4(t, freshPath)
	if len(freshAddrs) != 1 {
		t.Fatalf("fresh aerol-netns-0 holds %v", freshAddrs)
	}

	// The backup's database: aerol-netns-0 warm at the old machine's address.
	restored := testPool(t, 4)
	const backupIP = "10.88.2.111"
	slot, err := restored.st.BeginPrewarmContainerNetnsSlot(ctx, time.Unix(2, 0).UTC())
	if err != nil || slot.SlotID != slotNamePrefix+"0" {
		t.Fatalf("restored row: %+v %v", slot, err)
	}
	if err := restored.st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, freshPath, backupIP, time.Unix(2, 0).UTC()); err != nil {
		t.Fatal(err)
	}

	// The restored daemon's boot: reconcile, one refill tick, a create.
	if _, err := restored.Reconcile(ctx, host, nil, nil, time.Unix(3, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := restored.Prewarm(ctx, host, time.Unix(4, 0).UTC()); err != nil {
		t.Fatalf("restored prewarm: %v", err)
	}
	path, ip, err := NewRuntimeHandoff(restored, host).Provision(ctx, "sb-after-restore")
	if err != nil {
		t.Fatal(err)
	}
	holds := netnsIPv4(t, path)
	if len(holds) != 1 || holds[0] != ip {
		t.Fatalf("sandbox came up at %v, not at its prepaid address %q (netns %s; fresh install had %v)", holds, ip, path, freshAddrs)
	}
	t.Logf("handed %s at %s; the fresh install's slot had %v, the backup's row %s", ip, path, freshAddrs, backupIP)
	if hostnet.HostHasIPv6() {
		out, err := exec.Command("ip", "netns", "exec", filepath.Base(path), "cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "1" {
			t.Fatalf("IPv6 in the handed slot: %q %v", out, err)
		}
	}
}
