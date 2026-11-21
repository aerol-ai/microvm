//go:build linux

package rootd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/network/nsbuild"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The helper's own network (network_linux.go): its layout checks, which
// need no rights, and, as root in a privileged container, namespaces read
// back from the real kernel.

// netLayout is a CNI layout under a fresh folder: plugins, a config folder
// and a netns folder.
type netLayout struct {
	cfg     Config
	plugins string
}

func newNetLayout(t *testing.T) netLayout {
	t.Helper()
	base := t.TempDir()
	plugins := filepath.Join(base, "cni", "bin")
	if err := os.MkdirAll(plugins, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"bridge", "host-local"} {
		if err := os.WriteFile(filepath.Join(plugins, p), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testConfig(t)
	cfg.Policy.NetnsDir = filepath.Join(base, "netns")
	cfg.Network = NetworkConfig{PluginDir: plugins, ConfPath: filepath.Join(base, "cni", "net.d", "aerolvm.conflist")}
	return netLayout{cfg: cfg, plugins: plugins}
}

// TestOpenNetwork: the helper writes its CNI config when it is absent,
// with the range the setting names, and reads the bridge and range back.
func TestOpenNetwork(t *testing.T) {
	l := newNetLayout(t)
	l.cfg.Network.Subnet = "10.200.0.0/16"
	h, err := openNetwork(l.cfg)
	if err != nil {
		t.Fatal(err)
	}
	k := h.(*kernelNetwork)
	if k.Subnet() != netip.MustParsePrefix("10.200.0.0/16") || k.bridge != cni.DefaultBridgeName {
		t.Fatalf("subnet %v bridge %q", k.Subnet(), k.bridge)
	}
	st := statOf(t, l.cfg.Network.ConfPath)
	if st.Mode&0o777 != 0o644 || int(st.Uid) != os.Geteuid() {
		t.Fatalf("config mode %o uid %d", st.Mode&0o777, st.Uid)
	}
	if fi, err := os.Stat(l.cfg.Policy.NetnsDir); err != nil || !fi.IsDir() {
		t.Fatalf("netns folder not made: %v", err)
	}
	// A second open reads the config already there, untouched.
	before, _ := os.ReadFile(l.cfg.Network.ConfPath)
	l.cfg.Network.Subnet = ""
	if _, err := openNetwork(l.cfg); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(l.cfg.Network.ConfPath); string(after) != string(before) {
		t.Fatal("the config was rewritten")
	}
	// The host step writes it again if it went, and sets no sysctl it
	// cannot: as a plain user the sysctl write fails, which is the error.
	if err := os.Remove(l.cfg.Network.ConfPath); err != nil {
		t.Fatal(err)
	}
	err = k.EnsureHost()
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(l.cfg.Network.ConfPath); err != nil {
			t.Fatalf("EnsureHost did not write the config: %v", err)
		}
	} else if err == nil {
		t.Log("forwarding sysctls already on and writable here")
	}
}

// TestOpenNetworkRefuses: every place root runs or trusts something must
// be root's alone; anything else stops the network calls, with the reason.
func TestOpenNetworkRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, l *netLayout)
		want   string
	}{
		{"no configuration", func(t *testing.T, l *netLayout) {}, ""},
		{"a plugin missing", func(t *testing.T, l *netLayout) { _ = os.Remove(filepath.Join(l.plugins, "host-local")) }, "host-local"},
		{"a plugin others can write", func(t *testing.T, l *netLayout) {
			chmod(t, filepath.Join(l.plugins, "bridge"), 0o777)
		}, "written by others"},
		{"a plugin that is a link", func(t *testing.T, l *netLayout) {
			p := filepath.Join(l.plugins, "bridge")
			_ = os.Remove(p)
			if err := os.Symlink("/bin/sh", p); err != nil {
				t.Fatal(err)
			}
		}, "not a plain file"},
		{"a plugin folder others can write", func(t *testing.T, l *netLayout) { chmod(t, l.plugins, 0o777) }, "written by others"},
		{"no plugin folder", func(t *testing.T, l *netLayout) { _ = os.RemoveAll(l.plugins) }, "CNI plugin folder"},
		{"a config others can write", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{"cniVersion":"1.0.0","name":"a","plugins":[{"type":"bridge","bridge":"aerolvm0","ipam":{"type":"host-local","subnet":"10.88.0.0/16"}}]}`, 0o666)
		}, "written by others"},
		{"a config folder others can write", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{}`, 0o644)
			chmod(t, filepath.Dir(l.cfg.Network.ConfPath), 0o777)
		}, "CNI config folder"},
		{"a config whose plugin is not the bridge", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{"cniVersion":"1.0.0","name":"a","plugins":[{"type":"macvlan","ipam":{"type":"host-local","subnet":"10.88.0.0/16"}}]}`, 0o644)
		}, "not bridge"},
		{"a config with no IPAM plugin", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{"cniVersion":"1.0.0","name":"a","type":"bridge","bridge":"x0","ipam":{"subnet":"10.88.0.0/16"}}`, 0o644)
		}, "no IPAM plugin"},
		{"a config naming a plugin path", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{"cniVersion":"1.0.0","name":"a","type":"bridge","bridge":"x0","ipam":{"type":"../../bin/sh","subnet":"10.88.0.0/16"}}`, 0o644)
		}, "not a plugin name"},
		{"a config with no range", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{"cniVersion":"1.0.0","name":"a","type":"bridge","ipam":{"type":"host-local"}}`, 0o644)
		}, "no IPv4"},
		{"a config that does not parse", func(t *testing.T, l *netLayout) { writeConf(t, l, `{`, 0o644) }, "cni"},
		{"a range the setting disagrees with", func(t *testing.T, l *netLayout) {
			writeConf(t, l, `{"cniVersion":"1.0.0","name":"a","type":"bridge","ipam":{"type":"host-local","subnet":"10.88.0.0/16"}}`, 0o644)
			l.cfg.Network.Subnet = "10.99.0.0/16"
		}, "SB_CONTAINERD_BRIDGE_SUBNET is 10.99.0.0/16"},
		{"a netns folder others can write", func(t *testing.T, l *netLayout) {
			if err := os.MkdirAll(l.cfg.Policy.NetnsDir, 0o755); err != nil {
				t.Fatal(err)
			}
			chmod(t, l.cfg.Policy.NetnsDir, 0o777)
		}, "netns folder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newNetLayout(t)
			if tc.want == "" {
				l.cfg.Network = NetworkConfig{}
			}
			tc.break_(t, &l)
			_, err := openNetwork(l.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("openNetwork = %v, want %q", err, tc.want)
			}
		})
	}
}

func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func writeConf(t *testing.T, l *netLayout, body string, mode os.FileMode) {
	t.Helper()
	p := l.cfg.Network.ConfPath
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, p, mode)
}

func TestCheckPluginName(t *testing.T) {
	for _, n := range []string{"", ".", "..", "a/b", "x\x00"} {
		if err := checkPlugin(-1, "/opt/cni/bin", n, 0); err == nil || !strings.Contains(err.Error(), "not a plugin name") {
			t.Errorf("%q: %v", n, err)
		}
	}
}

// --- As root: the real kernel ---

func needRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
}

func shortID(t testing.TB) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// vethRunner stands in for the bridge CNI plugin: ADD makes a veth pair,
// moves one end into the namespace as eth0 with an address, and puts the
// other on the bridge; DEL deletes the pair. Without the plugin binaries
// it gives the kernel the same shape the bridge plugin does.
type vethRunner struct {
	bridge string
	next   atomic.Int32
	mu     sync.Mutex
	hosts  map[string]string // container id -> host side
}

func (r *vethRunner) Add(_ context.Context, path, id string) (cni.Result, error) {
	n := r.next.Add(1)
	host := fmt.Sprintf("vh%s%d", id[len(id)-min(len(id), 6):], n)
	if len(host) > 15 {
		host = host[:15]
	}
	peer := fmt.Sprintf("vp%d", n)
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: host}, PeerName: peer}); err != nil {
		return cni.Result{}, err
	}
	br, err := netlink.LinkByName(r.bridge)
	if err != nil {
		return cni.Result{}, err
	}
	hl, _ := netlink.LinkByName(host)
	if err := netlink.LinkSetMaster(hl, br); err != nil {
		return cni.Result{}, err
	}
	_ = netlink.LinkSetUp(hl)
	pl, _ := netlink.LinkByName(peer)
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return cni.Result{}, err
	}
	defer ns.Close()
	if err := netlink.LinkSetNsFd(pl, int(ns)); err != nil {
		return cni.Result{}, err
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return cni.Result{}, err
	}
	defer h.Close()
	in, err := h.LinkByName(peer)
	if err != nil {
		return cni.Result{}, err
	}
	if err := h.LinkSetName(in, "eth0"); err != nil {
		return cni.Result{}, err
	}
	ip := fmt.Sprintf("10.77.%d.%d", n/250, n%250+2)
	addr, _ := netlink.ParseAddr(ip + "/16")
	if err := h.AddrAdd(in, addr); err != nil {
		return cni.Result{}, err
	}
	_ = h.LinkSetUp(in)
	r.mu.Lock()
	r.hosts[id] = host
	r.mu.Unlock()
	return cni.Result{IP4: ip}, nil
}

func (r *vethRunner) Del(_ context.Context, _, id string) error {
	r.mu.Lock()
	host := r.hosts[id]
	delete(r.hosts, id)
	r.mu.Unlock()
	if host == "" {
		return nil
	}
	if l, err := netlink.LinkByName(host); err == nil {
		return netlink.LinkDel(l)
	}
	return nil
}

// countingRunner counts CNI ADDs and passes everything on, the NAT
// teardown included.
type countingRunner struct {
	cni.Runner
	adds atomic.Int32
}

func (c *countingRunner) Add(ctx context.Context, path, id string) (cni.Result, error) {
	c.adds.Add(1)
	return c.Runner.Add(ctx, path, id)
}

func (c *countingRunner) TeardownIPMasq(ctx context.Context, id, ip string) error {
	if t, ok := c.Runner.(cni.IPMasqTeardown); ok {
		return t.TeardownIPMasq(ctx, id, ip)
	}
	return nil
}

// kernelRig is the helper's kernelNetwork on a test netns folder. With
// AEROL_KT_CNI_DIR naming a root-owned folder of the real CNI plugins
// (bridge, host-local; iptables installed), it is the helper's own,
// opened by openNetwork with its own CNI config: the bridge plugin's real
// shape is what the ownership check is held to. Without it, vethRunner
// stands in for CNI on a test bridge.
func kernelRig(t testing.TB) (*kernelNetwork, *countingRunner) {
	t.Helper()
	needRoot(t)
	if dir := os.Getenv("AEROL_KT_CNI_DIR"); dir != "" {
		base := t.TempDir()
		cfg := Config{
			Policy:  testPolicy(),
			Network: NetworkConfig{PluginDir: dir, ConfPath: filepath.Join(base, "net.d", "aerolvm.conflist"), Subnet: "10.79.0.0/16"},
		}
		cfg.Policy.NetnsDir = filepath.Join(base, "netns")
		h, err := openNetwork(cfg)
		if err != nil {
			t.Fatalf("openNetwork with the real plugins: %v", err)
		}
		if err := h.EnsureHost(); err != nil {
			t.Fatal(err)
		}
		k := h.(*kernelNetwork)
		c := &countingRunner{Runner: k.steps.Runner}
		k.steps = k.stepsWith(c)
		t.Cleanup(func() { cleanNetns(k) })
		return k, c
	}
	br := "aerolt" + shortID(t)
	if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: br}}); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(br); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	dir := t.TempDir()
	root := filepath.Join(dir, "netns")
	self, err := netns.GetFromPath("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = self.Close() })
	k := &kernelNetwork{netnsDir: root, subnet: netip.MustParsePrefix("10.77.0.0/16"), bridge: br, self: self, owner: 0}
	c := &countingRunner{Runner: &vethRunner{bridge: br, hosts: map[string]string{}}}
	k.steps = k.stepsWith(c)
	t.Cleanup(func() { cleanNetns(k) })
	return k, c
}

// cleanNetns removes every namespace a test left, then the folder's mount.
func cleanNetns(k *kernelNetwork) {
	entries, _ := os.ReadDir(k.netnsDir)
	for _, e := range entries {
		_ = k.Remove(context.Background(), e.Name(), filepath.Join(k.netnsDir, e.Name()), "")
		_ = nsbuild.DeleteNamed(k.netnsDir, e.Name())
	}
	_ = unix.Unmount(k.netnsDir, unix.MNT_DETACH)
}

// TestKernelInspect: the kernel's own view decides what is a sandbox's.
func TestKernelInspect(t *testing.T) {
	k, _ := kernelRig(t)
	ctx := context.Background()
	path := filepath.Join(k.netnsDir, "sb-1")
	if st, err := k.Inspect(path); err != nil || st.Exists {
		t.Fatalf("missing: %+v %v", st, err)
	}
	ip, err := k.Realize(ctx, "sb-1", path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := k.Inspect(path)
	if err != nil || !st.Exists || st.Foreign != "" || len(st.IPv4) != 1 || st.IPv4[0] != ip {
		t.Fatalf("realized: %+v %v (want %s)", st, err, ip)
	}

	// A namespace with loopback alone: a build not attached yet.
	if err := nsbuild.CreateNamed(k.netnsDir, "fresh"); err != nil {
		t.Fatal(err)
	}
	if st, err := k.Inspect(filepath.Join(k.netnsDir, "fresh")); err != nil || !st.Exists || st.Foreign != "" || len(st.IPv4) != 0 {
		t.Fatalf("fresh: %+v %v", st, err)
	}
	// Someone else's: a dummy link, and a veth not on the helper's bridge.
	foreign := func(name string, add func(h *netlink.Handle) error) string {
		if err := nsbuild.CreateNamed(k.netnsDir, name); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(k.netnsDir, name)
		ns, err := netns.GetFromPath(p)
		if err != nil {
			t.Fatal(err)
		}
		defer ns.Close()
		h, err := netlink.NewHandleAt(ns)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		if err := add(h); err != nil {
			t.Fatal(err)
		}
		return p
	}
	dummy := foreign("cni-dummy", func(h *netlink.Handle) error {
		return h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	})
	other := "ov" + shortID(t)
	offBridge := foreign("cni-veth", func(h *netlink.Handle) error {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: other}, PeerName: other + "p"}); err != nil {
			return err
		}
		t.Cleanup(func() {
			if l, err := netlink.LinkByName(other); err == nil {
				_ = netlink.LinkDel(l)
			}
		})
		p, _ := netlink.LinkByName(other + "p")
		ns, _ := netns.GetFromPath(filepath.Join(k.netnsDir, "cni-veth"))
		defer ns.Close()
		return netlink.LinkSetNsFd(p, int(ns))
	})
	for _, p := range []string{dummy, offBridge} {
		if st, err := k.Inspect(p); err != nil || !st.Exists || st.Foreign == "" || st.IPv4 != nil {
			t.Fatalf("%s: %+v %v", p, st, err)
		}
	}
	// A plain empty file is a build cut short before its bind; a file with
	// content or a link is no namespace of the helper's.
	half := filepath.Join(k.netnsDir, "half")
	if err := os.WriteFile(half, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if st, err := k.Inspect(half); err != nil || !st.Exists || st.Foreign != "" {
		t.Fatalf("half made: %+v %v", st, err)
	}
	if err := os.WriteFile(filepath.Join(k.netnsDir, "full"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if st, _ := k.Inspect(filepath.Join(k.netnsDir, "full")); st.Foreign == "" {
		t.Fatal("a file with content passed as a namespace")
	}
	if err := os.Symlink("/proc/1/ns/net", filepath.Join(k.netnsDir, "link")); err != nil {
		t.Fatal(err)
	}
	if st, _ := k.Inspect(filepath.Join(k.netnsDir, "link")); st.Foreign == "" {
		t.Fatal("a link passed as a namespace")
	}
	if err := k.Remove(ctx, "sb-1", path, ip); err != nil {
		t.Fatal(err)
	}
	if st, _ := k.Inspect(path); st.Exists {
		t.Fatal("still there after Remove")
	}
	if err := k.DisableIPv6(filepath.Join(k.netnsDir, "fresh")); err != nil {
		t.Fatal(err)
	}
}

// TestKernelNetworkCalls: the helper's calls over its socket on the real
// kernel. A repeat answers without a second attach; a foreign namespace
// is refused, reads included.
func TestKernelNetworkCalls(t *testing.T) {
	k, runner := kernelRig(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	first, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil || again.GetContainerIp() != first.GetContainerIp() || runner.adds.Load() != 1 {
		t.Fatalf("repeat = %v, %v after %d adds", again, err, runner.adds.Load())
	}
	addrs, err := c.NetnsAddrs(ctx, &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"})
	if err != nil || !addrs.GetExists() || addrs.GetIpv4()[0] != first.GetContainerIp() {
		t.Fatalf("NetnsAddrs = %v, %v", addrs, err)
	}
	if err := nsbuild.CreateNamed(k.netnsDir, "foreign"); err != nil {
		t.Fatal(err)
	}
	ns, _ := netns.GetFromPath(filepath.Join(k.netnsDir, "foreign"))
	h, _ := netlink.NewHandleAt(ns)
	if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}); err != nil {
		t.Fatal(err)
	}
	h.Close()
	ns.Close()
	_, err = c.RemoveNetns(ctx, &rootdpb.RemoveNetnsRequest{NetnsName: "foreign"})
	wantRefusal(t, r, err, codes.PermissionDenied, ReasonNotSandboxNetns)
	_, err = c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "foreign"})
	wantRefusal(t, r, err, codes.PermissionDenied, ReasonNotSandboxNetns)
	if _, err := os.Stat(filepath.Join(k.netnsDir, "foreign")); err != nil {
		t.Fatalf("the foreign namespace was touched: %v", err)
	}
	if _, err := c.RemoveNetns(ctx, &rootdpb.RemoveNetnsRequest{NetnsName: "sb-1", ContainerIp: first.GetContainerIp()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(k.netnsDir, "sb-1")); !os.IsNotExist(err) {
		t.Fatalf("sb-1 left: %v", err)
	}
}

// --- The 100-parallel-create benchmark on the real kernel (plan §3.7) ---

func percentileOf(d []time.Duration, p float64) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[int(float64(len(s)-1)*p)]
}

// burstOf runs n at once and times each from the moment all were let go.
func burstOf(n int, one func(i int) error) ([]time.Duration, error) {
	out, errs := make([]time.Duration, n), make([]error, n)
	var wg, ready sync.WaitGroup
	start := make(chan struct{})
	var t0 time.Time
	for i := range n {
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			errs[i] = one(i)
			out[i] = time.Since(t0)
		}()
	}
	ready.Wait()
	t0 = time.Now()
	close(start)
	wg.Wait()
	return out, errors.Join(errs...)
}

// BenchmarkKernelCreate100: 100 creates at once, each building a real
// network namespace, attaching it (the real plugins with AEROL_KT_CNI_DIR,
// else vethRunner) and reading its address back, in three ways:
//
//   - single: in process, as netns.Host and the driver's probe do today;
//   - single-inspect: in process, but with the helper's own read
//     (ownership check included), to split the cost of that read from the
//     socket's;
//   - split: through the helper's socket (rootclient's RealizeNetns, then
//     NetnsAddrs).
//
// The order of the three turns each round, so none always runs first.
// Reports p50 and p99 of each, and of the first create on a fresh client
// (the handshake included).
//
//	go test -run '^$' -bench KernelCreate100 -benchtime 9x ./internal/rootd/   (root, privileged)
func BenchmarkKernelCreate100(b *testing.B) {
	const n = 100
	k, _ := kernelRig(b)
	r := newRig(b, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	ctx := context.Background()
	clear := func() {
		entries, _ := os.ReadDir(k.netnsDir)
		for _, e := range entries {
			_ = k.Remove(ctx, e.Name(), filepath.Join(k.netnsDir, e.Name()), "")
		}
	}
	inProcess := func(read func(path string) error) func(i int) func(j int) error {
		return func(i int) func(j int) error {
			return func(j int) error {
				path, _, err := k.steps.Realize(ctx, fmt.Sprintf("s%d-%d", i, j))
				if err != nil {
					return err
				}
				return read(path)
			}
		}
	}
	var first []time.Duration
	modes := []struct {
		name string
		one  func(i int) func(j int) error
		got  []time.Duration
	}{
		{"single", inProcess(func(p string) error { _, err := hostnet.NetnsIPv4Addrs(p); return err }), nil},
		{"single-inspect", inProcess(func(p string) error { _, err := k.Inspect(p); return err }), nil},
		{"split", func(i int) func(j int) error {
			c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, Timeout: 60 * time.Second, HelperUID: uint32(os.Geteuid())})
			b.Cleanup(func() { _ = c.Close() })
			t0 := time.Now()
			if _, _, err := c.RealizeNetns(ctx, fmt.Sprintf("f%d", i)); err != nil {
				b.Fatal(err)
			}
			if _, _, err := c.NetnsAddrs(ctx, fmt.Sprintf("f%d", i)); err != nil {
				b.Fatal(err)
			}
			first = append(first, time.Since(t0))
			return func(j int) error {
				name := fmt.Sprintf("p%d-%d", i, j)
				if _, _, err := c.RealizeNetns(ctx, name); err != nil {
					return err
				}
				_, _, err := c.NetnsAddrs(ctx, name)
				return err
			}
		}, nil},
	}
	for i := 0; i < b.N; i++ {
		for m := range modes {
			mode := &modes[(i+m)%len(modes)]
			d, err := burstOf(n, mode.one(i))
			if err != nil {
				b.Fatal(err)
			}
			mode.got = append(mode.got, d...)
			clear()
		}
	}
	for _, m := range modes {
		b.ReportMetric(float64(percentileOf(m.got, 0.5).Microseconds()), m.name+"-p50-us")
		b.ReportMetric(float64(percentileOf(m.got, 0.99).Microseconds()), m.name+"-p99-us")
	}
	b.ReportMetric(float64(percentileOf(first, 0.5).Microseconds()), "first-p50-us")
}

// BenchmarkKernelCreateOne is one create with nothing else running: the
// boot-path cost per create (plan §3.7) of each mode, on the real kernel.
func BenchmarkKernelCreateOne(b *testing.B) {
	k, _ := kernelRig(b)
	r := newRig(b, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	ctx := context.Background()
	c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, Timeout: 30 * time.Second, HelperUID: uint32(os.Geteuid())})
	b.Cleanup(func() { _ = c.Close() })
	for _, mode := range []string{"single", "split"} {
		b.Run(mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				name := fmt.Sprintf("%s-%d", mode, i)
				if mode == "single" {
					path, _, err := k.steps.Realize(ctx, name)
					if err == nil {
						_, err = hostnet.NetnsIPv4Addrs(path)
					}
					if err != nil {
						b.Fatal(err)
					}
				} else {
					if _, _, err := c.RealizeNetns(ctx, name); err != nil {
						b.Fatal(err)
					}
					if _, _, err := c.NetnsAddrs(ctx, name); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				_ = k.Remove(ctx, name, filepath.Join(k.netnsDir, name), "")
				b.StartTimer()
			}
		})
	}
}

// TestFallbackTunnel: the kernel's own per-namespace tunnel devices, by
// name and kind, down, are no one's link; anything else by those names is.
func TestFallbackTunnel(t *testing.T) {
	for _, tc := range []struct {
		link netlink.Link
		want bool
	}{
		{&netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: "tunl0"}}, true},
		{&netlink.Sittun{LinkAttrs: netlink.LinkAttrs{Name: "sit0"}}, true},
		{&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "gre0"}, Local: net.IPv4zero}, true},
		{&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "gre0"}}, true}, // no address: reads as ip6gre
		{&netlink.Vti{LinkAttrs: netlink.LinkAttrs{Name: "ip_vti0"}}, true},
		{&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: "erspan0"}, LinkType: "erspan"}, true},
		{&netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: "tunl0", Flags: net.FlagUp}}, false},
		{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tunl0"}}, false},
		{&netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: "tunl1"}}, false},
		{&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sit0"}}, false},
	} {
		if got := fallbackTunnel(tc.link); got != tc.want {
			t.Errorf("%s (%s, flags %v) = %v", tc.link.Attrs().Name, tc.link.Type(), tc.link.Attrs().Flags, got)
		}
	}
}

// TestNetworkCallsNeedTheAgentsUID (broken-agent suite): a process that is
// not the agent never reaches a network call; the connection is refused at
// the peer check and nothing reaches the kernel.
func TestNetworkCallsNeedTheAgentsUID(t *testing.T) {
	fn := newFakeNet()
	r := newRig(t, func(c *Config, o *Options) {
		realPeer(uint32(os.Getuid())+1, "")(c, o)
		o.Network = fn
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	_, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	wantCode(t, err, codes.Unavailable)
	_, err = c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "sb-1"})
	wantCode(t, err, codes.Unavailable)
	if got := fn.recorded(); len(got) != 0 {
		t.Fatalf("a caller with another uid reached the kernel: %v", got)
	}
	if refs := r.refused(); len(refs) == 0 || refs[0].Reason != ReasonPeer {
		t.Fatalf("refusals %+v", refs)
	}
}

// TestInspectFiles: what is in the netns folder, read without rights: a
// missing name, a build cut short before its bind (an empty plain file),
// and things that are no namespace of the helper's (a link, a file with
// content, a folder). The steps that need rights fail plainly without
// them.
func TestInspectFiles(t *testing.T) {
	dir := t.TempDir()
	k := &kernelNetwork{netnsDir: dir, owner: uint32(os.Geteuid()), subnet: netip.MustParsePrefix("10.77.0.0/16")}
	k.steps = k.stepsWith(&countingRunner{Runner: cni.NewFakeRunner()})
	if st, err := k.Inspect(filepath.Join(dir, "none")); err != nil || st.Exists {
		t.Fatalf("missing: %+v %v", st, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "half"), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if st, err := k.Inspect(filepath.Join(dir, "half")); err != nil || !st.Exists || st.Foreign != "" {
		t.Fatalf("half made: %+v %v", st, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "full"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/1/ns/net", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"full", "link", "folder"} {
		if st, err := k.Inspect(filepath.Join(dir, n)); err != nil || !st.Exists || st.Foreign == "" {
			t.Fatalf("%s: %+v %v", n, st, err)
		}
	}
	if os.Geteuid() == 0 {
		return
	}
	if _, err := k.Realize(context.Background(), "sb-1", filepath.Join(dir, "sb-1")); err == nil {
		t.Fatal("an unprivileged build succeeded")
	}
	if err := k.DisableIPv6(filepath.Join(dir, "half")); err == nil {
		t.Fatal("IPv6 off in a plain file")
	}
	if err := k.Remove(context.Background(), "half", filepath.Join(dir, "half"), ""); err != nil {
		t.Fatalf("Remove of a half-made file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "half")); !os.IsNotExist(err) {
		t.Fatalf("half-made file left: %v", err)
	}
}
