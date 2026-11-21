//go:build linux

package rootd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/network/nsbuild"
	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// nsfsMagic is the filesystem type of a bound network namespace.
const nsfsMagic = 0x6e736673

// kernelNetwork is the helper's NetworkHost: nsbuild's steps with the
// helper's own CNI runner, and namespaces read back from the kernel.
type kernelNetwork struct {
	netnsDir string
	subnet   netip.Prefix
	bridge   string
	steps    nsbuild.Steps
	// self is the helper's own network namespace, where the bridge and
	// every sandbox veth's peer live.
	self netns.NsHandle
	// conf is how to write the CNI config when it is absent.
	confDir, confName string
	conflist          cni.ConflistOptions
	owner             uint32
}

// openNetwork checks the helper's network layout and opens it. Every
// folder root acts in must be root's alone, the whole way down, or the
// agent could place what root then runs or trusts:
//
//   - the netns folder (made where missing): a name in it is what root
//     left there, never a link the agent put to another namespace;
//   - the CNI plugin folder and the plugins the config names (bridge and
//     its IPAM plugin): root runs them, so each must be root's file that no
//     one else can write;
//   - the CNI config's folder and the config: the config names the plugin
//     root runs. The helper writes it when it is absent, with the range
//     SB_CONTAINERD_BRIDGE_SUBNET names (or the default); one already there
//     must hand out that range when the setting names one, and its plugin
//     must be the bridge plugin.
func openNetwork(cfg Config) (NetworkHost, error) {
	n := cfg.Network
	if !n.configured() {
		return nil, errors.New("no CNI configuration")
	}
	owner := uint32(os.Geteuid())
	k := &kernelNetwork{netnsDir: cfg.Policy.NetnsDir, confDir: filepath.Dir(n.ConfPath), confName: filepath.Base(n.ConfPath), owner: owner}
	fd, err := openFolder(k.netnsDir)
	if err != nil {
		return nil, fmt.Errorf("netns folder %s: %w", k.netnsDir, err)
	}
	_ = unix.Close(fd)
	pfd, err := walkFolder(n.PluginDir, false, func(at string, st *unix.Stat_t, last bool) error {
		return rootfolder.CheckFolder(at, uint32(st.Mode), st.Uid, owner, !last)
	})
	if err != nil {
		return nil, fmt.Errorf("CNI plugin folder %s: %w", n.PluginDir, err)
	}
	defer func() { _ = unix.Close(pfd) }()

	subnet := n.Subnet
	if subnet == "" {
		subnet = cni.DefaultBridgeSubnet
	}
	k.conflist = cni.ConflistOptions{Name: "aerolvm", Bridge: cni.DefaultBridgeName, Subnet: subnet, MTU: cni.UplinkMTU()}
	if err := k.ensureConflist(); err != nil {
		return nil, err
	}
	if k.bridge, err = cni.BridgeName(n.ConfPath); err != nil {
		return nil, err
	}
	if k.subnet, err = cni.BridgeSubnet(n.ConfPath); err != nil {
		return nil, err
	}
	if n.Subnet != "" && k.subnet.String() != n.Subnet {
		return nil, fmt.Errorf("SB_CONTAINERD_BRIDGE_SUBNET is %s, but the CNI config at %s hands out %s; "+
			"the helper never rewrites that file, since sandboxes may hold its addresses", n.Subnet, n.ConfPath, k.subnet)
	}
	ipam, err := ipamType(n.ConfPath)
	if err != nil {
		return nil, err
	}
	for _, plugin := range []string{"bridge", ipam} {
		if err := checkPlugin(pfd, n.PluginDir, plugin, owner); err != nil {
			return nil, err
		}
	}
	runner, err := cni.NewExecRunner(cni.Config{PluginDir: n.PluginDir, ConfPath: n.ConfPath})
	if err != nil {
		return nil, err
	}
	if k.self, err = netns.GetFromPath("/proc/self/ns/net"); err != nil {
		return nil, fmt.Errorf("the helper's own network namespace: %w", err)
	}
	k.steps = k.stepsWith(runner)
	return k, nil
}

// stepsWith are nsbuild's steps in the helper's netns folder.
func (k *kernelNetwork) stepsWith(runner cni.Runner) nsbuild.Steps {
	root := k.netnsDir
	return nsbuild.Steps{
		Runner: runner, Root: root,
		Create:      func(_ context.Context, name string) error { return nsbuild.CreateNamed(root, name) },
		LoopbackUp:  func(_ context.Context, name string) error { return nsbuild.LoopbackUp(filepath.Join(root, name)) },
		Delete:      func(_ context.Context, name string) error { return nsbuild.DeleteNamed(root, name) },
		DisableIPv6: hostnet.DisableIPv6InNetns,
	}
}

// ensureConflist writes the CNI config when it is absent, through its
// checked folder, and checks the one there: root's file, which no one else
// can write.
func (k *kernelNetwork) ensureConflist() error {
	dfd, err := openFolder(k.confDir)
	if err != nil {
		return fmt.Errorf("CNI config folder %s: %w", k.confDir, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	switch err := unix.Fstatat(dfd, k.confName, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
		body, err := cni.RenderBridgeConflist(k.conflist)
		if err != nil {
			return err
		}
		return writeNew(dfd, k.confName, body)
	case err != nil:
		return fmt.Errorf("CNI config %s: %w", filepath.Join(k.confDir, k.confName), err)
	}
	return checkRootFile(&st, filepath.Join(k.confDir, k.confName), k.owner)
}

// writeNew writes body to name in dfd through a temporary name, 0644.
func writeNew(dfd int, name string, body []byte) error {
	tmp, err := tmpName(name)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(body)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// checkRootFile: a plain file of root's (or the test's own user), which no
// one else can write.
func checkRootFile(st *unix.Stat_t, at string, owner uint32) error {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%s is not a plain file (mode %o)", at, st.Mode)
	case st.Uid != 0 && st.Uid != owner:
		return fmt.Errorf("%s belongs to uid %d", at, st.Uid)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%s can be written by others (mode %o)", at, st.Mode&0o7777)
	}
	return nil
}

// checkPlugin checks a CNI plugin the helper will run: a name, not a path,
// and root's plain file in the checked plugin folder.
func checkPlugin(pfd int, dir, name string, owner uint32) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("CNI plugin %q is not a plugin name", name)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("CNI plugin %s: %w", filepath.Join(dir, name), err)
	}
	return checkRootFile(&st, filepath.Join(dir, name), owner)
}

// ipamType is the IPAM plugin the config's bridge plugin runs.
func ipamType(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read CNI config %s: %w", path, err)
	}
	type plugin struct {
		IPAM struct {
			Type string `json:"type"`
		} `json:"ipam"`
	}
	var conf struct {
		plugin
		Plugins []plugin `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &conf); err != nil {
		return "", fmt.Errorf("parse CNI config %s: %w", path, err)
	}
	p := conf.plugin
	if len(conf.Plugins) > 0 {
		p = conf.Plugins[0]
	}
	if p.IPAM.Type == "" {
		return "", fmt.Errorf("CNI config %s names no IPAM plugin", path)
	}
	return p.IPAM.Type, nil
}

func (k *kernelNetwork) Subnet() netip.Prefix { return k.subnet }

func (k *kernelNetwork) EnsureHost() error {
	if err := hostnet.EnsureForwardingSysctls(); err != nil {
		return err
	}
	return k.ensureConflist()
}

// Inspect reads the namespace at path without following a link: whether it
// is there, whether everything in it is the helper's, and its addresses.
//
// The helper's own are a namespace with loopback alone (a build not yet
// attached), veths whose peers are on the helper's bridge in the helper's
// namespace (an attached sandbox, gVisor's included: runsc takes the
// address but leaves the link), and an empty plain file (a build cut short
// before the bind). Anything else in the netns folder is someone else's.
func (k *kernelNetwork) Inspect(path string) (NetnsState, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return NetnsState{}, nil
	case errors.Is(err, unix.ELOOP):
		return NetnsState{Exists: true, Foreign: "a link, not a namespace"}, nil
	case err != nil:
		return NetnsState{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return NetnsState{}, err
	}
	if fs.Type != nsfsMagic {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return NetnsState{}, err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Size == 0 && (st.Uid == 0 || st.Uid == k.owner) {
			return NetnsState{Exists: true}, nil
		}
		return NetnsState{Exists: true, Foreign: "not a namespace"}, nil
	}
	h, err := netlink.NewHandleAt(netns.NsHandle(fd), unix.NETLINK_ROUTE)
	if err != nil {
		return NetnsState{}, err
	}
	defer h.Close()
	links, err := h.LinkList()
	if err != nil {
		return NetnsState{}, err
	}
	st := NetnsState{Exists: true}
	hostID, bridge := -1, -1
	for _, l := range links {
		a := l.Attrs()
		if a.Flags&net.FlagLoopback != 0 || fallbackTunnel(l) {
			continue
		}
		if bridge < 0 {
			// Looked up once, and only for a namespace with links: a fresh
			// one has loopback alone.
			if hostID, err = h.GetNetNsIdByFd(int(k.self)); err != nil {
				return NetnsState{}, err
			}
			if br, err := netlink.LinkByName(k.bridge); err == nil {
				bridge = br.Attrs().Index
			}
		}
		if !ownVeth(l, hostID, bridge) {
			st.Foreign = "link " + a.Name
			st.IPv4 = nil
			return st, nil
		}
		addrs, err := h.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return NetnsState{}, err
		}
		for _, ad := range addrs {
			if ip := ad.IP.To4(); ip != nil && !ip.IsLoopback() {
				st.IPv4 = append(st.IPv4, ip.String())
			}
		}
	}
	return st, nil
}

// fallbackTunnels are the devices the kernel makes in every new network
// namespace while their tunnel module is loaded (unless
// net.core.fb_tunnels_only_for_init_net is set), by name and kind: a fresh
// sandbox namespace has them beside loopback, down and with no address.
// The GRE and VTI kinds are read from the device's addresses (netlink's
// Type), which a fallback device may not report, so either family passes.
var fallbackTunnels = map[string][]string{
	"tunl0":      {"ipip"},
	"sit0":       {"sit"},
	"ip6tnl0":    {"ip6tnl"},
	"gre0":       {"gre", "ip6gre"},
	"gretap0":    {"gretap", "ip6gretap"},
	"erspan0":    {"erspan"},
	"ip6gre0":    {"ip6gre", "gre"},
	"ip6gretap0": {"ip6gretap", "gretap"},
	"ip_vti0":    {"vti", "vti6"},
	"ip6_vti0":   {"vti6", "vti"},
}

// fallbackTunnel: one of those, down.
func fallbackTunnel(l netlink.Link) bool {
	a := l.Attrs()
	return a.Flags&net.FlagUp == 0 && slices.Contains(fallbackTunnels[a.Name], l.Type())
}

// ownVeth: a veth whose peer is in the helper's namespace (hostID, as the
// sandbox's namespace numbers it) and sits on the helper's bridge.
func ownVeth(l netlink.Link, hostID, bridge int) bool {
	a := l.Attrs()
	if l.Type() != "veth" || hostID < 0 || bridge < 0 || a.NetNsID != hostID {
		return false
	}
	peer, err := netlink.LinkByIndex(a.ParentIndex)
	return err == nil && peer.Type() == "veth" && peer.Attrs().MasterIndex == bridge
}

func (k *kernelNetwork) Realize(ctx context.Context, name, path string) (string, error) {
	got, ip, err := k.steps.Realize(ctx, name)
	if err == nil && got != path {
		err = fmt.Errorf("built at %s, not %s", got, path)
	}
	return ip, err
}

func (k *kernelNetwork) Remove(ctx context.Context, name, path, ip string) error {
	return k.steps.Remove(ctx, name, path, ip)
}

func (k *kernelNetwork) DisableIPv6(path string) error { return hostnet.DisableIPv6InNetns(path) }
