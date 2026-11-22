// Package buildnet is rootless BuildKit's own network (plans/security-gaps-
// m1-m4.md §3.5 PR 10b, eng review D14): one named network namespace on the
// sandboxes' bridge, with one address from the sandboxes' range, that the
// rootless buildkit.service joins (systemd NetworkNamespacePath).
//
// Everything a build sends, its base-image pulls and its RUN steps alike,
// leaves through that namespace's veth on the sandboxes' bridge. So the host
// firewall rules every sandbox address gets apply to it unchanged: the egress
// floor (cloud metadata and the operator's floor addresses), the node guard
// (no node ports), and the drop between sandbox ranges. No firewall rule is
// written for it. RUN steps still get a namespace each: rootless BuildKit's
// bridge network, inside RootlessKit's own namespace, whose outbound
// traffic leaves through this one.
//
// It is built by a root oneshot unit (install.sh's aerolvm-build-net
// service, `sandboxd host build-network up`), never by sandboxd: the
// namespace belongs to the build unit, in privilege mode split as in single.
package buildnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
)

// Name is the namespace's name and its CNI container id. It has a dot, so
// no sandbox ID and no netns pool slot (letters, digits, '-' and '_' only,
// models.ValidateSandboxID) can ever take it.
const Name = "aerolvm.build"

// DefaultResolvConf is the resolv.conf the build unit binds over
// /etc/resolv.conf: from inside the namespace a host's loopback stub
// resolver (systemd-resolved's 127.0.0.53) cannot be reached, so it gets
// the host's upstream resolvers, as a sandbox does.
const DefaultResolvConf = "/run/aerolvm-build-net/resolv.conf"

// Host realizes and removes the namespace (*netns.Host).
type Host interface {
	Realize(ctx context.Context, slot netns.Slot) (string, string, error)
	Remove(ctx context.Context, slot netns.Slot) error
	IPv4Addrs(ctx context.Context, slot netns.Slot) ([]string, error)
}

// Config is what Up and Down need.
type Config struct {
	Host Host
	// Subnet is the sandboxes' range, read from the CNI config the host's
	// CNI runner uses (cni.BridgeSubnet).
	Subnet netip.Prefix
	// NetnsRoot is the netns folder; empty is /run/netns.
	NetnsRoot string
	// ResolvConf is where Up writes the namespace's resolv.conf; empty is
	// DefaultResolvConf. HostResolvConf is the host file it is made from;
	// empty is resolvconf.HostPath.
	ResolvConf     string
	HostResolvConf string
	// exists reports whether a path is there; nil is os.Lstat.
	exists func(string) bool
}

// Result is the namespace Up left in place.
type Result struct {
	Path string
	IP   netip.Addr
	// Built is true when Up made the namespace (none was there, or the
	// one there had no address in the sandboxes' range); false when it
	// kept the one already there, which a running buildkitd may be in.
	Built bool
}

// Up makes sure the namespace is there with an address in the sandboxes'
// range, and writes its resolv.conf. A namespace already there with such an
// address is kept as it is: a buildkitd may be running in it. One without
// (the range changed, or a build that failed half way) is removed and
// built again, and the build unit has to restart to join the new one.
func Up(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Host == nil {
		return Result{}, errors.New("build network: a netns host is required")
	}
	subnet := cfg.Subnet.Masked()
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return Result{}, fmt.Errorf("build network: the sandboxes' range %q is not an IPv4 range", cfg.Subnet)
	}
	path := filepath.Join(cfg.netnsRoot(), Name)
	slot := netns.Slot{SandboxID: Name, NetnsPath: path}
	if cfg.present(path) {
		addrs, err := cfg.Host.IPv4Addrs(ctx, slot)
		if ip, ok := inRange(addrs, subnet); err == nil && ok {
			return Result{Path: path, IP: ip}, writeResolvConf(cfg)
		}
		if err := cfg.Host.Remove(ctx, slot); err != nil {
			return Result{}, fmt.Errorf("build network: remove the namespace at %s, which has no address in %s: %w", path, subnet, err)
		}
	}
	got, ipText, err := cfg.Host.Realize(ctx, netns.Slot{SandboxID: Name})
	if err != nil {
		return Result{}, fmt.Errorf("build network: %w", err)
	}
	ip, ok := inRange([]string{ipText}, subnet)
	if !ok {
		rmErr := cfg.Host.Remove(ctx, netns.Slot{SandboxID: Name, NetnsPath: got, ContainerIP: ipText})
		return Result{}, errors.Join(fmt.Errorf("build network: CNI gave the namespace %q, which is not in the sandboxes' range %s", ipText, subnet), rmErr)
	}
	return Result{Path: got, IP: ip, Built: true}, writeResolvConf(cfg)
}

// Down removes the namespace and its address. A namespace not there is
// success.
func Down(ctx context.Context, cfg Config) error {
	if cfg.Host == nil {
		return errors.New("build network: a netns host is required")
	}
	path := filepath.Join(cfg.netnsRoot(), Name)
	if !cfg.present(path) {
		return nil
	}
	slot := netns.Slot{SandboxID: Name, NetnsPath: path}
	var ip string
	if addrs, err := cfg.Host.IPv4Addrs(ctx, slot); err == nil && len(addrs) > 0 {
		ip = addrs[0]
	}
	slot.ContainerIP = ip
	if err := cfg.Host.Remove(ctx, slot); err != nil {
		return fmt.Errorf("build network: %w", err)
	}
	return nil
}

func (c Config) netnsRoot() string {
	if c.NetnsRoot != "" {
		return c.NetnsRoot
	}
	return "/run/netns"
}

func (c Config) present(path string) bool {
	if c.exists != nil {
		return c.exists(path)
	}
	_, err := os.Lstat(path)
	return err == nil
}

// inRange is the first of addrs that is a host address of subnet.
func inRange(addrs []string, subnet netip.Prefix) (netip.Addr, bool) {
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err == nil && ip.Is4() && subnet.Contains(ip) && ip != subnet.Addr() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// writeResolvConf writes the namespace's resolv.conf from the host's,
// whole or not at all (a temp file renamed into place), world-readable:
// the build user reads it through the unit's bind mount.
func writeResolvConf(cfg Config) error {
	src := cfg.HostResolvConf
	if src == "" {
		src = resolvconf.HostPath
	}
	dst := cfg.ResolvConf
	if dst == "" {
		dst = DefaultResolvConf
	}
	body, err := resolvconf.Generate(src)
	if err != nil {
		return fmt.Errorf("build network: resolv.conf: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("build network: resolv.conf folder: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".resolv.conf-")
	if err != nil {
		return fmt.Errorf("build network: resolv.conf: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("build network: resolv.conf: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("build network: resolv.conf: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("build network: resolv.conf: %w", err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("build network: resolv.conf: %w", err)
	}
	return nil
}
