package buildnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Build steps' own network (review of #1398, F4). RootlessKit gives
// buildkitd a namespace of its own for build steps (--detach-netns), whose
// traffic leaves through RootlessKit's user-space network stack in the
// aerolvm.build namespace. Inside it, each step gets its own point-to-point
// link (the CNI ptp plugin, steps.conflist written by install.sh), never a
// shared bridge: no step can send a frame to another, so none can spoof
// another's address on a shared segment. What a step could still reach
// through that namespace's routing is closed by the step guard below, which
// runs inside RootlessKit before buildkitd starts:
//   - another step (its address in StepRange);
//   - the namespace itself (anything listening there);
//   - RootlessKit's own network (UplinkRange: its gateway and DNS);
//   - the aerolvm.build namespace's own addresses, where buildkitd and
//     RootlessKit run;
//   - an address a step does not own (strict reverse-path filtering);
//   - and IPv6, turned off on every link of the namespace: the drop rules
//     are IPv4, and a step reached a listener there over IPv6 link-local
//     (review of #1398).
//
// Everything else leaves through aerolvm.build onto the sandboxes' bridge,
// where the host firewall's sandbox rules apply.

const (
	// StepRange is the addresses build steps get (steps.conflist), and
	// UplinkRange RootlessKit's own network (its --cidr). Both come from
	// the block set aside for benchmark tests (RFC 2544), which no real
	// destination a build reaches uses: a step cannot reach an address in
	// either range.
	StepRange   = "198.18.0.0/16"
	UplinkRange = "198.19.0.0/24"
)

// GuardConfig is what ApplyStepGuard needs.
type GuardConfig struct {
	// Netns is the steps' namespace: RootlessKit's detached one,
	// $ROOTLESSKIT_STATE_DIR/netns, open only inside RootlessKit's mount
	// namespace.
	Netns string
	// Steps and Uplink are StepRange and UplinkRange.
	Steps, Uplink netip.Prefix
	// Own are the addresses of the namespace buildkitd runs in
	// (aerolvm.build); OwnAddrs reads them.
	Own []netip.Addr
	// IPv6 is whether the kernel has IPv6 to turn off
	// (hostnet.HostHasIPv6); without it there is nothing to turn off.
	IPv6 bool
	// run runs one command; nil is exec.
	run func(ctx context.Context, name string, args ...string) error
}

// StepGuardCommands are the commands ApplyStepGuard runs, in order: each
// enters the steps' namespace with nsenter. Every rule drops traffic from
// the steps' range, so nothing a step does not send is touched, and the
// namespace is new at each RootlessKit start, so the rules never repeat.
func StepGuardCommands(cfg GuardConfig) ([][]string, error) {
	if strings.TrimSpace(cfg.Netns) == "" {
		return nil, errors.New("step guard: no steps namespace (is this running inside RootlessKit with --detach-netns?)")
	}
	steps, uplink := cfg.Steps.Masked(), cfg.Uplink.Masked()
	if !steps.IsValid() || !steps.Addr().Is4() || !uplink.IsValid() || !uplink.Addr().Is4() {
		return nil, fmt.Errorf("step guard: the step range %q and RootlessKit's range %q must be IPv4 ranges", cfg.Steps, cfg.Uplink)
	}
	if steps.Overlaps(uplink) {
		return nil, fmt.Errorf("step guard: the step range %s overlaps RootlessKit's range %s", steps, uplink)
	}
	enter := []string{"nsenter", "--net=" + cfg.Netns}
	sysctl := func(k string) []string { return append(append([]string{}, enter...), "sysctl", "-qw", k+"=1") }
	drop := func(chain string, dst string) []string {
		c := append(append([]string{}, enter...), "iptables", "-w", "-I", chain, "-s", steps.String())
		if dst != "" {
			c = append(c, "-d", dst)
		}
		return append(c, "-j", "DROP")
	}
	var cmds [][]string
	if cfg.IPv6 {
		// First, so no link BuildKit makes later ever has IPv6: "default"
		// is what a new link starts with, "all" turns off the links there.
		cmds = append(cmds, sysctl("net.ipv6.conf.all.disable_ipv6"), sysctl("net.ipv6.conf.default.disable_ipv6"))
	}
	cmds = append(cmds,
		// A step sends only from its own address: strict reverse-path
		// filtering on every link, those made later included.
		sysctl("net.ipv4.conf.all.rp_filter"),
		sysctl("net.ipv4.conf.default.rp_filter"),
		drop("INPUT", ""),
		drop("FORWARD", steps.String()),
		drop("FORWARD", uplink.String()),
	)
	for _, a := range cfg.Own {
		if a.Is4() && !a.IsLoopback() {
			cmds = append(cmds, drop("FORWARD", netip.PrefixFrom(a, 32).String()))
		}
	}
	return cmds, nil
}

// ApplyStepGuard runs StepGuardCommands. Any failure stops it: buildkitd
// must not start with steps that can reach each other.
func ApplyStepGuard(ctx context.Context, cfg GuardConfig) error {
	cmds, err := StepGuardCommands(cfg)
	if err != nil {
		return err
	}
	run := cfg.run
	if run == nil {
		run = runCommand
	}
	for _, c := range cmds {
		if err := run(ctx, c[0], c[1:]...); err != nil {
			return fmt.Errorf("step guard: %s: %w", strings.Join(c, " "), err)
		}
	}
	return nil
}

// runCommand runs a command and returns its output with a failure.
func runCommand(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// OwnAddrs are the IPv4 addresses of the namespace this process is in,
// loopback left out.
func OwnAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return ipv4NonLoopback(addrs), nil
}

func ipv4NonLoopback(addrs []net.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLoopback() {
			out = append(out, ip)
		}
	}
	return out
}

// DetachedNetns is the steps' namespace RootlessKit names for its child
// in $ROOTLESSKIT_STATE_DIR, or "" outside RootlessKit.
func DetachedNetns() string {
	dir := strings.TrimSpace(os.Getenv("ROOTLESSKIT_STATE_DIR"))
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "netns")
}
