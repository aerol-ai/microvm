package buildnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func guardConfig() GuardConfig {
	return GuardConfig{Netns: "/run/aerolvm-buildkit/rootlesskit/netns",
		Steps: netip.MustParsePrefix(StepRange), Uplink: netip.MustParsePrefix(UplinkRange),
		Own: []netip.Addr{netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd00::2")}}
}

// The guard closes every way one step reaches another or the node through
// the steps' namespace (review of #1398, F4), and touches nothing a step
// does not send.
func TestStepGuardCommands(t *testing.T) {
	cmds, err := StepGuardCommands(guardConfig())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cmds {
		if c[0] != "nsenter" || c[1] != "--net=/run/aerolvm-buildkit/rootlesskit/netns" {
			t.Fatalf("command %q does not run in the steps' namespace", c)
		}
		got = append(got, strings.Join(c[2:], " "))
	}
	want := []string{
		"sysctl -qw net.ipv4.conf.all.rp_filter=1",
		"sysctl -qw net.ipv4.conf.default.rp_filter=1",
		"iptables -w -I INPUT -s 198.18.0.0/16 -j DROP",
		"iptables -w -I FORWARD -s 198.18.0.0/16 -d 198.18.0.0/16 -j DROP",
		"iptables -w -I FORWARD -s 198.18.0.0/16 -d 198.19.0.0/24 -j DROP",
		"iptables -w -I FORWARD -s 198.18.0.0/16 -d 10.88.0.2/32 -j DROP",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestStepGuardCommandsRefuses(t *testing.T) {
	for name, edit := range map[string]func(*GuardConfig){
		"no namespace":       func(c *GuardConfig) { c.Netns = " " },
		"no step range":      func(c *GuardConfig) { c.Steps = netip.Prefix{} },
		"an IPv6 uplink":     func(c *GuardConfig) { c.Uplink = netip.MustParsePrefix("fd00::/64") },
		"overlapping ranges": func(c *GuardConfig) { c.Uplink = netip.MustParsePrefix("198.18.4.0/24") },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := guardConfig()
			edit(&cfg)
			if _, err := StepGuardCommands(cfg); err == nil {
				t.Fatal("accepted")
			}
			if err := ApplyStepGuard(context.Background(), cfg); err == nil {
				t.Fatal("applied")
			}
		})
	}
}

// The commands run in order, and the first failure stops the guard (and
// so buildkitd's start).
func TestApplyStepGuard(t *testing.T) {
	cfg := guardConfig()
	var ran []string
	cfg.run = func(_ context.Context, name string, args ...string) error {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil
	}
	if err := ApplyStepGuard(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cmds, _ := StepGuardCommands(cfg)
	if len(ran) != len(cmds) {
		t.Fatalf("ran %d commands, want %d", len(ran), len(cmds))
	}
	ran = nil
	cfg.run = func(_ context.Context, name string, args ...string) error {
		ran = append(ran, name)
		if len(ran) == 3 {
			return errors.New("iptables: no such table")
		}
		return nil
	}
	err := ApplyStepGuard(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "no such table") || len(ran) != 3 {
		t.Fatalf("err = %v after %d commands, want a stop at the third", err, len(ran))
	}
}

func TestRunCommand(t *testing.T) {
	if err := runCommand(context.Background(), "true"); err != nil {
		t.Fatalf("true: %v", err)
	}
	if err := runCommand(context.Background(), "sh", "-c", "echo nope >&2; exit 3"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("a failing command: %v", err)
	}
}

func TestOwnAddrs(t *testing.T) {
	got := ipv4NonLoopback([]net.Addr{
		&net.IPNet{IP: net.ParseIP("10.88.0.2"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPAddr{IP: net.ParseIP("10.0.0.9")},
	})
	if len(got) != 1 || got[0] != netip.MustParseAddr("10.88.0.2") {
		t.Fatalf("addresses %v, want only 10.88.0.2", got)
	}
	if _, err := OwnAddrs(); err != nil {
		t.Fatalf("OwnAddrs: %v", err)
	}
}

func TestDetachedNetns(t *testing.T) {
	t.Setenv("ROOTLESSKIT_STATE_DIR", "")
	if DetachedNetns() != "" {
		t.Fatal("a namespace outside RootlessKit")
	}
	t.Setenv("ROOTLESSKIT_STATE_DIR", "/run/aerolvm-buildkit/rootlesskit")
	if got := DetachedNetns(); got != "/run/aerolvm-buildkit/rootlesskit/netns" {
		t.Fatalf("DetachedNetns = %q", got)
	}
}
