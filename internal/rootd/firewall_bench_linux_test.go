//go:build linux

package rootd

// The budget of a create's and a teardown's root work with the host
// firewall on (M1 PR 4 + PR 5), split against single, on the real kernel:
//
//	single: in this process, as sandboxd does it in privilege mode single:
//	        the namespace build, then block-all and the egress policy;
//	        a teardown clears the address, then removes the slot.
//	split:  through the helper's socket with the client sandboxd builds:
//	        one PrepareSandbox (cold: netns + firewall; warm: firewall),
//	        one ReleaseSandbox.
//
// Run as root in a privileged container, with the real CNI plugins for
// the real numbers (AEROL_KT_CNI_DIR, as the other kernel benchmarks).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

var (
	benchAllow = []string{"192.0.2.7/32"}
	benchDeny  = []string{"198.51.100.0/24"}
	bothParts  = []string{rootdpb.PartNetns, rootdpb.PartFirewall}
)

// firewallBench is a rig with the helper's firewall on, an in-process
// netrules manager for single mode, and the agent's client for split.
type firewallBench struct {
	k  *kernelNetwork
	r  *rig
	m  *netrules.Manager
	c  *rootclient.Client
	tb testing.TB
}

func newFirewallBench(tb testing.TB) *firewallBench {
	tb.Helper()
	k, _ := kernelRig(tb)
	if os.Getenv("AEROL_KT_CNI_DIR") == "" {
		k.leases = filepath.Join(tb.TempDir(), "leases")
		if err := os.MkdirAll(k.leases, 0o755); err != nil {
			tb.Fatal(err)
		}
		k.steps = k.stepsWith(&leasingRunner{Runner: k.steps.Runner, dir: k.leases, ips: map[string]string{}})
	}
	// Both sides on the production backend (SB_NETRULES_BACKEND's
	// default): a rig's helper would otherwise run iptables processes.
	r := newRig(tb, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		c.Firewall.Backend = "netlink"
		o.Network = k
	})
	m, err := newRulesManager("netlink")
	if err != nil {
		tb.Fatal(err)
	}
	m.SetBridgeSubnet(k.Subnet().String())
	if err := m.EnsureChain(); err != nil {
		tb.Fatal(err)
	}
	// As sandboxd's single mode at boot (prepareBlockSets), and as the
	// helper's EnsureHost: block-all through the block sets.
	if err := m.PrepareBlockSets(); err != nil {
		tb.Logf("block sets not prepared: %v", err)
	}
	c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, HelperUID: uint32(os.Geteuid())})
	tb.Cleanup(func() { _ = c.Close() })
	if _, err := c.EnsureHostFirewall(context.Background()); err != nil {
		tb.Fatal(err)
	}
	return &firewallBench{k: k, r: r, m: m, c: c, tb: tb}
}

// singleCold is a cold create's root work in process.
func (f *firewallBench) singleCold(ctx context.Context, name string) (string, error) {
	_, ip, err := f.k.steps.Realize(ctx, name)
	if err != nil {
		return "", err
	}
	return ip, f.singleRules(ip)
}

func (f *firewallBench) singleRules(ip string) error {
	if _, err := f.m.BlockAllEgressReport(ip); err != nil {
		return err
	}
	return f.m.ApplyEgressPolicy(ip, benchAllow, benchDeny)
}

func (f *firewallBench) singleRelease(ctx context.Context, name, ip string) error {
	if err := f.m.ClearAddress(ip); err != nil {
		return err
	}
	return f.k.Remove(ctx, name, filepath.Join(f.k.netnsDir, name), ip)
}

func (f *firewallBench) splitCold(ctx context.Context, c *rootclient.Client, name string) (string, error) {
	resp, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: name, Parts: bothParts,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true, AllowCidrs: benchAllow, DenyCidrs: benchDeny}})
	return resp.GetContainerIp(), err
}

func (f *firewallBench) splitWarm(ctx context.Context, name, ip string) error {
	_, err := f.c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: name, Parts: []string{rootdpb.PartFirewall},
		ContainerIp: ip, Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true, AllowCidrs: benchAllow, DenyCidrs: benchDeny}})
	return err
}

func (f *firewallBench) splitRelease(ctx context.Context, name, ip string) error {
	return f.c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: name, ContainerIp: ip, Parts: bothParts})
}

// BenchmarkKernelFirewallCreate: one at a time. cold and teardown time the
// call alone (the slot's build or removal for the other is untimed); warm
// is a realized slot's rules.
func BenchmarkKernelFirewallCreate(b *testing.B) {
	f := newFirewallBench(b)
	ctx := context.Background()
	for _, mode := range []string{"single", "split"} {
		b.Run("cold/"+mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				name := fmt.Sprintf("c%s-%d", mode[:2], i)
				var ip string
				var err error
				if mode == "single" {
					ip, err = f.singleCold(ctx, name)
				} else {
					ip, err = f.splitCold(ctx, f.c, name)
				}
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				_ = f.splitRelease(ctx, name, ip)
				b.StartTimer()
			}
		})
		b.Run("warm/"+mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				name := fmt.Sprintf("w%s-%d", mode[:2], i)
				_, ip, err := f.k.steps.Realize(ctx, name)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if mode == "single" {
					err = f.singleRules(ip)
				} else {
					err = f.splitWarm(ctx, name, ip)
				}
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				_ = f.splitRelease(ctx, name, ip)
				b.StartTimer()
			}
		})
		b.Run("teardown/"+mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				name := fmt.Sprintf("t%s-%d", mode[:2], i)
				ip, err := f.splitCold(ctx, f.c, name)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if mode == "single" {
					err = f.singleRelease(ctx, name, ip)
				} else {
					err = f.splitRelease(ctx, name, ip)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkKernelFirewallCreate100: 100 cold creates at once, rules
// included, single and split in turn (which goes first rotates), and the
// first call of a new client in split (its handshake, and on the first
// round the helper's lazy open of its firewall).
func BenchmarkKernelFirewallCreate100(b *testing.B) {
	const n = 100
	f := newFirewallBench(b)
	ctx := context.Background()
	// Every slot goes, its rules with it (the helper finds each address).
	clear := func() {
		entries, _ := os.ReadDir(f.k.netnsDir)
		for _, e := range entries {
			_ = f.splitRelease(ctx, e.Name(), "")
		}
	}
	var first []time.Duration
	modes := []struct {
		name string
		one  func(i int) func(j int) error
		got  []time.Duration
	}{
		{"single", func(i int) func(j int) error {
			return func(j int) error { _, err := f.singleCold(ctx, fmt.Sprintf("s%d-%d", i, j)); return err }
		}, nil},
		{"split", func(i int) func(j int) error {
			c := rootclient.New(rootclient.Config{Socket: f.r.cfg.Socket, HelperUID: uint32(os.Geteuid())})
			b.Cleanup(func() { _ = c.Close() })
			t0 := time.Now()
			if _, err := f.splitCold(ctx, c, fmt.Sprintf("f%d", i)); err != nil {
				b.Fatal(err)
			}
			first = append(first, time.Since(t0))
			return func(j int) error { _, err := f.splitCold(ctx, c, fmt.Sprintf("p%d-%d", i, j)); return err }
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
