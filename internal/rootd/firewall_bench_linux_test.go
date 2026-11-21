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
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/nsbuild"
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
	// single are sandboxd's own steps in single mode (netns.Host): no
	// marks, a blocking flock, CNI with no process group.
	single nsbuild.Steps
}

func newFirewallBench(tb testing.TB, sopts ...grpc.ServerOption) *firewallBench {
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
		o.ServerOptions = append(o.ServerOptions, sopts...)
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
	single := k.steps
	if dir := os.Getenv("AEROL_KT_CNI_DIR"); dir != "" {
		runner, err := cni.NewExecRunner(cni.Config{PluginDir: dir, ConfPath: filepath.Join(k.confDir, k.confName)})
		if err != nil {
			tb.Fatal(err)
		}
		single.Runner = runner
	}
	root := k.netnsDir
	single.Create = func(_ context.Context, name string) error { return nsbuild.CreateNamed(root, name) }
	single.FlushConntrack, single.StopOnCancel = nil, false
	return &firewallBench{k: k, r: r, m: m, c: c, tb: tb, single: single}
}

// singleCold is a cold create's root work in process.
func (f *firewallBench) singleCold(ctx context.Context, name string) (string, error) {
	_, ip, err := f.single.Realize(ctx, name)
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

// TestKernelCreateBudget is the create's root work, split against single,
// as a paired measurement: every round runs both, in turns (which goes
// first turns each time), so load on the machine falls on both alike. It
// splits split mode's extra into the time inside the helper's call
// (PrepareSandbox's handler, server side) and the client's round trip
// around it. Runs only with AEROL_BUDGET_ROUNDS set (and
// AEROL_BUDGET_PER_ROUND, default 5), as root, with the real CNI plugins
// for the real numbers:
//
//	AEROL_KT_CNI_DIR=/opt/cni/bin AEROL_BUDGET_ROUNDS=25 go test -run TestKernelCreateBudget -v ./internal/rootd/
func TestKernelCreateBudget(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("AEROL_BUDGET_ROUNDS"))
	if rounds <= 0 {
		t.Skip("a measurement: set AEROL_BUDGET_ROUNDS")
	}
	per := 5
	if v, err := strconv.Atoi(os.Getenv("AEROL_BUDGET_PER_ROUND")); err == nil && v > 0 {
		per = v
	}
	// The handler's own time, for the call the test just made (calls here
	// are one at a time).
	var handler atomic.Int64
	f := newFirewallBench(t, grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		t0 := time.Now()
		resp, err := h(ctx, req)
		handler.Store(int64(time.Since(t0)))
		return resp, err
	}))
	ctx := context.Background()
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	type series struct{ single, split, inside []float64 }
	var cold, warm, floor series
	var loads []float64
	// A floor change: an operator floor of budgetFloorSize ranges, two
	// lists in turn so each change rewrites the chain. Single mode's floor
	// is on a subnet of its own (one manager per subnet, as on a node).
	var floorLists [2][]netip.Prefix
	for i := range floorLists {
		for j := range budgetFloorSize {
			floorLists[i] = append(floorLists[i], netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + i), byte(j), 0, 0}), 16))
		}
	}
	singleFloorSubnet := netip.MustParsePrefix("10.251.0.0/24")
	n := 0
	for r := range rounds {
		loads = append(loads, budgetLoad())
		var cs, cp, ci, ws, wp, wi, fs, fp, fi []float64
		for k := range per {
			for _, split := range [][]bool{{false, true}, {true, false}}[(r+k)%2] {
				list := floorLists[(n+k)%2]
				t0 := time.Now()
				var err error
				if split {
					strs := make([]string, len(list))
					for i, p := range list {
						strs[i] = p.String()
					}
					_, err = f.c.SetEgressFloor(ctx, strs)
				} else {
					err = f.m.SetFloor(singleFloorSubnet, list)
				}
				d := time.Since(t0)
				if err != nil {
					t.Fatal(err)
				}
				if split {
					fp, fi = append(fp, ms(d)), append(fi, ms(time.Duration(handler.Load())))
				} else {
					fs = append(fs, ms(d))
				}
			}
		}
		floor.single, floor.split, floor.inside = append(floor.single, budgetMedian(fs)), append(floor.split, budgetMedian(fp)), append(floor.inside, budgetMedian(fi))
		for k := range per {
			for _, split := range [][]bool{{false, true}, {true, false}}[(r+k)%2] {
				n++
				name := fmt.Sprintf("c%d", n)
				t0 := time.Now()
				var ip string
				var err error
				if split {
					ip, err = f.splitCold(ctx, f.c, name)
				} else {
					ip, err = f.singleCold(ctx, name)
				}
				d := time.Since(t0)
				if err != nil {
					t.Fatal(err)
				}
				if split {
					cp, ci = append(cp, ms(d)), append(ci, ms(time.Duration(handler.Load())))
				} else {
					cs = append(cs, ms(d))
				}
				if err := f.splitRelease(ctx, name, ip); err != nil {
					t.Fatal(err)
				}

				name = fmt.Sprintf("w%d", n)
				if _, ip, err = f.k.steps.Realize(ctx, name); err != nil {
					t.Fatal(err)
				}
				t0 = time.Now()
				if split {
					err = f.splitWarm(ctx, name, ip)
				} else {
					err = f.singleRules(ip)
				}
				d = time.Since(t0)
				if err != nil {
					t.Fatal(err)
				}
				if split {
					wp, wi = append(wp, ms(d)), append(wi, ms(time.Duration(handler.Load())))
				} else {
					ws = append(ws, ms(d))
				}
				if err := f.splitRelease(ctx, name, ip); err != nil {
					t.Fatal(err)
				}
			}
		}
		cold.single, cold.split, cold.inside = append(cold.single, budgetMedian(cs)), append(cold.split, budgetMedian(cp)), append(cold.inside, budgetMedian(ci))
		warm.single, warm.split, warm.inside = append(warm.single, budgetMedian(ws)), append(warm.split, budgetMedian(wp)), append(warm.inside, budgetMedian(wi))
	}
	for _, s := range []struct {
		name string
		s    series
	}{{"cold create (namespace, CNI, block-all, policy)", cold}, {"warm create (block-all, policy)", warm},
		{fmt.Sprintf("floor change (%d ranges)", budgetFloorSize), floor}} {
		t.Logf("%s: %s", s.name, budgetPaired(s.s.single, s.s.split))
		t.Logf("  inside the helper's call vs single: %s", budgetPaired(s.s.single, s.s.inside))
		t.Logf("  the client's round trip (split - inside): %s", budgetPaired(s.s.inside, s.s.split))
	}
	t.Logf("load average (1 min) over the rounds: %.2f to %.2f", slices.Min(loads), slices.Max(loads))
}

// budgetFloorSize is the operator floor's size in the floor-change series.
const budgetFloorSize = 64

func budgetMedian(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// budgetPaired: each side's median of round medians, and the per-round
// difference (b - a): its mean with a 95% confidence interval (Student
// t), and its median.
func budgetPaired(a, b []float64) string {
	d := make([]float64, len(a))
	var mean float64
	for i := range a {
		d[i] = b[i] - a[i]
		mean += d[i]
	}
	mean /= float64(len(d))
	var ss float64
	for _, x := range d {
		ss += (x - mean) * (x - mean)
	}
	table := []float64{12.71, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145,
		2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042}
	half := 0.0
	if df := len(d) - 1; df >= 1 {
		tc := 1.96
		if df <= len(table) {
			tc = table[df-1]
		}
		half = tc * math.Sqrt(ss/float64(df)) / math.Sqrt(float64(len(d)))
	}
	return fmt.Sprintf("%.2f vs %.2f ms; per round mean %+.2f ms (95%% CI %+.2f to %+.2f), median %+.2f ms, %d rounds",
		budgetMedian(a), budgetMedian(b), mean, mean-half, mean+half, budgetMedian(d), len(d))
}

func budgetLoad() float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	v, _ := strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	return v
}
