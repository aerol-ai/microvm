//go:build linux

package rootd

// Raw-TCP host-port forwarding's cost in each privilege mode, measured the
// paired way (TestKernelCreateBudget): an expose (a port forwarded to a
// sandbox) and an unexpose, made by sandboxd's own hostport.Forwarder in
// process (single) and through the helper (split), in turns within every
// round. Root, iptables, and AEROL_BUDGET_ROUNDS.

import (
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

func TestKernelHostPortBudget(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("AEROL_BUDGET_ROUNDS"))
	if rounds <= 0 {
		t.Skip("a measurement: set AEROL_BUDGET_ROUNDS")
	}
	k := reviewKernelNet(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		c.HostPorts = rootpolicy.HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 21215}
		o.Network = k
	})
	c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, HelperUID: uint32(os.Geteuid())})
	t.Cleanup(func() { _ = c.Close() })
	sb, err := rootdpb.NewRootHelperClient(r.conn).RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	target := hostport.Target{Kind: hostport.DNAT, Addr: netip.AddrPortFrom(netip.MustParseAddr(sb.GetContainerIp()), 5432)}
	b, err := hostport.NewIPTablesBackend()
	if err != nil {
		t.Fatal(err)
	}
	single := hostport.New(b, hostport.FlushConntrack)
	split := rootclient.NewHostPortForwarder(c, nil)
	// Both sides' chains and jumps, once, outside the measurement.
	if err := single.Ensure(22999, target); err != nil {
		t.Fatal(err)
	}
	if err := split.Ensure(22998, target); err != nil {
		t.Fatal(err)
	}
	type fwd interface {
		Ensure(int, hostport.Target) error
		Remove(int) error
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	per := 5
	var ensS, ensP, remS, remP []float64
	var loads []float64
	n := 0
	for rd := range rounds {
		loads = append(loads, budgetLoad())
		var es, ep, rs, rp []float64
		for i := range per {
			for _, sp := range [][]bool{{false, true}, {true, false}}[(rd+i)%2] {
				n++
				hp := 22000 + n%900
				var f fwd = single
				if sp {
					f = split
				}
				t0 := time.Now()
				if err := f.Ensure(hp, target); err != nil {
					t.Fatal(err)
				}
				e := ms(time.Since(t0))
				t0 = time.Now()
				if err := f.Remove(hp); err != nil {
					t.Fatal(err)
				}
				rm := ms(time.Since(t0))
				if sp {
					ep, rp = append(ep, e), append(rp, rm)
				} else {
					es, rs = append(es, e), append(rs, rm)
				}
			}
		}
		ensS, ensP = append(ensS, budgetMedian(es)), append(ensP, budgetMedian(ep))
		remS, remP = append(remS, budgetMedian(rs)), append(remP, budgetMedian(rp))
	}
	t.Logf("expose (a host port forwarded to a sandbox): %s", budgetPaired(ensS, ensP))
	t.Logf("unexpose (the forward removed, its connections cut): %s", budgetPaired(remS, remP))
	t.Logf("load average (1 min) over the rounds: %.2f to %.2f", slices.Min(loads), slices.Max(loads))
	_ = single.Remove(22999)
	_ = split.Remove(22998)
}
