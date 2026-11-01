//go:build linux && kerneltest

package netrules

// Real-kernel checks of the batch path, in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run 'KernelBatch' -bench 'KernelBlockClear'
//
// The batch must leave exactly the rules the per-rule path leaves (compared
// as `iptables -S` sees them) while reading each chain once.

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// freshFilter gives each run an empty iptables-nft filter table.
func freshFilter(tb testing.TB) {
	tb.Helper()
	if os.Geteuid() != 0 {
		tb.Skip("needs root in a privileged container")
	}
	_ = exec.Command("nft", "delete", "table", "ip", "filter").Run()
	if out, err := exec.Command("iptables", "-w", "-P", "FORWARD", "ACCEPT").CombinedOutput(); err != nil {
		tb.Fatalf("iptables: %v: %s", err, out)
	}
}

func kernelManager(tb testing.TB, batch bool) *Manager {
	tb.Helper()
	m, err := NewWithOptions(true, BackendNetlink, ChainAerolvmUser)
	if err != nil {
		tb.Fatal(err)
	}
	m.SetBridgeSubnet("10.99.0.0/16")
	if err := m.EnsureChain(); err != nil {
		tb.Fatal(err)
	}
	if !batch {
		// The per-rule path: the same backend with DeleteAll/EnsureAll
		// hidden.
		m.ipt = perRuleBackend{m.ipt, m.ipt.(inputBootstrapBackend)}
	}
	return m
}

// perRuleBackend is a backend with its batch methods hidden.
type perRuleBackend struct {
	RuleBackend
	inputBootstrapBackend
}

func iptablesS(tb testing.TB, chains ...string) string {
	tb.Helper()
	var sb strings.Builder
	for _, c := range chains {
		out, err := exec.Command("iptables", "-w", "-S", c).CombinedOutput()
		if err != nil {
			tb.Fatalf("iptables -S %s: %v: %s", c, err, out)
		}
		sb.Write(out)
	}
	return sb.String()
}

func neighbours(tb testing.TB, m *Manager, n int) {
	tb.Helper()
	for i := 0; i < n; i++ {
		if err := m.BlockAllEgress(fmt.Sprintf("10.98.%d.%d", i/250, i%250+2)); err != nil {
			tb.Fatal(err)
		}
	}
}

// nodeGuarded installs the node guard (AEROLVM-NODE) for the bridge subnet
// the way the service does at boot, through a manager of its own on the
// real backend, and returns that manager and the guard's chains.
func nodeGuarded(tb testing.TB) (*Manager, []string) {
	tb.Helper()
	g, err := NewWithOptions(true, BackendNetlink, ChainAerolvmUser)
	if err != nil {
		tb.Fatal(err)
	}
	subnet := netip.MustParsePrefix("10.99.0.0/16")
	if err := g.SetNodeGuard(subnet, []NodePort{{Proto: "udp", Port: 53}, {Proto: "tcp", Port: 15080}}); err != nil {
		tb.Fatal(err)
	}
	pair := NodeChainsFor(subnet)
	return g, []string{ChainAerolvmNode, pair[0], pair[1]}
}

// TestKernelBatchMatchesPerRule runs the same sequence on both paths and
// compares the chains after each step, including a duplicate rule a past
// race left (which the clear must sweep) and a re-block (idempotent). The
// node guard is in place first, as on a node since #851: neither path may
// change a rule of it, and INPUT must end up the same on both.
func TestKernelBatchMatchesPerRule(t *testing.T) {
	run := func(batch bool) []string {
		freshFilter(t)
		guard, guardChains := nodeGuarded(t)
		guardBefore := iptablesS(t, guardChains...)
		m := kernelManager(t, batch)
		neighbours(t, m, 20)
		var trace []string
		snap := func(step string, ins bool, err error) {
			if got := iptablesS(t, guardChains...); got != guardBefore {
				t.Fatalf("batch=%v %s changed the node guard:\n--- before\n%s\n--- after\n%s", batch, step, guardBefore, got)
			}
			trace = append(trace, fmt.Sprintf("== %s inserted=%v err=%v\n%s", step, ins, err, iptablesS(t, "INPUT", ChainAerolvmUser, ChainAerolvmInput)))
		}
		defer func() {
			if repaired, err := guard.ReassertNodeGuard(); err != nil || repaired {
				t.Fatalf("batch=%v: node guard not intact after the sequence: repaired=%v err=%v", batch, repaired, err)
			}
		}()
		ins, err := m.BlockAllEgressReport("10.97.0.2")
		snap("block", ins, err)
		ins, err = m.BlockAllEgressReport("10.97.0.2")
		snap("block again", ins, err)
		if out, err := exec.Command("iptables", "-w", "-I", ChainAerolvmUser, "-s", "10.97.0.2", "-j", "DROP").CombinedOutput(); err != nil {
			t.Fatalf("seed duplicate: %v %s", err, out)
		}
		snap("duplicate seeded", false, nil)
		err = m.ClearBlockAllEgress("10.97.0.2")
		snap("clear", false, err)
		err = m.ClearBlockAllEgress("10.97.0.2")
		snap("clear again", false, err)
		return trace
	}
	per, batch := run(false), run(true)
	for i := range per {
		if per[i] != batch[i] {
			t.Fatalf("batch diverges from the per-rule path at step %d:\n--- per-rule\n%s\n--- batch\n%s", i, per[i], batch[i])
		}
	}
	last := batch[len(batch)-1]
	if strings.Contains(last, "10.97.0.2") {
		t.Fatalf("clear left a rule for the sandbox:\n%s", last)
	}
	if !strings.Contains(last, "10.98.0.21") {
		t.Fatalf("clear touched a neighbour's rules:\n%s", last)
	}
}

// BenchmarkKernelBlockClear times the block-all install and its lift on
// both paths next to n other sandboxes' rules: the per-rule path reads the
// chains per rule, the batch once per chain.
func BenchmarkKernelBlockClear(b *testing.B) {
	for _, n := range []int{0, 200, 1000} {
		for _, path := range []string{"per-rule", "batch"} {
			b.Run(fmt.Sprintf("neighbours=%d/%s", n, path), func(b *testing.B) {
				freshFilter(b)
				m := kernelManager(b, path == "batch")
				neighbours(b, m, n)
				var block, clear []time.Duration
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					s := time.Now()
					if _, err := m.BlockAllEgressReport("10.97.0.2"); err != nil {
						b.Fatal(err)
					}
					block = append(block, time.Since(s))
					s = time.Now()
					if err := m.ClearBlockAllEgress("10.97.0.2"); err != nil {
						b.Fatal(err)
					}
					clear = append(clear, time.Since(s))
				}
				b.StopTimer()
				b.ReportMetric(float64(median(block).Microseconds()), "block_p50_us")
				b.ReportMetric(float64(median(clear).Microseconds()), "clear_p50_us")
			})
		}
	}
}

func median(v []time.Duration) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), v...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s[len(s)/2]
}
