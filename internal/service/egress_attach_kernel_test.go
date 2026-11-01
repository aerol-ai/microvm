//go:build linux && kerneltest

package service

// Real-kernel attach benchmarks, run in a privileged Linux container:
//
//	docker run --rm --privileged -v "$PWD":/src -w /src golang:1.26-bookworm \
//	  sh -c 'apt-get update -qq && apt-get install -y -qq nftables iptables >/dev/null && \
//	         go test -tags kerneltest -run "^$" -bench KernelEgress -benchtime 300x -v ./internal/service/'
//
// The gateway runs the production nft backend (inet aerolvm_egress) and the
// driver's block-all goes through the production host firewall
// (pkg/docker/netrules, netlink backend, AEROLVM-USER + AEROLVM-INPUT), so
// every kernel write a live attach makes is in the measurement.

import (
	"fmt"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

func kernelRules(tb testing.TB) *netrules.Manager {
	tb.Helper()
	return kernelRulesOn(tb, false)
}

// kernelRulesOn is kernelRules with the block-all on the block sets
// (pkg/docker/netrules blockset.go) or on the per-address rules.
func kernelRulesOn(tb testing.TB, sets bool) *netrules.Manager {
	tb.Helper()
	// A clean slate per run: the tables are ours inside the container.
	_ = exec.Command("nft", "delete", "table", "inet", egress.TableName).Run()
	_ = exec.Command("nft", "delete", "table", "ip", "filter").Run()
	_ = exec.Command("nft", "delete", "table", "ip", netrules.BlockTable).Run()
	netrules.ResetBlockSetsForTest()
	// iptables-nft creates the ip filter table and its base chains, as on a
	// real host.
	if out, err := exec.Command("iptables", "-w", "-P", "FORWARD", "ACCEPT").CombinedOutput(); err != nil {
		tb.Fatalf("iptables: %v: %s", err, out)
	}
	m, err := netrules.NewWithOptions(true, netrules.BackendNetlink, netrules.ChainAerolvmUser)
	if err != nil {
		tb.Fatal(err)
	}
	m.SetBridgeSubnet("10.99.0.0/16")
	if err := m.EnsureChain(); err != nil {
		tb.Fatal(err)
	}
	if sets {
		if err := m.PrepareBlockSets(); err != nil {
			tb.Fatal(err)
		}
	}
	return m
}

// kernelPrefillRules installs n other sandboxes' block-all rules, the host
// firewall of a node running n restricted sandboxes: every rule lookup the
// attach's unblock makes walks past them.
func kernelPrefillRules(tb testing.TB, m *netrules.Manager, n int) {
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.98.%d.%d", i/250, i%250+2)
		if err := m.BlockAllEgress(ip); err != nil {
			tb.Fatal(err)
		}
	}
}

func BenchmarkKernelEgressAttach(b *testing.B) {
	for _, prefill := range []int{0, 200} {
		b.Run(fmt.Sprintf("prefill=%d", prefill), func(b *testing.B) {
			rules := kernelRules(b)
			kernelPrefillRules(b, rules, prefill)
			a := newAttachBench(b, egress.NewNFTBackend(), rules)
			a.prefill(b, prefill)
			total := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				total = append(total, a.attachOnce(b, i))
			}
			b.StopTimer()
			a.reportStages(b, total)
		})
	}
}

// BenchmarkKernelEgressCreate: whole creates next to 200 restricted
// neighbours and 50 attached gateway-mode ones, for a runtime that reports
// the address on return (late) and one that reports it before a 20 ms
// build (early: containerd's task start and readiness take longer).
func BenchmarkKernelEgressCreate(b *testing.B) {
	for _, early := range []bool{false, true} {
		b.Run(map[bool]string{false: "late", true: "early"}[early], func(b *testing.B) {
			rules := kernelRules(b)
			kernelPrefillRules(b, rules, 200)
			a := newAttachBench(b, egress.NewNFTBackend(), rules)
			a.prefill(b, 50)
			a.rt.early, a.rt.build = early, 20*time.Millisecond
			benchCreates(b, a)
		})
	}
}

// BenchmarkKernelEgressCreateNeighbours: early creates next to 300 and
// 1,000 restricted neighbours, 50 attached gateway-mode ones and two
// create/destroy loops churning the host firewall, with the block-all on
// the per-address rules and on the block sets. The lift (unblock) is what
// the create still waits for after the build; on the sets it is an add.
func BenchmarkKernelEgressCreateNeighbours(b *testing.B) {
	for _, n := range []int{300, 1000} {
		for _, sets := range []bool{false, true} {
			b.Run(fmt.Sprintf("neighbours=%d/sets=%v", n, sets), func(b *testing.B) {
				rules := kernelRulesOn(b, sets)
				kernelPrefillRules(b, rules, n)
				a := newAttachBench(b, egress.NewNFTBackend(), rules)
				a.prefill(b, 50)
				a.rt.early, a.rt.build = true, 20*time.Millisecond
				// The per-address path's inserts can go stale under this
				// churn; count those creates rather than stop.
				a.tolerate = !sets
				var stop atomic.Bool
				var wg sync.WaitGroup
				for g := range 2 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := 0; !stop.Load(); i++ {
							ip := fmt.Sprintf("10.96.%d.%d", g, i%200+2)
							_ = rules.BlockAllEgress(ip)
							time.Sleep(20 * time.Millisecond)
							_ = rules.ClearBlockAllEgress(ip)
						}
					}()
				}
				b.Cleanup(func() { stop.Store(true); wg.Wait() })
				benchCreates(b, a)
			})
		}
	}
}
