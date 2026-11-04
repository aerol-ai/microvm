//go:build linux && kerneltest

package netrules

// Real-kernel, real-packet checks of the block sets against the
// per-address rules, in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run 'KernelBlockSets' -bench 'KernelBlockSets'
//
// A sandbox is a network namespace ("sb", 10.97.0.2) behind a veth into
// this namespace (the node, 10.97.0.1), which forwards to another ("out",
// 10.98.0.2). A packet "escapes" when it reaches out (forward) or this
// namespace's input past the block chains. Every step of a sandbox's life
// is checked on both paths, and so is a sandboxd killed (SIGKILL, a real
// separate process) between the block and the release.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	ktSandboxIP = "10.97.0.2"
	ktNodeIP    = "10.97.0.1"
	ktOutIP     = "10.98.0.2"
	ktHelperEnv = "AEROL_NETRULES_KT_HELPER"
)

// TestMain runs the helper modes this file starts as separate processes:
// a UDP echo server inside the sandbox namespace, and a sandboxd stand-in
// that blocks (and maybe lifts) an address, says so, and waits to be
// killed.
func TestMain(m *testing.M) {
	mode, arg, _ := strings.Cut(os.Getenv(ktHelperEnv), ":")
	switch mode {
	case "udpecho":
		conn, err := net.ListenPacket("udp4", arg)
		if err != nil {
			fmt.Println("listen:", err)
			os.Exit(2)
		}
		fmt.Println("ready")
		buf := make([]byte, 64)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				os.Exit(0)
			}
			_, _ = conn.WriteTo(buf[:n], from)
		}
	case "block", "lift":
		mgr, err := NewWithOptions(true, BackendNetlink, ChainAerolvmUser)
		if err == nil {
			err = mgr.PrepareBlockSets()
		}
		if err == nil {
			err = mgr.BlockAllEgress(arg)
		}
		if err == nil && mode == "lift" {
			err = mgr.LiftBlockAllEgress(arg)
		}
		if err != nil {
			fmt.Println("helper:", err)
			os.Exit(2)
		}
		fmt.Println(mode + "ed")
		select {} // until SIGKILL
	}
	os.Exit(m.Run())
}

func ktRun(tb testing.TB, args ...string) string {
	tb.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		tb.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// ktTopology builds sb ↔ node ↔ out, and counters for what escapes: in out
// for forwarded packets, and in this namespace's input after the block
// chains (priority 10) for packets to the node. Removes it all at cleanup.
func ktTopology(tb testing.TB) {
	tb.Helper()
	if os.Geteuid() != 0 {
		tb.Skip("needs root in a privileged container")
	}
	for _, ns := range []string{"sb", "out"} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
	_ = exec.Command("ip", "link", "del", "hsb").Run()
	_ = exec.Command("ip", "link", "del", "hout").Run()
	_ = exec.Command("nft", "delete", "table", "ip", "kt_count").Run()
	_ = exec.Command("nft", "delete", "table", "ip", BlockTable).Run()
	for _, cmd := range [][]string{
		{"sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "add", "sb"},
		{"ip", "netns", "add", "out"},
		{"ip", "link", "add", "hsb", "type", "veth", "peer", "name", "eth0", "netns", "sb"},
		{"ip", "link", "add", "hout", "type", "veth", "peer", "name", "eth0", "netns", "out"},
		{"ip", "addr", "add", ktNodeIP + "/24", "dev", "hsb"},
		{"ip", "addr", "add", "10.98.0.1/24", "dev", "hout"},
		{"ip", "link", "set", "hsb", "up"},
		{"ip", "link", "set", "hout", "up"},
		{"ip", "-n", "sb", "addr", "add", ktSandboxIP + "/24", "dev", "eth0"},
		{"ip", "-n", "sb", "link", "set", "eth0", "up"},
		{"ip", "-n", "sb", "link", "set", "lo", "up"},
		{"ip", "-n", "sb", "route", "add", "default", "via", ktNodeIP},
		{"ip", "-n", "out", "addr", "add", ktOutIP + "/24", "dev", "eth0"},
		{"ip", "-n", "out", "link", "set", "eth0", "up"},
		{"ip", "-n", "out", "route", "add", "default", "via", "10.98.0.1"},
		{"ip", "netns", "exec", "out", "nft", "add table ip kt_count; add chain ip kt_count in { type filter hook input priority 0; }; add rule ip kt_count in ip saddr " + ktSandboxIP + " counter"},
		{"nft", "add table ip kt_count; add chain ip kt_count in { type filter hook input priority 10; }; add rule ip kt_count in ip saddr " + ktSandboxIP + " udp dport 9 counter"},
	} {
		ktRun(tb, cmd...)
	}
	tb.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", "sb").Run()
		_ = exec.Command("ip", "netns", "del", "out").Run()
		_ = exec.Command("nft", "delete", "table", "ip", "kt_count").Run()
		_ = exec.Command("nft", "delete", "table", "ip", BlockTable).Run()
	})
}

// ktCounter reads the packets counted in ns ("" = this one).
func ktCounter(tb testing.TB, ns string) int {
	tb.Helper()
	args := []string{"nft", "list", "chain", "ip", "kt_count", "in"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	out := ktRun(tb, args...)
	i := strings.Index(out, "packets ")
	if i < 0 {
		tb.Fatalf("no counter in %s", out)
	}
	f := strings.Fields(out[i+len("packets "):])
	n, _ := strconv.Atoi(f[0])
	return n
}

// ktEscapes sends a burst from the sandbox to the outside and to the node
// and reports how many got through each way.
func ktEscapes(tb testing.TB) (forward, input int) {
	tb.Helper()
	f0, i0 := ktCounter(tb, "out"), ktCounter(tb, "")
	ktRun(tb, "ip", "netns", "exec", "sb", "bash", "-c",
		"for i in 1 2 3 4 5; do echo x > /dev/udp/"+ktOutIP+"/9; echo x > /dev/udp/"+ktNodeIP+"/9; done")
	time.Sleep(50 * time.Millisecond)
	return ktCounter(tb, "out") - f0, ktCounter(tb, "") - i0
}

func ktExpect(tb testing.TB, step string, open bool) {
	tb.Helper()
	fwd, in := ktEscapes(tb)
	if open && (fwd == 0 || in == 0) {
		tb.Fatalf("%s: want open, got forward %d input %d through", step, fwd, in)
	}
	if !open && (fwd != 0 || in != 0) {
		tb.Fatalf("%s: %d forwarded and %d input packets escaped a blocked sandbox", step, fwd, in)
	}
}

// ktReplyArrives: the node opens a UDP exchange with the sandbox; its reply
// must come back even while the sandbox is blocked (sandboxd to toolboxd).
func ktReplyArrives(tb testing.TB) bool {
	tb.Helper()
	cmd := exec.Command("ip", "netns", "exec", "sb", os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), ktHelperEnv+"=udpecho:"+ktSandboxIP+":7000")
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); strings.TrimSpace(line) != "ready" {
		tb.Fatalf("echo helper: %q", line)
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ktNodeIP)}, &net.UDPAddr{IP: net.ParseIP(ktSandboxIP), Port: 7000})
	if err != nil {
		tb.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		tb.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	return err == nil && string(buf[:n]) == "ping"
}

// ktManager is a fresh manager on AEROLVM-USER, on the block sets or not.
func ktManager(tb testing.TB, sets bool) *Manager {
	tb.Helper()
	freshFilter(tb)
	_ = exec.Command("nft", "delete", "table", "ip", BlockTable).Run()
	ResetBlockSetsForTest()
	m, err := NewWithOptions(true, BackendNetlink, ChainAerolvmUser)
	if err != nil {
		tb.Fatal(err)
	}
	m.SetBridgeSubnet("10.97.0.0/16")
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

// ktRestart is sandboxd starting again: a new manager that reads the sets
// the last one left.
func ktRestart(tb testing.TB) *Manager {
	tb.Helper()
	ResetBlockSetsForTest()
	m, err := NewWithOptions(true, BackendNetlink, ChainAerolvmUser)
	if err != nil {
		tb.Fatal(err)
	}
	if err := m.PrepareBlockSets(); err != nil {
		tb.Fatal(err)
	}
	return m
}

// TestKernelBlockSetsNoEscape walks a sandbox's life on both paths: open,
// blocked from before its first packet, lifted, blocked again, let go,
// and the next owner of the address blocked; host-opened exchanges get
// their replies throughout.
func TestKernelBlockSetsNoEscape(t *testing.T) {
	for _, sets := range []bool{false, true} {
		t.Run(fmt.Sprintf("sets=%v", sets), func(t *testing.T) {
			ktTopology(t)
			m := ktManager(t, sets)
			ktExpect(t, "before any rule", true)
			if err := m.BlockAllEgress(ktSandboxIP); err != nil {
				t.Fatal(err)
			}
			ktExpect(t, "blocked", false)
			if !ktReplyArrives(t) {
				t.Fatal("blocked: the node's own exchange with the sandbox got no reply")
			}
			if err := m.LiftBlockAllEgress(ktSandboxIP); err != nil {
				t.Fatal(err)
			}
			ktExpect(t, "lifted", true)
			if err := m.BlockAllEgress(ktSandboxIP); err != nil {
				t.Fatal(err)
			}
			ktExpect(t, "blocked again (a quota, a policy)", false)
			if err := m.LiftBlockAllEgress(ktSandboxIP); err != nil {
				t.Fatal(err)
			}
			if err := m.ClearBlockAllEgress(ktSandboxIP); err != nil {
				t.Fatal(err)
			}
			ktExpect(t, "let go", true)
			if sets {
				if b, r := BlockedInSets(ktSandboxIP); b || r {
					t.Fatalf("let go: sets still hold blocked=%v released=%v", b, r)
				}
				if out := ktRun(t, "nft", "list", "table", "ip", BlockTable); strings.Contains(out, ktSandboxIP) {
					t.Fatalf("let go: the table still names the address:\n%s", out)
				}
			}
			if err := m.BlockAllEgress(ktSandboxIP); err != nil {
				t.Fatal(err)
			}
			ktExpect(t, "the next owner, blocked", false)
		})
	}
}

// ktHelper starts a sandboxd stand-in that blocks (and with mode "lift"
// also releases) ip, and returns once it has.
func ktHelper(tb testing.TB, mode string) *exec.Cmd {
	tb.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), ktHelperEnv+"="+mode+":"+ktSandboxIP)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		tb.Fatal(err)
	}
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	if strings.TrimSpace(line) != mode+"ed" {
		_ = cmd.Process.Kill()
		tb.Fatalf("helper %s: %q", mode, line)
	}
	return cmd
}

// TestKernelBlockSetsSandboxdKilled: a sandboxd killed between a create's
// block and its release leaves the address blocked, through the restart,
// until the orphan's removal lets it go; one killed after the release
// leaves a release behind that must never open the address's next owner.
func TestKernelBlockSetsSandboxdKilled(t *testing.T) {
	t.Run("between block and release", func(t *testing.T) {
		ktTopology(t)
		ktManager(t, true)
		h := ktHelper(t, "block")
		ktExpect(t, "blocked by the doomed sandboxd", false)
		_ = h.Process.Signal(syscall.SIGKILL)
		_ = h.Wait()
		ktExpect(t, "after kill -9", false)
		m := ktRestart(t)
		ktExpect(t, "after the restart", false)
		if b, r := BlockedInSets(ktSandboxIP); !b || r {
			t.Fatalf("restart read blocked=%v released=%v, want blocked only", b, r)
		}
		// Reconcile's orphan removal destroys the sandbox: Forget.
		if err := m.ClearBlockAllEgress(ktSandboxIP); err != nil {
			t.Fatal(err)
		}
		ktExpect(t, "after the orphan's removal", true)
	})
	t.Run("after the release, then the address reused", func(t *testing.T) {
		ktTopology(t)
		ktManager(t, true)
		h := ktHelper(t, "lift")
		ktExpect(t, "released by the doomed sandboxd", true)
		_ = h.Process.Signal(syscall.SIGKILL)
		_ = h.Wait()
		m := ktRestart(t)
		if b, r := BlockedInSets(ktSandboxIP); !b || !r {
			t.Fatalf("restart read blocked=%v released=%v, want both (the stale release)", b, r)
		}
		// The address's next owner is a restricted create: its block must
		// hold even though the stale release is still in the set.
		if err := m.BlockAllEgress(ktSandboxIP); err != nil {
			t.Fatal(err)
		}
		ktExpect(t, "the next owner, blocked over a stale release", false)
		if _, r := BlockedInSets(ktSandboxIP); r {
			t.Fatal("the stale release survived the next owner's block")
		}
	})
}

// TestKernelBlockSetsConvertsLegacyRules: an older daemon's per-address
// block pair becomes a set element at boot, the rules go, and the address
// is blocked at every step.
func TestKernelBlockSetsConvertsLegacyRules(t *testing.T) {
	ktTopology(t)
	old := ktManager(t, false)
	if err := old.BlockAllEgress(ktSandboxIP); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(iptablesS(t, ChainAerolvmUser), ktSandboxIP) {
		t.Fatal("setup: no per-address rule")
	}
	ktExpect(t, "blocked by the old rules", false)
	m := ktRestart(t)
	ktExpect(t, "after conversion", false)
	if out := iptablesS(t, ChainAerolvmUser, ChainAerolvmInput); strings.Contains(out, ktSandboxIP) {
		t.Fatalf("conversion left the per-address rules:\n%s", out)
	}
	if b, _ := BlockedInSets(ktSandboxIP); !b {
		t.Fatal("conversion didn't put the address in @blocked")
	}
	if !m.legacyConverted.Load() {
		t.Fatal("conversion not recorded")
	}
	if err := m.LiftBlockAllEgress(ktSandboxIP); err != nil {
		t.Fatal(err)
	}
	ktExpect(t, "lifted after conversion", true)
}

// TestKernelBlockSetsFlushRebuilt: a ruleset flush of the block table is
// put back by the next operation, with what was blocked still blocked.
func TestKernelBlockSetsFlushRebuilt(t *testing.T) {
	ktTopology(t)
	m := ktManager(t, true)
	if err := m.BlockAllEgress(ktSandboxIP); err != nil {
		t.Fatal(err)
	}
	ktRun(t, "nft", "delete", "table", "ip", BlockTable)
	ktExpect(t, "after the flush (open: the rules of a flush are gone)", true)
	blockReassertMinGap = 0
	defer func() { blockReassertMinGap = 10 * time.Second }()
	if repaired, err := m.ReassertBlockSets(); err != nil || !repaired {
		t.Fatalf("reassert: repaired=%v err=%v", repaired, err)
	}
	ktExpect(t, "after the reassert", false)
	ktRun(t, "nft", "delete", "table", "ip", BlockTable)
	// An operation on another address puts the table back too.
	if err := m.BlockAllEgress("10.97.0.77"); err != nil {
		t.Fatal(err)
	}
	ktExpect(t, "after the next block", false)
}

// ktGen is the node's nftables generation: every commit bumps it.
func ktGen(tb testing.TB) uint32 {
	tb.Helper()
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		tb.Fatal(err)
	}
	defer c.Close()
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETGEN), Flags: netlink.Request},
		Data:   []byte{unix.AF_UNSPEC, 0, 0, 0},
	})
	if err != nil || len(msgs) != 1 || len(msgs[0].Data) < 4 {
		tb.Fatalf("getgen: %v %d", err, len(msgs))
	}
	ad, err := netlink.NewAttributeDecoder(msgs[0].Data[4:])
	if err != nil {
		tb.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		if ad.Type() == unix.NFTA_GEN_ID {
			return ad.Uint32()
		}
	}
	tb.Fatal("getgen: no generation id")
	return 0
}

// TestKernelBlockSetsSteadyReassertCommitsNothing: with the table as made,
// the re-assert only reads. It used to re-create the table, the sets and
// the chains every interval; the chain updates that commits made were freed
// after an RCU grace period, which the next netfilter socket closed on the
// node (the re-assert's own) waited for under the commit mutex, holding up
// every create's lift for 5 to 10 ms on a 48-vCPU host. The block-set
// operations also share one kept-open socket.
func TestKernelBlockSetsSteadyReassertCommitsNothing(t *testing.T) {
	ktTopology(t)
	m := ktManager(t, true)
	if err := m.BlockAllEgress(ktSandboxIP); err != nil {
		t.Fatal(err)
	}
	if err := m.LiftBlockAllEgress(ktSandboxIP); err != nil {
		t.Fatal(err)
	}
	// What the kernel reports reads back as made, on a fresh socket.
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tbl := blockTableRef()
	fwd, in := blockChains(tbl)
	if !blockTableInPlace(c, tbl, fwd, in) {
		t.Fatal("the table as EnsureBlockTable made it does not read back in place")
	}
	blockReassertMinGap = 0
	defer func() { blockReassertMinGap = 10 * time.Second }()
	nb := m.ipt.(*netlinkBackend)
	conn := nb.setC
	gen := ktGen(t)
	for i := 0; i < 3; i++ {
		if repaired, err := m.ReassertBlockSets(); err != nil || repaired {
			t.Fatalf("reassert %d: repaired=%v err=%v", i, repaired, err)
		}
	}
	if got := ktGen(t); got != gen {
		t.Fatalf("a steady re-assert committed: generation %d → %d", gen, got)
	}
	if nb.setC == nil || nb.setC != conn {
		t.Fatal("the block-set socket was not kept open across operations")
	}
	ktExpect(t, "after the re-asserts (lifted)", true)
	// A chain policy changed under us is put back by the next re-assert.
	ktRun(t, "nft", "chain", "ip", BlockTable, "input", "{", "policy", "drop", ";", "}")
	if _, err := m.ReassertBlockSets(); err != nil {
		t.Fatal(err)
	}
	if !blockTableInPlace(c, tbl, fwd, in) {
		t.Fatal("the re-assert did not put the chain policy back")
	}
}

func ktPct(v []time.Duration, p int) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	return s[(len(s)-1)*p/100]
}

// ktChurn blocks and lets go of other addresses in a loop, as other creates
// and destroys on the node do.
func ktChurn(m *Manager, stop *atomic.Bool, wg *sync.WaitGroup, base int) {
	defer wg.Done()
	for i := 0; !stop.Load(); i++ {
		ip := fmt.Sprintf("10.96.%d.%d", base, i%200+2)
		_ = m.BlockAllEgress(ip)
		time.Sleep(20 * time.Millisecond)
		_ = m.ClearBlockAllEgress(ip)
	}
}

// BenchmarkKernelBlockSets times a create's block and its lift, and the
// destroy's let-go, next to n blocked neighbours and two churning
// create/destroy loops, on the per-address rules and on the block sets.
func BenchmarkKernelBlockSets(b *testing.B) {
	for _, n := range []int{20, 300, 1000} {
		for _, sets := range []bool{false, true} {
			b.Run(fmt.Sprintf("neighbours=%d/sets=%v", n, sets), func(b *testing.B) {
				m := ktManager(b, sets)
				neighbours(b, m, n)
				var stop atomic.Bool
				var wg sync.WaitGroup
				wg.Add(2)
				go ktChurn(m, &stop, &wg, 1)
				go ktChurn(m, &stop, &wg, 2)
				b.Cleanup(func() { stop.Store(true); wg.Wait() })
				var block, lift, forget []time.Duration
				stale := 0
				for i := 0; i < b.N; i++ {
					s := time.Now()
					if err := m.BlockAllEgress("10.97.0.2"); errors.Is(err, errBatchStale) {
						// The per-address path positions its insert from a
						// listing; under this churn at 1,000 rules the chain
						// can move three times in a row. The sets have no
						// positions.
						stale++
						i--
						continue
					} else if err != nil {
						b.Fatal(err)
					}
					block = append(block, time.Since(s))
					time.Sleep(30 * time.Millisecond) // the build and the gateway attach
					s = time.Now()
					if err := m.LiftBlockAllEgress("10.97.0.2"); err != nil {
						b.Fatal(err)
					}
					lift = append(lift, time.Since(s))
					s = time.Now()
					if err := m.ClearBlockAllEgress("10.97.0.2"); err != nil {
						b.Fatal(err)
					}
					forget = append(forget, time.Since(s))
				}
				b.ReportMetric(float64(stale), "stale_block_failures")
				for _, x := range []struct {
					name string
					v    []time.Duration
				}{{"block", block}, {"lift", lift}, {"forget", forget}} {
					b.ReportMetric(float64(ktPct(x.v, 50).Microseconds()), x.name+"_p50_us")
					b.ReportMetric(float64(ktPct(x.v, 99).Microseconds()), x.name+"_p99_us")
				}
			})
		}
	}
}
