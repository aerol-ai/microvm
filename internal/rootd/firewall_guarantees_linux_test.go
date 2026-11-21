//go:build linux

package rootd

// The helper firewall's guarantees across calls and helper restarts, on
// Linux: positional in-memory rules (no root) and the real kernel (root,
// privileged container, both rule backends via FWREV_BACKEND):
//
//   - the floor's jump is the user chain's first rule from the moment the
//     helper's firewall opens, a restart included;
//   - a floor change never leaves the floor without its DROPs;
//   - an address's policy is replaced, never added to, and its size and
//     write time are bounded (a cap per policy and per node, the caller's
//     deadline between writes);
//   - a released address leaves no block-all behind, a restart included.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// posRules is netrules' rule backend in memory WITH rule order: Insert
// honours its position and EnsureJumpChain keeps the jump first, as both
// kernel backends do.
type posRules struct {
	mu    sync.Mutex
	rules map[string][]string
}

func newPosRules() *posRules { return &posRules{rules: map[string][]string{}} }

func (p *posRules) Exists(table, chain string, spec ...string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.rules[chain], strings.Join(spec, " ")), nil
}

func (p *posRules) Insert(table, chain string, pos int, spec ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.rules[chain]
	i := min(max(pos-1, 0), len(l))
	p.rules[chain] = slices.Insert(l, i, strings.Join(spec, " "))
	return nil
}

func (p *posRules) Delete(table, chain string, spec ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := slices.Index(p.rules[chain], strings.Join(spec, " "))
	if i < 0 {
		return errors.New("does a matching rule exist")
	}
	p.rules[chain] = slices.Delete(p.rules[chain], i, i+1)
	return nil
}

func (p *posRules) EnsureUserChain(chain string) error { p.touch(chain); return nil }
func (p *posRules) EnsureForwardJump(chain string) error {
	return p.EnsureJumpChain("FORWARD", chain)
}
func (p *posRules) EnsureInputChain(chain string) error { return p.EnsureJumpChain("INPUT", chain) }
func (p *posRules) EnsureJumpChain(parent, child string) error {
	p.touch(child)
	p.mu.Lock()
	defer p.mu.Unlock()
	j := "-j " + child
	if l := p.rules[parent]; len(l) > 0 && l[0] == j {
		return nil
	}
	p.rules[parent] = slices.Insert(p.rules[parent], 0, j)
	return nil
}
func (p *posRules) FlushChain(chain string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules[chain] = nil
	return nil
}

// ClearCommented is what both kernel backends do: every rule of the chains
// keyed by ip (its source) that carries the comment goes.
func (p *posRules) ClearCommented(chains []string, ip, comment string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range chains {
		p.rules[c] = slices.DeleteFunc(p.rules[c], func(r string) bool {
			return strings.HasPrefix(r, "-s "+ip+" ") && strings.Contains(r, "--comment "+comment+" ")
		})
	}
	return nil
}

func (p *posRules) touch(chain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.rules[chain]; !ok {
		p.rules[chain] = nil
	}
}
func (p *posRules) chain(c string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.rules[c])
}

// openWith opens a helper firewall over rules, as a fresh helper process
// does (the netrules floor registry is process-wide, so it is reset).
func openWith(t *testing.T, rules netrules.RuleBackend) *kernelFirewall {
	t.Helper()
	origRules, origFence, origSysctls := newRulesManager, newFenceBackend, ensureSysctls
	t.Cleanup(func() { newRulesManager, newFenceBackend, ensureSysctls = origRules, origFence, origSysctls })
	newRulesManager = func(string) (*netrules.Manager, error) { return netrules.NewWithBackend(rules), nil }
	newFenceBackend = func() ipv6fence.Backend { return &memFence{} }
	ensureSysctls = func() error { return nil }
	netrules.ResetFloorsForTest()
	h, err := openFirewall(Config{}, newFakeNet())
	if err != nil {
		t.Fatal(err)
	}
	return h.(*kernelFirewall)
}

// A helper that starts on a kernel an earlier helper filled (a swap, a
// crash) installs its own floor when its firewall opens, before any rule
// call, so a sandbox's rules always go in below the floor's jump.
func TestFloorStaysFirstAfterHelperRestart(t *testing.T) {
	rules := newPosRules()
	chain := netrules.ChainDockerUser // NewWithBackend's user chain
	h1 := openWith(t, rules)
	if _, err := h1.EnsureHost(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := h1.SetFloor(nil); err != nil {
		t.Fatal(err)
	}
	floorJump := "-j " + netrules.FloorChainFor(netip.MustParsePrefix("10.88.0.0/16"))
	if got := rules.chain(chain); len(got) == 0 || got[0] != floorJump {
		t.Fatalf("before the restart the floor's jump is not first: %q", got)
	}
	// The helper restarts; the kernel keeps its rules. Even with the
	// agent's EnsureHost tick first, the new helper knows nothing of the floor.
	h2 := openWith(t, rules)
	if _, err := h2.EnsureHost(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.Rules(context.Background(), rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, "10.88.0.2",
		[]string{"169.254.169.254/32"}, nil); err != nil {
		t.Fatal(err)
	}
	h2.Reassert(context.Background()) // the helper's own timer
	got := rules.chain(chain)
	t.Logf("%s after the restart:\n  %s", chain, strings.Join(got, "\n  "))
	// The floor's chain is either of its two slots (a change swaps them).
	if got[0] != floorJump && got[0] != floorJump+"-B" {
		t.Fatalf("after a helper restart the floor's jump is not first: first rule %q", got[0])
	}
}

// An address's policy is replaced as a whole: a second and third policy
// leave one policy's rules, not three.
func TestPolicyIsReplacedNotAdded(t *testing.T) {
	fn := newFakeNet()
	rules := newPosRules()
	k := openWith(t, rules)
	r := newRig(t, func(_ *Config, o *Options) { o.Network, o.Firewall = fn, k })
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	resp, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	ip := resp.GetContainerIp()
	const calls = 3
	for n := range calls {
		list := make([]string, rootpolicy.MaxPolicyCIDRs)
		for i := range list {
			list[i] = fmt.Sprintf("%d.%d.%d.0/24", 11+n, i/256, i%256)
		}
		if _, err := c.SandboxRules(context.Background(), &rootdpb.SandboxRulesRequest{ContainerIp: ip,
			Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, DenyCidrs: list}); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, r := range rules.chain(netrules.ChainDockerUser) {
		if strings.HasPrefix(r, "-s "+ip+" ") {
			n++
		}
	}
	t.Logf("rules keyed by %s in the user chain after %d calls: %d", ip, calls, n)
	if n > rootpolicy.MaxPolicyCIDRs+1 {
		t.Fatalf("one address holds %d rules; a policy holds at most %d", n, rootpolicy.MaxPolicyCIDRs+1)
	}
}

// ---- real kernel (root) ----

func shell(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Logf("%s %v: %v: %s", name, args, err, out)
	}
	return string(out)
}

func firstRule(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "-A ") {
			return l
		}
	}
	return ""
}

// pkts is the packet count on the first line of `iptables -L -v -x -n`
// that holds every word of match.
func pkts(listing string, match ...string) int {
	for _, l := range strings.Split(listing, "\n") {
		ok := true
		for _, m := range match {
			ok = ok && strings.Contains(l, m)
		}
		if f := strings.Fields(l); ok && len(f) > 0 {
			n, _ := strconv.Atoi(f[0])
			return n
		}
	}
	return -1
}

func reviewKernelNet(t *testing.T) *kernelNetwork {
	k, _ := kernelRig(t)
	if os.Getenv("AEROL_KT_CNI_DIR") == "" {
		k.leases = filepath.Join(t.TempDir(), "leases")
		if err := os.MkdirAll(k.leases, 0o755); err != nil {
			t.Fatal(err)
		}
		k.steps = k.stepsWith(&leasingRunner{Runner: k.steps.Runner, dir: k.leases, ips: map[string]string{}})
	}
	return k
}

func reviewHelper(t *testing.T, k *kernelNetwork, backend string) (*rig, rootdpb.RootHelperClient) {
	// A new helper process: netrules' process-wide registries start empty.
	netrules.ResetFloorsForTest()
	netrules.ResetBlockSetsForTest()
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		c.Firewall.Backend = backend
		o.Network = k
	})
	return r, rootdpb.NewRootHelperClient(r.conn)
}

// A helper restart on the real kernel: the new helper's floor is first and
// takes a sandbox's packets to the metadata endpoint, and a release before
// its first EnsureHost leaves the address out of the block sets. Backend
// from FWREV_BACKEND.
func TestKernelHelperRestartKeepsFloorAndBlockSets(t *testing.T) {
	needRoot(t)
	backend := os.Getenv("FWREV_BACKEND")
	if backend == "" {
		backend = "netlink"
	}
	k := reviewKernelNet(t)
	ctx := callCtx(t)
	floorChain := netrules.FloorChainFor(k.Subnet())

	// Helper 1: the agent's boot: host step, floor, then a create with
	// block-all (a sandbox whose policy is "no network").
	r1, c1 := reviewHelper(t, k, backend)
	if _, err := c1.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{}); err != nil {
		t.Fatal(err)
	}
	sb0, err := c1.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-0",
		Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}, Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}})
	if err != nil {
		t.Fatal(err)
	}
	ip0 := sb0.GetContainerIp()
	if f := firstRule(shell(t, "iptables", "-w", "-S", netrules.ChainAerolvmUser)); !strings.Contains(f, "-j "+floorChain) {
		t.Fatalf("helper 1: the floor's jump is not first: %q", f)
	}
	t.Logf("helper 1 blocked sets:\n%s", shell(t, "nft", "list", "table", "ip", "aerolvm_block"))

	// Helper 1 stops (a swap); helper 2 starts on the same kernel.
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	r1.srv.Shutdown(sctx)
	cancel()
	_, c2 := reviewHelper(t, k, backend)

	// The agent destroys sb-0 before its next EnsureHost tick (up to
	// ipv6fence.ReassertInterval after the swap).
	if _, err := c2.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-0", ContainerIp: ip0,
		Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}}); err != nil {
		t.Fatal(err)
	}
	if backend == "netlink" {
		sets := shell(t, "nft", "list", "set", "ip", "aerolvm_block", "blocked")
		t.Logf("after sb-0's release on helper 2:\n%s", sets)
		if strings.Contains(sets, ip0) {
			t.Errorf("sb-0 released (CNI DEL freed %s) with %s still in @blocked", ip0, ip0)
		}
	}

	// The agent's fence tick runs EnsureHost, then a create whose allowlist
	// names the metadata endpoint, which the floor drops regardless.
	if _, err := c2.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); err != nil {
		t.Fatal(err)
	}
	sb1, err := c2.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1",
		Parts:    []string{rootdpb.PartNetns, rootdpb.PartFirewall},
		Firewall: &rootdpb.SandboxFirewall{AllowCidrs: []string{"169.254.169.254/32"}}})
	if err != nil {
		t.Fatal(err)
	}
	user := shell(t, "iptables", "-w", "-S", netrules.ChainAerolvmUser)
	t.Logf("%s on helper 2:\n%s", netrules.ChainAerolvmUser, user)
	if f := firstRule(user); !strings.Contains(f, "-j "+floorChain) {
		t.Errorf("after a helper restart the floor's jump is not first: first rule %q", f)
	}
	// The floor in use: either of the subnet's two slots.
	active := firstRule(user)[strings.LastIndex(firstRule(user), " ")+1:]
	if os.Getenv("AEROL_KT_CNI_DIR") != "" {
		// A packet from sb-1 to the metadata endpoint: which rule takes it?
		_ = exec.Command("nsenter", "--net="+sb1.GetNetnsPath(), "--", "timeout", "2", "bash", "-c",
			"exec 3<>/dev/tcp/169.254.169.254/80").Run()
		u := shell(t, "iptables", "-w", "-L", netrules.ChainAerolvmUser, "-v", "-x", "-n")
		fl := shell(t, "iptables", "-w", "-L", active, "-v", "-x", "-n")
		t.Logf("counters:\n%s\n%s", u, fl)
		acc, drop := pkts(u, "ACCEPT", sb1.GetContainerIp(), "169.254.169.254"), pkts(fl, "DROP", "169.254.169.254")
		if drop <= 0 {
			t.Errorf("sb-1's packets to 169.254.169.254 never hit the floor's DROP (floor %d pkts, sb-1's ACCEPT %d pkts)", drop, acc)
		}
	}
	if _, err := c2.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: sb1.GetContainerIp(),
		Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}}); err != nil {
		t.Fatal(err)
	}
}

// A policy's kernel work is bounded: the biggest allowed goes in within
// seconds (one transaction per chunk of rules on netlink, the default) and
// one past the cap is refused before any write.
func TestKernelPolicySizeAndCostAreBounded(t *testing.T) {
	needRoot(t)
	k := reviewKernelNet(t)
	_, c := reviewHelper(t, k, "netlink")
	ctx := callCtx(t)
	if _, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{}); err != nil {
		t.Fatal(err)
	}
	list := func(n, salt int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%d.%d.%d.0/24", 11+salt, i/256, i%256)
		}
		return out
	}
	names := 0
	slot := func() string {
		names++
		name := fmt.Sprintf("sb-%d", names)
		r, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: name})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetContainerIp()
	}
	sizes := []int{256, 512, 1024}
	if s := os.Getenv("FWREV_SIZES"); s != "" {
		sizes = nil
		for _, f := range strings.Split(s, ",") {
			n, _ := strconv.Atoi(f)
			sizes = append(sizes, n)
		}
	}
	for i, n := range sizes {
		ip := slot()
		start := time.Now()
		_, err := c.SandboxRules(context.Background(), &rootdpb.SandboxRulesRequest{ContainerIp: ip,
			Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, AllowCidrs: list(n, i)})
		took := time.Since(start)
		t.Logf("allowlist of %d on %s: %v (err %v)", n, ip, took.Round(time.Millisecond), err)
		// One transaction per chunk: the biggest policy allowed goes in
		// within seconds, where it took over a minute rule by rule.
		if err == nil && took > 10*time.Second {
			t.Errorf("an allowlist of %d took %v", n, took)
		}
		// And comes out, so the next test's kernel is not this one's.
		start = time.Now()
		if _, err := c.SandboxRules(context.Background(), &rootdpb.SandboxRulesRequest{ContainerIp: ip,
			Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY}); err != nil {
			t.Fatalf("clear of %d: %v", n, err)
		}
		t.Logf("its clear: %v", time.Since(start).Round(time.Millisecond))
	}
	// Past the per-policy cap: refused, nothing written.
	if _, err := c.SandboxRules(context.Background(), &rootdpb.SandboxRulesRequest{ContainerIp: slot(),
		Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, AllowCidrs: list(rootpolicy.MaxPolicyCIDRs+1, 9)}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a policy past the cap = %v", err)
	}
}

// watchRules counts rule operations made while the floor chain holds no
// metadata DROP (after it first did).
type watchRules struct {
	*posRules
	floor   string
	meta    string
	armed   bool
	openOps int
}

// check follows the floor a packet meets: the chain the user chain's
// first rule jumps to (a replace moves the jump to the subnet's other
// floor chain).
func (w *watchRules) check() {
	if !w.armed {
		return
	}
	floor := w.floor
	if user := w.chain(netrules.ChainDockerUser); len(user) > 0 {
		if c, ok := strings.CutPrefix(user[0], "-j "); ok {
			floor = c
		}
	}
	if !slices.Contains(w.chain(floor), w.meta) {
		w.openOps++
	}
}

func (w *watchRules) Delete(table, chain string, spec ...string) error {
	err := w.posRules.Delete(table, chain, spec...)
	w.check()
	return err
}

func (w *watchRules) EnsureJumpChain(parent, child string) error {
	err := w.posRules.EnsureJumpChain(parent, child)
	w.check()
	return err
}
func (w *watchRules) Insert(table, chain string, pos int, spec ...string) error {
	err := w.posRules.Insert(table, chain, pos, spec...)
	w.check()
	return err
}
func (w *watchRules) FlushChain(chain string) error {
	err := w.posRules.FlushChain(chain)
	w.check()
	return err
}

// A floor change builds the new floor in the subnet's other chain and then
// moves the jump, so the floor a packet meets holds the metadata DROP at
// every kernel operation of the change.
func TestFloorChangeKeepsTheMetadataDrop(t *testing.T) {
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	w := &watchRules{posRules: newPosRules(), floor: netrules.FloorChainFor(subnet),
		meta: "-s 10.88.0.0/16 -d 169.254.169.254/32 -j DROP"}
	k := openWith(t, w)
	if _, err := k.SetFloor(nil); err != nil {
		t.Fatal(err)
	}
	w.armed = true
	list := make([]netip.Prefix, 4096)
	for i := range list {
		list[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i / 256), byte(i % 256), 0}), 24)
	}
	if _, err := k.SetFloor(list); err != nil {
		t.Fatal(err)
	}
	t.Logf("rule operations while the floor had no metadata DROP: %d", w.openOps)
	if w.openOps > 0 {
		t.Fatalf("SetEgressFloor left 169.254.169.254 off the floor for %d kernel operations", w.openOps)
	}
}

// The same on the real kernel: while the floor is changed again and again,
// a witness after the filter table counts packets to the metadata endpoint
// that got through; there must be none.
func TestKernelFloorChangeKeepsDropping(t *testing.T) {
	needRoot(t)
	if os.Getenv("AEROL_KT_CNI_DIR") == "" {
		t.Skip("needs the real CNI plugins (a routed sandbox)")
	}
	backend := os.Getenv("FWREV_BACKEND")
	if backend == "" {
		backend = "netlink"
	}
	k := reviewKernelNet(t)
	_, c := reviewHelper(t, k, backend)
	ctx := callCtx(t)
	if _, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{}); err != nil {
		t.Fatal(err)
	}
	sb, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"add table inet fwrevw", "add chain inet fwrevw wit { type filter hook forward priority 10 ; }",
		"add rule inet fwrevw wit ip daddr 169.254.169.254 counter"} {
		shell(t, "nft", strings.Fields(cmd)...)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "fwrevw").Run() })
	witness := func() string { return shell(t, "nft", "list", "chain", "inet", "fwrevw", "wit") }
	knock := func(d time.Duration) {
		_ = exec.Command("nsenter", "--net="+sb.GetNetnsPath(), "--", "bash", "-c",
			fmt.Sprintf("end=$((SECONDS+%d)); while [ $SECONDS -lt $end ]; do timeout 0.05 bash -c 'exec 3<>/dev/tcp/169.254.169.254/80' 2>/dev/null; done", int(d.Seconds()))).Run()
	}
	knock(2 * time.Second)
	t.Logf("witness with the floor in place:\n%s", witness())
	lists := [2][]string{}
	for n := range lists {
		lists[n] = make([]string, 4096)
		for i := range lists[n] {
			lists[n][i] = fmt.Sprintf("%d.%d.%d.0/24", 11+n, i/256, i%256)
		}
	}
	stop := make(chan struct{})
	done := make(chan int)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				done <- n
				return
			default:
			}
			start := time.Now()
			if _, err := c.SetEgressFloor(context.Background(), &rootdpb.SetEgressFloorRequest{Cidrs: lists[n%2]}); err != nil {
				t.Logf("SetEgressFloor: %v", err)
			}
			if n < 3 {
				t.Logf("SetEgressFloor of 4096 took %v", time.Since(start).Round(time.Millisecond))
			}
			n++
		}
	}()
	knock(8 * time.Second)
	close(stop)
	n := <-done
	// The node's floor back to the fixed one, and sb-1 gone, so the next
	// test's kernel is not this one's.
	defer func() {
		if _, err := c.SetEgressFloor(callCtx(t), &rootdpb.SetEgressFloorRequest{}); err != nil {
			t.Error(err)
		}
		if _, err := c.ReleaseSandbox(callCtx(t), &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: sb.GetContainerIp(),
			Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}}); err != nil {
			t.Error(err)
		}
	}()
	w := witness()
	t.Logf("after %d floor replacements, witness:\n%s", n, w)
	if strings.Contains(w, "counter packets") && !strings.Contains(w, "counter packets 0 ") {
		t.Errorf("packets from sb-1 to 169.254.169.254 got through while the floor changed")
	}
}

// A policy write stops at its caller's deadline: between rules on exec,
// between chunks on netlink; nothing lands after the call returned.
func TestKernelPolicyWriteStopsAtDeadline(t *testing.T) {
	needRoot(t)
	for _, tc := range []struct {
		backend  string
		deadline time.Duration
	}{{"netlink", 30 * time.Millisecond}, {"exec", 500 * time.Millisecond}} {
		t.Run(tc.backend, func(t *testing.T) {
			k := reviewKernelNet(t)
			_, c := reviewHelper(t, k, tc.backend)
			ctx := callCtx(t)
			if _, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); err != nil {
				t.Fatal(err)
			}
			r, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-dl-" + tc.backend})
			if err != nil {
				t.Fatal(err)
			}
			ip := r.GetContainerIp()
			list := make([]string, rootpolicy.MaxPolicyCIDRs)
			for i := range list {
				list[i] = fmt.Sprintf("21.%d.%d.0/24", i/256, i%256)
			}
			dctx, cancel := context.WithTimeout(context.Background(), tc.deadline)
			start := time.Now()
			_, err = c.SandboxRules(dctx, &rootdpb.SandboxRulesRequest{ContainerIp: ip,
				Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, AllowCidrs: list})
			took := time.Since(start)
			cancel()
			count := func() int {
				return strings.Count(shell(t, "iptables", "-w", "-S", netrules.ChainAerolvmUser), "-s "+ip+"/32")
			}
			time.Sleep(500 * time.Millisecond) // the write in flight lands
			at := count()
			time.Sleep(2 * time.Second)
			later := count()
			t.Logf("call with a %v deadline: %v after %v; rules %d, 2 s later %d", tc.deadline, status.Code(err), took.Round(time.Millisecond), at, later)
			if status.Code(err) == codes.OK {
				t.Skip("the whole policy went in within the deadline here")
			}
			if later > at {
				t.Fatalf("the helper kept writing for a call its caller abandoned (%d -> %d rules)", at, later)
			}
			// The release clears what did land.
			if _, err := c.SandboxRules(callCtx(t), &rootdpb.SandboxRulesRequest{ContainerIp: ip,
				Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY}); err != nil {
				t.Fatal(err)
			}
			if n := count(); n != 0 {
				t.Fatalf("%d rules left after the clear", n)
			}
		})
	}
}
