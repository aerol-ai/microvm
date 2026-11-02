package netrules

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// chainBackend is an ordered, chain-aware RuleBackend that can also run a
// packet through the filter table, so the node guard is tested by what a
// packet meets, not only by which rules exist. It implements every optional
// backend interface the way the netlink backend does (EnsureJumpChain moves
// the jump to the top and drops lower copies).
type chainBackend struct {
	mu     sync.Mutex
	chains map[string][]string
	// fail injects an error into the named operation ("Insert:<chain>",
	// "Exists:<chain>", "Delete:<chain>", "Flush:<chain>", "UserChain:<chain>",
	// "InputChain", "JumpChain").
	fail map[string]error
	// onInsert runs after each insert, outside the lock (a probe mid-swap).
	onInsert func(chain string, spec []string)
}

func newChainBackend() *chainBackend {
	return &chainBackend{chains: map[string][]string{"INPUT": nil}, fail: map[string]error{}}
}

var establishedRule = strings.Join(inputEstablishedReturn, " ")

func (c *chainBackend) err(op string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fail[op]
}

func (c *chainBackend) Exists(_, chain string, spec ...string) (bool, error) {
	if err := c.err("Exists:" + chain); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// iptables -C exits 2 (an error, not "absent") when the rule jumps to a
	// chain that does not exist: the guard must create its chains first.
	if i := slices.Index(spec, "-j"); i >= 0 && i+1 < len(spec) && strings.HasPrefix(spec[i+1], ownChainPrefix) {
		if _, ok := c.chains[spec[i+1]]; !ok {
			return false, fmt.Errorf("Chain '%s' does not exist", spec[i+1])
		}
	}
	return slices.Contains(c.chains[chain], strings.Join(spec, " ")), nil
}

func (c *chainBackend) Insert(_, chain string, pos int, spec ...string) error {
	if err := c.err("Insert:" + chain); err != nil {
		return err
	}
	c.mu.Lock()
	rules, ok := c.chains[chain]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("no chain %s", chain)
	}
	i := min(max(pos-1, 0), len(rules))
	c.chains[chain] = slices.Insert(rules, i, strings.Join(spec, " "))
	hook := c.onInsert
	c.mu.Unlock()
	if hook != nil {
		hook(chain, spec)
	}
	return nil
}

func (c *chainBackend) Delete(_, chain string, spec ...string) error {
	if err := c.err("Delete:" + chain); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := slices.Index(c.chains[chain], strings.Join(spec, " ")); i >= 0 {
		c.chains[chain] = slices.Delete(c.chains[chain], i, i+1)
		return nil
	}
	return errNoMatch{}
}

func (c *chainBackend) EnsureUserChain(chain string) error {
	if err := c.err("UserChain:" + chain); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.chains[chain]; !ok {
		c.chains[chain] = []string{}
	}
	return nil
}

func (c *chainBackend) EnsureForwardJump(string) error { return nil }

// EnsureInputChain is the exec backend's contract: the chain, its
// established-return first rule, and an INPUT jump somewhere.
func (c *chainBackend) EnsureInputChain(chain string) error {
	if err := c.err("InputChain"); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.chains[chain], establishedRule) {
		c.chains[chain] = slices.Insert(c.chains[chain], 0, establishedRule)
	}
	if !slices.Contains(c.chains["INPUT"], "-j "+chain) {
		c.chains["INPUT"] = slices.Insert(c.chains["INPUT"], 0, "-j "+chain)
	}
	return nil
}

func (c *chainBackend) EnsureJumpChain(parent, child string) error {
	if err := c.err("JumpChain"); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	jump := "-j " + child
	if _, ok := c.chains[child]; !ok {
		c.chains[child] = []string{}
	}
	rest := slices.DeleteFunc(slices.Clone(c.chains[parent]), func(r string) bool { return r == jump })
	c.chains[parent] = slices.Insert(rest, 0, jump)
	return nil
}

func (c *chainBackend) FlushChain(chain string) error {
	if err := c.err("Flush:" + chain); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chains[chain] = []string{}
	return nil
}

func (c *chainBackend) rules(chain string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.chains[chain])
}

func (c *chainBackend) setRules(chain string, rules ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chains[chain] = rules
}

// packet is what the evaluator matches on.
type packet struct {
	src, dst    string
	proto       string
	port        int
	established bool
}

// verdict runs p through INPUT: "DROP", or "PASS" when INPUT ends without a
// drop (the policy and any host firewall decide from there).
func (c *chainBackend) verdict(t *testing.T, p packet) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	v, _ := c.walk(t, "INPUT", p, 0)
	if v == "DROP" {
		return "DROP"
	}
	return "PASS"
}

// walk returns "DROP", "ACCEPT", or "" when the chain ran out or returned.
func (c *chainBackend) walk(t *testing.T, chain string, p packet, depth int) (string, bool) {
	if depth > 8 {
		t.Fatalf("jump loop at %s", chain)
	}
	for _, r := range c.chains[chain] {
		if r == establishedRule {
			if p.established {
				return "", true
			}
			continue
		}
		toks := strings.Fields(r)
		match, target := true, ""
		for i := 0; i < len(toks); i++ {
			switch toks[i] {
			case "-s":
				i++
				match = match && inPrefix(toks[i], p.src)
			case "-d":
				i++
				match = match && inPrefix(toks[i], p.dst)
			case "-p":
				i++
				match = match && toks[i] == p.proto
			case "--dport":
				i++
				match = match && toks[i] == strconv.Itoa(p.port)
			case "-m":
				i += 3 // comment --comment <tag>
			case "-j":
				i++
				target = toks[i]
			default:
				t.Fatalf("evaluator: unknown token %q in %q", toks[i], r)
			}
		}
		if !match {
			continue
		}
		switch target {
		case "DROP", "ACCEPT":
			return target, true
		case "RETURN":
			return "", true
		default:
			if v, _ := c.walk(t, target, p, depth+1); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

func inPrefix(spec, addr string) bool {
	a := netip.MustParseAddr(addr)
	if pfx, err := netip.ParsePrefix(spec); err == nil {
		return pfx.Contains(a)
	}
	return netip.MustParseAddr(spec) == a
}

var (
	dockerBridge = netip.MustParsePrefix("172.17.0.0/16")
	cniBridge    = netip.MustParsePrefix("10.88.0.0/16")
	tapPool      = netip.MustParsePrefix("172.16.0.0/16")
	gatewayAllow = []NodePort{{Proto: "udp", Port: 53054}, {Proto: "tcp", Port: 53054}, {Proto: "tcp", Port: 15080}}
)

// TestSetNodeGuardRuleShape: the INPUT jump is first, AEROLVM-NODE returns
// established traffic before any subnet jump, and the subnet's chain lists
// the allowlist in order with the drop last.
func TestSetNodeGuardRuleShape(t *testing.T) {
	be := newChainBackend()
	be.setRules("INPUT", "-j ufw-before-input")
	m := NewWithBackend(be)
	allow := append(slices.Clone(gatewayAllow), NodePort{Proto: "udp", Port: 53, Dst: netip.MustParseAddr("10.0.1.5")})
	if err := m.SetNodeGuard(netip.MustParsePrefix("172.17.3.4/16"), allow); err != nil {
		t.Fatal(err)
	}
	chains := NodeChainsFor(dockerBridge)
	if got := be.rules("INPUT"); got[0] != "-j "+ChainAerolvmNode {
		t.Fatalf("the guard must be the first thing INPUT does: %q", got)
	}
	if got, want := be.rules(ChainAerolvmNode), []string{establishedRule, "-s 172.17.0.0/16 -j " + chains[0]}; !slices.Equal(got, want) {
		t.Fatalf("AEROLVM-NODE = %q, want %q", got, want)
	}
	want := []string{
		"-s 172.17.0.0/16 -p udp --dport 53054 -m comment --comment sbx-node-guard -j RETURN",
		"-s 172.17.0.0/16 -p tcp --dport 53054 -m comment --comment sbx-node-guard -j RETURN",
		"-s 172.17.0.0/16 -p tcp --dport 15080 -m comment --comment sbx-node-guard -j RETURN",
		"-s 172.17.0.0/16 -d 10.0.1.5 -p udp --dport 53 -m comment --comment sbx-node-guard -j RETURN",
		"-s 172.17.0.0/16 -m comment --comment sbx-node-guard -j DROP",
	}
	if got := be.rules(chains[0]); !slices.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", chains[0], got, want)
	}
	if got := be.rules(chains[1]); len(got) != 0 {
		t.Fatalf("the idle chain must be empty: %q", got)
	}
	// Every rule the guard writes is one the netlink backend can express.
	for _, c := range []string{ChainAerolvmNode, chains[0]} {
		for _, r := range be.rules(c) {
			if r == establishedRule {
				continue
			}
			if _, err := parseRulespec(strings.Fields(r)...); err != nil {
				t.Errorf("rule %q does not parse: %v", r, err)
			}
		}
	}
}

// TestNodeGuardVerdicts: what a packet from a sandbox meets at the node.
func TestNodeGuardVerdicts(t *testing.T) {
	be := newChainBackend()
	m := NewWithBackend(be)
	allow := append(slices.Clone(gatewayAllow),
		NodePort{Proto: "tcp", Port: 443},
		NodePort{Proto: "udp", Port: 53, Dst: netip.MustParseAddr("10.0.1.5")})
	if err := m.SetNodeGuard(dockerBridge, allow); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		p    packet
		want string
	}{
		{"node exporter on the bridge gateway", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "tcp", port: 9100}, "DROP"},
		{"node exporter on the private address", packet{src: "172.17.0.5", dst: "10.0.1.5", proto: "tcp", port: 9100}, "DROP"},
		{"SIEM forwarder over udp", packet{src: "172.17.0.5", dst: "10.0.1.5", proto: "udp", port: 514}, "DROP"},
		{"operator ssh", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "tcp", port: 22}, "DROP"},
		{"sandboxd API", packet{src: "172.17.0.5", dst: "10.0.1.5", proto: "tcp", port: 21212}, "DROP"},
		{"gateway proxy", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "tcp", port: 15080}, "PASS"},
		{"gateway DNS over udp", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "udp", port: 53054}, "PASS"},
		{"gateway proxy port over udp is not a thing", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "udp", port: 15080}, "DROP"},
		{"ingress", packet{src: "172.17.0.5", dst: "10.0.1.5", proto: "tcp", port: 443}, "PASS"},
		{"the resolver the sandbox was given", packet{src: "172.17.0.5", dst: "10.0.1.5", proto: "udp", port: 53}, "PASS"},
		{"dns on another node address", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "udp", port: 53}, "DROP"},
		{"a toolbox reply to sandboxd", packet{src: "172.17.0.5", dst: "172.17.0.1", proto: "tcp", port: 41234, established: true}, "PASS"},
		{"not a sandbox", packet{src: "10.0.2.9", dst: "10.0.1.5", proto: "tcp", port: 9100}, "PASS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := be.verdict(t, tc.p); got != tc.want {
				t.Fatalf("%+v: %s, want %s", tc.p, got, tc.want)
			}
		})
	}
}

// TestSetNodeGuardSwapNeverOpens: a new allowlist is built in the idle
// chain, the jump moves, the old chain empties; at no step does a port that
// neither list allows get through.
func TestSetNodeGuardSwapNeverOpens(t *testing.T) {
	be := newChainBackend()
	m := NewWithBackend(be)
	if err := m.SetNodeGuard(cniBridge, gatewayAllow); err != nil {
		t.Fatal(err)
	}
	denied := packet{src: "10.88.0.7", dst: "10.88.0.1", proto: "tcp", port: 9100}
	steps := 0
	be.onInsert = func(string, []string) {
		steps++
		if got := be.verdict(t, denied); got != "DROP" {
			t.Errorf("step %d of the swap let a denied port through", steps)
		}
	}
	added := append(slices.Clone(gatewayAllow), NodePort{Proto: "tcp", Port: 8443})
	if err := m.SetNodeGuard(cniBridge, added); err != nil {
		t.Fatal(err)
	}
	be.onInsert = nil
	chains := NodeChainsFor(cniBridge)
	if got := be.rules(ChainAerolvmNode); !slices.Equal(got, []string{establishedRule, "-s 10.88.0.0/16 -j " + chains[1]}) {
		t.Fatalf("the jump must move to the idle chain: %q", got)
	}
	if len(be.rules(chains[0])) != 0 {
		t.Fatalf("the old chain must be emptied: %q", be.rules(chains[0]))
	}
	if be.verdict(t, packet{src: "10.88.0.7", dst: "10.88.0.1", proto: "tcp", port: 8443}) != "PASS" {
		t.Fatal("the new port must be open after the swap")
	}
	// And back: the third list lands in the first chain again.
	if err := m.SetNodeGuard(cniBridge, gatewayAllow); err != nil {
		t.Fatal(err)
	}
	if be.rules(ChainAerolvmNode)[1] != "-s 10.88.0.0/16 -j "+chains[0] || be.verdict(t, packet{src: "10.88.0.7", dst: "10.88.0.1", proto: "tcp", port: 8443}) != "DROP" {
		t.Fatalf("a removed port must close: %q", be.rules(ChainAerolvmNode))
	}
	// A daemon that died mid-swap left both jumps: the next set still ends
	// with exactly one, and the denied port stays closed throughout.
	be.setRules(ChainAerolvmNode, establishedRule, "-s 10.88.0.0/16 -j "+chains[1], "-s 10.88.0.0/16 -j "+chains[0])
	if err := m.SetNodeGuard(cniBridge, gatewayAllow); err != nil {
		t.Fatal(err)
	}
	if n := len(be.rules(ChainAerolvmNode)); n != 2 || be.verdict(t, denied) != "DROP" {
		t.Fatalf("after a half-finished swap: %q", be.rules(ChainAerolvmNode))
	}
}

// TestReassertNodeGuard: an intact guard is left alone; one a flush or a
// host firewall reload took away comes back.
func TestReassertNodeGuard(t *testing.T) {
	denied := packet{src: "172.16.0.6", dst: "172.16.0.5", proto: "tcp", port: 9100}
	cases := []struct {
		name   string
		break_ func(be *chainBackend)
	}{
		{"subnet chain flushed", func(be *chainBackend) { be.setRules(NodeChainsFor(tapPool)[0]) }},
		{"guard chain flushed", func(be *chainBackend) { be.setRules(ChainAerolvmNode) }},
		{"whole table flushed", func(be *chainBackend) {
			for c := range be.chains {
				be.chains[c] = []string{}
			}
		}},
		{"chains deleted", func(be *chainBackend) {
			be.chains = map[string][]string{"INPUT": {}}
		}},
		{"INPUT rewritten above the guard", func(be *chainBackend) { be.setRules("INPUT", "-s 172.16.0.0/16 -j ACCEPT") }},
		{"drop rule deleted", func(be *chainBackend) {
			c := NodeChainsFor(tapPool)[0]
			be.setRules(c, slices.DeleteFunc(be.rules(c), func(r string) bool { return strings.HasSuffix(r, "DROP") })...)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newChainBackend()
			m := NewWithBackend(be)
			if repaired, err := m.ReassertNodeGuard(); repaired || err != nil {
				t.Fatalf("before any set it is a no-op: %v %v", repaired, err)
			}
			if err := m.SetNodeGuard(tapPool, gatewayAllow); err != nil {
				t.Fatal(err)
			}
			if repaired, err := m.ReassertNodeGuard(); repaired || err != nil {
				t.Fatalf("an intact guard is not rebuilt: %v %v", repaired, err)
			}
			tc.break_(be)
			repaired, err := m.ReassertNodeGuard()
			if err != nil {
				t.Fatal(err)
			}
			if got := be.verdict(t, denied); got != "DROP" {
				t.Fatalf("after re-assert the denied port is %s (repaired=%v)\nINPUT=%q\nNODE=%q", got, repaired, be.rules("INPUT"), be.rules(ChainAerolvmNode))
			}
			if be.rules("INPUT")[0] != "-j "+ChainAerolvmNode {
				t.Fatalf("the INPUT jump must be first again: %q", be.rules("INPUT"))
			}
			if be.verdict(t, packet{src: "172.16.0.6", dst: "172.16.0.5", proto: "tcp", port: 15080}) != "PASS" {
				t.Fatal("the allowlist must come back with the guard")
			}
		})
	}
}

// TestNodeGuardsOfSeveralRuntimesCoexist: docker, containerd and
// Firecracker each guard their own subnet through the one AEROLVM-NODE
// chain; changing one runtime's guard leaves the others alone.
func TestNodeGuardsOfSeveralRuntimesCoexist(t *testing.T) {
	be := newChainBackend()
	docker, ctd, fc := NewWithBackend(be), NewWithBackend(be), NewWithBackend(be)
	ctd.userChain, fc.userChain = ChainAerolvmUser, ChainAerolvmFC
	seen := map[string]bool{}
	for _, sn := range []netip.Prefix{dockerBridge, cniBridge, tapPool} {
		for _, c := range NodeChainsFor(sn) {
			if seen[c] || len(c) > 28 {
				t.Fatalf("chain %q collides or is too long for iptables", c)
			}
			seen[c] = true
		}
	}
	for _, step := range []struct {
		m  *Manager
		sn netip.Prefix
	}{{docker, dockerBridge}, {ctd, cniBridge}, {fc, tapPool}} {
		if err := step.m.SetNodeGuard(step.sn, gatewayAllow); err != nil {
			t.Fatal(err)
		}
	}
	// Replacing containerd's (a new port) must leave the other two intact.
	if err := ctd.SetNodeGuard(cniBridge, []NodePort{{Proto: "tcp", Port: 8443}}); err != nil {
		t.Fatal(err)
	}
	if n := len(be.rules(ChainAerolvmNode)); n != 4 {
		t.Fatalf("one established-return and one jump per subnet: %q", be.rules(ChainAerolvmNode))
	}
	for _, tc := range []struct {
		p    packet
		want string
	}{
		{packet{src: "172.17.0.2", dst: "172.17.0.1", proto: "tcp", port: 9100}, "DROP"},
		{packet{src: "172.17.0.2", dst: "10.88.0.1", proto: "tcp", port: 15080}, "PASS"},
		{packet{src: "10.88.0.9", dst: "10.88.0.1", proto: "tcp", port: 15080}, "DROP"},
		{packet{src: "10.88.0.9", dst: "172.17.0.1", proto: "tcp", port: 8443}, "PASS"},
		{packet{src: "172.16.0.10", dst: "172.16.0.9", proto: "tcp", port: 9100}, "DROP"},
		{packet{src: "172.16.0.10", dst: "172.16.0.9", proto: "udp", port: 53054}, "PASS"},
	} {
		if got := be.verdict(t, tc.p); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.p, got, tc.want)
		}
	}
}

// TestSetNodeGuardErrors: nothing pretends a guard is in place.
func TestSetNodeGuardErrors(t *testing.T) {
	var nilMgr *Manager
	if err := nilMgr.SetNodeGuard(dockerBridge, nil); !errors.Is(err, ErrNodeGuardDisabled) {
		t.Fatalf("nil manager: %v", err)
	}
	if r, err := nilMgr.ReassertNodeGuard(); r || err != nil {
		t.Fatal("nil manager re-assert is a no-op")
	}
	if err := (&Manager{}).SetNodeGuard(dockerBridge, nil); !errors.Is(err, ErrNodeGuardDisabled) {
		t.Fatalf("disabled manager: %v", err)
	}
	if err := NewWithBackend(&memBackend{}).SetNodeGuard(dockerBridge, nil); !errors.Is(err, ErrNodeGuardUnsupported) {
		t.Fatalf("a backend without chain management: %v", err)
	}
	m := NewWithBackend(newChainBackend())
	for _, bad := range []struct {
		sn    netip.Prefix
		allow []NodePort
	}{
		{netip.Prefix{}, nil},
		{netip.MustParsePrefix("fd00::/64"), nil},
		{dockerBridge, []NodePort{{Proto: "sctp", Port: 1}}},
		{dockerBridge, []NodePort{{Proto: "tcp"}}},
		{dockerBridge, []NodePort{{Proto: "udp", Port: 53, Dst: netip.MustParseAddr("fd00::1")}}},
	} {
		if err := m.SetNodeGuard(bad.sn, bad.allow); err == nil {
			t.Errorf("SetNodeGuard(%v, %v) must fail", bad.sn, bad.allow)
		}
	}
	chains := NodeChainsFor(dockerBridge)
	for _, op := range []string{
		"InputChain", "JumpChain", "Exists:" + ChainAerolvmNode, "UserChain:" + chains[0],
		"Flush:" + chains[0], "Insert:" + chains[0], "Insert:" + ChainAerolvmNode, "Delete:" + ChainAerolvmNode, "Flush:" + chains[1],
	} {
		be := newChainBackend()
		be.fail[op] = errors.New("boom " + op)
		if op == "Delete:"+ChainAerolvmNode {
			// deleteUntilGone treats an unrecognized error as fatal only
			// when the rule is still there, which a probe confirms.
			be.chains[ChainAerolvmNode] = []string{establishedRule, "-s 172.17.0.0/16 -j " + chains[1]}
		}
		if err := NewWithBackend(be).SetNodeGuard(dockerBridge, gatewayAllow); err == nil {
			t.Errorf("an error in %s must surface", op)
		}
	}
	// A guard with an allowlist entry: its insert can fail too.
	be := newChainBackend()
	be.onInsert = func(chain string, spec []string) {
		if slices.Contains(spec, "RETURN") {
			be.fail["Insert:"+chain] = errors.New("boom")
		}
	}
	be.fail = map[string]error{}
	failing := NewWithBackend(be)
	if err := failing.SetNodeGuard(dockerBridge, append(slices.Clone(gatewayAllow), NodePort{Proto: "tcp", Port: 1})); err == nil {
		t.Error("a failed allowlist insert must surface")
	}
	// Re-assert reports what it could not check, and a backend that lost
	// chain management.
	be2 := newChainBackend()
	m2 := NewWithBackend(be2)
	if err := m2.SetNodeGuard(dockerBridge, gatewayAllow); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"InputChain", "Exists:" + ChainAerolvmNode, "Exists:" + chains[0]} {
		be2.fail = map[string]error{op: errors.New("boom")}
		if _, err := m2.ReassertNodeGuard(); err == nil {
			t.Errorf("re-assert must surface %s", op)
		}
	}
	be2.fail = map[string]error{}
	m2.ipt = &memBackend{}
	if _, err := m2.ReassertNodeGuard(); !errors.Is(err, ErrNodeGuardUnsupported) {
		t.Fatalf("re-assert on a plain backend: %v", err)
	}
	if r, err := (&Manager{}).ReassertNodeGuard(); r || err != nil {
		t.Fatal("a disabled manager has nothing to re-assert")
	}
}

func TestNodePortString(t *testing.T) {
	for p, want := range map[NodePort]string{
		{Proto: "tcp", Port: 15080}:                                    "tcp/15080",
		{Proto: "udp", Port: 53, Dst: netip.MustParseAddr("10.0.1.5")}: "udp/53@10.0.1.5",
	} {
		if p.String() != want {
			t.Errorf("%v.String() = %q, want %q", p, p.String(), want)
		}
	}
	a, b := NodeChainsFor(netip.MustParsePrefix("10.88.1.2/16")), NodeChainsFor(cniBridge)
	if a != b || a[0] == a[1] || !strings.HasPrefix(a[0], ChainAerolvmNode+"-") {
		t.Fatalf("chains are keyed by the masked subnet: %v %v", a, b)
	}
}
