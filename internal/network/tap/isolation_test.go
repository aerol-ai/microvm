package tap

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeTables is an in-memory iptables: ordered rules per table/chain, with
// injectable failures per operation.
type fakeTables struct {
	chains map[string][][]string // "table/chain" -> rules
	fail   map[string]error      // operation name -> error
	calls  []string
}

func newFakeTables() *fakeTables {
	return &fakeTables{chains: map[string][][]string{
		"mangle/FORWARD": nil,
		"filter/FORWARD": nil,
	}, fail: map[string]error{}}
}

func (f *fakeTables) op(name string) error {
	f.calls = append(f.calls, name)
	return f.fail[name]
}

func (f *fakeTables) Exists(table, chain string, spec ...string) (bool, error) {
	if err := f.op("exists"); err != nil {
		return false, err
	}
	for _, r := range f.chains[table+"/"+chain] {
		if slices.Equal(r, spec) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeTables) Append(table, chain string, spec ...string) error {
	if err := f.op("append"); err != nil {
		return err
	}
	k := table + "/" + chain
	f.chains[k] = append(f.chains[k], slices.Clone(spec))
	return nil
}

func (f *fakeTables) Insert(table, chain string, pos int, spec ...string) error {
	if err := f.op("insert"); err != nil {
		return err
	}
	k := table + "/" + chain
	f.chains[k] = slices.Insert(f.chains[k], pos-1, slices.Clone(spec))
	return nil
}

func (f *fakeTables) ChainExists(table, chain string) (bool, error) {
	if err := f.op("chainExists"); err != nil {
		return false, err
	}
	_, ok := f.chains[table+"/"+chain]
	return ok, nil
}

func (f *fakeTables) NewChain(table, chain string) error {
	if err := f.op("newChain"); err != nil {
		return err
	}
	f.chains[table+"/"+chain] = nil
	return nil
}

// packet is what the evaluator below needs of a forwarded packet.
type packet struct {
	src, dst string
	proto    string // only for messages: no rule matches on protocol
	state    string // conntrack state: NEW, ESTABLISHED, RELATED
}

// forwardVerdict walks the mangle FORWARD hook as the kernel would for the
// rule shapes EnsureIsolation installs: -s/-d CIDR, conntrack [!] --ctstate,
// comment, and -j DROP or a jump to a user chain. "ACCEPT" means the packet
// leaves mangle FORWARD for the filter hook; the drops here are final there.
func (f *fakeTables) forwardVerdict(t *testing.T, p packet) string {
	t.Helper()
	var walk func(chain string, depth int) (string, bool)
	walk = func(chain string, depth int) (string, bool) {
		if depth > 4 {
			t.Fatalf("jump loop at %s", chain)
		}
		for _, r := range f.chains["mangle/"+chain] {
			target, ok := ruleMatches(t, r, p)
			if !ok {
				continue
			}
			switch target {
			case "DROP", "ACCEPT":
				return target, true
			case "RETURN":
				return "", false
			default:
				if v, done := walk(target, depth+1); done {
					return v, true
				}
			}
		}
		return "", false
	}
	if v, done := walk("FORWARD", 0); done {
		return v
	}
	return "ACCEPT"
}

func ruleMatches(t *testing.T, r []string, p packet) (target string, ok bool) {
	t.Helper()
	inCIDR := func(addr, cidr string) bool {
		pfx := netip.MustParsePrefix(cidr)
		return pfx.Contains(netip.MustParseAddr(addr))
	}
	for i := 0; i < len(r); i++ {
		switch r[i] {
		case "-s":
			i++
			if !inCIDR(p.src, r[i]) {
				return "", false
			}
		case "-d":
			i++
			if !inCIDR(p.dst, r[i]) {
				return "", false
			}
		case "-m":
			i++ // module name; its options follow
		case "--comment":
			i++
		case "!":
			if r[i+1] != "--ctstate" {
				t.Fatalf("unsupported negation in %v", r)
			}
			i += 2
			if slices.Contains(strings.Split(r[i], ","), p.state) {
				return "", false
			}
		case "--ctstate":
			i++
			if !slices.Contains(strings.Split(r[i], ","), p.state) {
				return "", false
			}
		case "-j":
			i++
			target = r[i]
		default:
			t.Fatalf("unsupported token %q in %v", r[i], r)
		}
	}
	return target, true
}

// TestEnsureIsolationDropsGuestToGuestAndCrossRuntime is the network half of
// the Firecracker toolbox fix and the UC-318 ICMP finding: with the TAP
// subnet 172.16.0.0/16, guests on two /30s and a container on the containerd
// bridge (10.88.0.0/16), no guest reaches another in any protocol, nothing
// on a bridge opens a connection into a guest (port 2280 included), and a
// guest's own egress and its replies keep flowing.
func TestEnsureIsolationDropsGuestToGuestAndCrossRuntime(t *testing.T) {
	f := newFakeTables()
	// Something else already sits in mangle FORWARD; ours goes on top.
	f.chains["mangle/FORWARD"] = [][]string{{"-j", "SOMEONE-ELSE"}}
	f.chains["mangle/SOMEONE-ELSE"] = [][]string{{"-j", "RETURN"}}
	if err := EnsureIsolation(f, "172.16.9.9/16"); err != nil {
		t.Fatal(err)
	}
	if got := f.chains["mangle/FORWARD"][0]; !slices.Equal(got, []string{"-j", IsolationChain}) {
		t.Fatalf("first mangle FORWARD rule = %v, want the isolation jump", got)
	}
	if len(f.chains["filter/FORWARD"]) != 0 {
		t.Fatal("the isolation must not live in filter, where an ACCEPT above it would skip it")
	}

	const (
		guestA    = "172.16.0.2"
		guestB    = "172.16.0.6"
		hostEndB  = "172.16.0.5"
		container = "10.88.0.7"
		gvisor    = "10.88.0.9"
		docker    = "172.17.0.3"
		internet  = "93.184.216.34"
	)
	for _, tc := range []struct {
		name string
		p    packet
		want string
	}{
		{"guest to guest, ICMP echo", packet{guestA, guestB, "icmp", "NEW"}, "DROP"},
		{"guest to guest, TCP to the toolbox port", packet{guestA, guestB, "tcp/2280", "NEW"}, "DROP"},
		{"guest to guest, UDP", packet{guestA, guestB, "udp", "NEW"}, "DROP"},
		{"guest to guest, a flow conntrack calls established", packet{guestA, guestB, "tcp", "ESTABLISHED"}, "DROP"},
		{"guest to another guest's host end", packet{guestA, hostEndB, "icmp", "NEW"}, "DROP"},
		{"container to guest, TCP to the toolbox port", packet{container, guestB, "tcp/2280", "NEW"}, "DROP"},
		{"container to guest, ICMP echo", packet{container, guestB, "icmp", "NEW"}, "DROP"},
		{"gVisor sandbox to guest", packet{gvisor, guestB, "tcp/2280", "NEW"}, "DROP"},
		{"docker container to guest", packet{docker, guestB, "tcp/8080", "NEW"}, "DROP"},
		{"spoofed guest source from a container", packet{guestA, guestB, "tcp/2280", "NEW"}, "DROP"},
		{"the internet opening into a guest", packet{internet, guestB, "tcp/22", "NEW"}, "DROP"},
		{"guest egress", packet{guestB, internet, "tcp/443", "NEW"}, "ACCEPT"},
		{"the reply to guest egress", packet{internet, guestB, "tcp/443", "ESTABLISHED"}, "ACCEPT"},
		{"an ICMP error about guest egress", packet{internet, guestB, "icmp", "RELATED"}, "ACCEPT"},
		{"container egress, untouched", packet{container, internet, "tcp/443", "NEW"}, "ACCEPT"},
		{"container to container, left to the container chains", packet{container, gvisor, "tcp", "NEW"}, "ACCEPT"},
	} {
		if got := f.forwardVerdict(t, tc.p); got != tc.want {
			t.Errorf("%s (%s %s->%s %s) = %s, want %s", tc.name, tc.p.proto, tc.p.src, tc.p.dst, tc.p.state, got, tc.want)
		}
	}
}

// Re-running converges: no duplicate rule or jump, and a flushed table is put
// back. It is what the reassert tick calls.
func TestEnsureIsolationIsIdempotent(t *testing.T) {
	f := newFakeTables()
	for i := 0; i < 3; i++ {
		if err := EnsureIsolation(f, "172.16.0.0/16"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.chains["mangle/FORWARD"]); n != 1 {
		t.Fatalf("mangle FORWARD has %d rules after 3 runs, want 1", n)
	}
	if n := len(f.chains["mangle/"+IsolationChain]); n != 2 {
		t.Fatalf("isolation chain has %d rules after 3 runs, want 2", n)
	}
	// Something flushed mangle FORWARD: the next run puts the jump back.
	f.chains["mangle/FORWARD"] = nil
	delete(f.chains, "mangle/"+IsolationChain)
	if err := EnsureIsolation(f, "172.16.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if v := f.forwardVerdict(t, packet{"172.16.0.2", "172.16.0.6", "icmp", "NEW"}); v != "DROP" {
		t.Fatalf("after a flush and reassert, guest to guest = %s", v)
	}
}

func TestEnsureIsolationErrors(t *testing.T) {
	for _, bad := range []string{"", "nope", "fd00::/64"} {
		if err := EnsureIsolation(newFakeTables(), bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	for _, op := range []string{"chainExists", "newChain", "exists", "append", "insert"} {
		f := newFakeTables()
		f.fail[op] = errors.New("iptables: boom")
		err := EnsureIsolation(f, "172.16.0.0/16")
		if err == nil || !strings.Contains(err.Error(), "tap isolation") {
			t.Fatalf("%s failure: err = %v", op, err)
		}
	}
	// The jump check fails only after the chain rules were checked.
	f := newFakeTables()
	n := 0
	f.fail = map[string]error{}
	wrapped := &countingExists{fakeTables: f, failOn: 3, n: &n}
	if err := EnsureIsolation(wrapped, "172.16.0.0/16"); err == nil || !strings.Contains(err.Error(), "FORWARD jump") {
		t.Fatalf("jump check failure: err = %v", err)
	}
}

// countingExists fails the failOn-th Exists call.
type countingExists struct {
	*fakeTables
	failOn int
	n      *int
}

func (c *countingExists) Exists(table, chain string, spec ...string) (bool, error) {
	*c.n++
	if *c.n == c.failOn {
		return false, errors.New("iptables: boom")
	}
	return c.fakeTables.Exists(table, chain, spec...)
}
