package hostport

import (
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// memBackend is an in-memory iptables that NORMALIZES rules the way real
// iptables lists them ("-m tcp" after "-p tcp", "-d ip/32"), so a
// text-vs-meaning bug in Reconcile shows up here instead of on a host.
type memBackend struct {
	mu      sync.Mutex
	chains  map[string][]string // "table/chain" → normalized specs, in order
	failOn  string              // op name to fail, for error paths
	appends int
	deletes int
}

// Tests never touch the host sysctl: CI runs on linux without root.
var ipForwardCalls int

func TestMain(m *testing.M) {
	enableIPForward = func() error { ipForwardCalls++; return nil }
	os.Exit(m.Run())
}

func newMem() *memBackend {
	return &memBackend{chains: map[string][]string{
		"nat/PREROUTING": nil, "nat/OUTPUT": nil, "nat/POSTROUTING": nil, "filter/FORWARD": nil,
	}}
}

func normalize(spec []string) string {
	var out []string
	for i := 0; i < len(spec); i++ {
		out = append(out, spec[i])
		if spec[i] == "-p" && i+1 < len(spec) && spec[i+1] == "tcp" {
			out = append(out, "tcp", "-m", "tcp")
			i++
			continue
		}
		if spec[i] == "-d" && i+1 < len(spec) && !strings.Contains(spec[i+1], "/") {
			out = append(out, spec[i+1]+"/32")
			i++
		}
	}
	return strings.Join(out, " ")
}

func (m *memBackend) fail(op string) error {
	if m.failOn == op {
		return errors.New(op + " failed")
	}
	return nil
}

func (m *memBackend) ChainExists(table, chain string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ChainExists"); err != nil {
		return false, err
	}
	_, ok := m.chains[table+"/"+chain]
	return ok, nil
}

func (m *memBackend) NewChain(table, chain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("NewChain"); err != nil {
		return err
	}
	m.chains[table+"/"+chain] = []string{}
	return nil
}

func (m *memBackend) Exists(table, chain string, spec ...string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Exists"); err != nil {
		return false, err
	}
	n := normalize(spec)
	for _, r := range m.chains[table+"/"+chain] {
		if r == n {
			return true, nil
		}
	}
	return false, nil
}

func (m *memBackend) Insert(table, chain string, pos int, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Insert"); err != nil {
		return err
	}
	k := table + "/" + chain
	m.chains[k] = append([]string{normalize(spec)}, m.chains[k]...)
	return nil
}

func (m *memBackend) Append(table, chain string, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Append"); err != nil {
		return err
	}
	k := table + "/" + chain
	m.chains[k] = append(m.chains[k], normalize(spec))
	m.appends++
	return nil
}

func (m *memBackend) Delete(table, chain string, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Delete"); err != nil {
		return err
	}
	k := table + "/" + chain
	n := normalize(spec)
	for i, r := range m.chains[k] {
		if r == n || r == strings.Join(spec, " ") {
			m.chains[k] = append(m.chains[k][:i], m.chains[k][i+1:]...)
			m.deletes++
			return nil
		}
	}
	return errors.New("no such rule")
}

func (m *memBackend) List(table, chain string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("List"); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range m.chains[table+"/"+chain] {
		out = append(out, "-A "+chain+" "+r)
	}
	return out, nil
}

func (m *memBackend) rules(table, chain string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.chains[table+"/"+chain]...)
}

type flushLog struct {
	mu    sync.Mutex
	ports []int
}

func (f *flushLog) flush(hp int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports = append(f.ports, hp)
	return nil
}

func dnat(addr string, masq bool) Target {
	return Target{Kind: DNAT, Addr: netip.MustParseAddrPort(addr), Masquerade: masq}
}

func TestForwarderBootstrapsChainsAndJumpsOnce(t *testing.T) {
	m := newMem()
	f := New(m, nil)
	for i := 0; i < 2; i++ {
		if err := f.Ensure(22000, dnat("10.0.0.5:5432", false)); err != nil {
			t.Fatal(err)
		}
	}
	for _, j := range []string{"nat/PREROUTING", "nat/OUTPUT", "nat/POSTROUTING", "filter/FORWARD"} {
		if got := len(m.chains[j]); got != 1 {
			t.Fatalf("%s has %d jumps, want exactly 1 (idempotent bootstrap)", j, got)
		}
	}
	if !strings.Contains(m.chains["nat/PREROUTING"][0], "--dst-type LOCAL") {
		t.Fatal("PREROUTING jump must be limited to local destinations")
	}
}

func TestForwarderOwnerIngressAndRedirectRules(t *testing.T) {
	m := newMem()
	f := New(m, nil)
	// Owner: DNAT to the container, no masquerade.
	if err := f.Ensure(22000, dnat("10.0.0.5:5432", false)); err != nil {
		t.Fatal(err)
	}
	// Ingress: DNAT to owner:hp WITH masquerade (replies come back here).
	if err := f.Ensure(22001, dnat("10.1.0.9:22001", true)); err != nil {
		t.Fatal(err)
	}
	// Wake / mediator: redirect to the sandboxd listener.
	if err := f.Ensure(22002, Target{Kind: Redirect, RedirectPort: 21215}); err != nil {
		t.Fatal(err)
	}
	nat := strings.Join(m.rules("nat", ChainNAT), "\n")
	for _, want := range []string{
		"--dport 22000 -m comment --comment aerolvm-hp-22000 -j DNAT --to-destination 10.0.0.5:5432",
		"--dport 22001 -m comment --comment aerolvm-hp-22001 -j DNAT --to-destination 10.1.0.9:22001",
		"--dport 22002 -m comment --comment aerolvm-hp-22002 -j REDIRECT --to-ports 21215",
	} {
		if !strings.Contains(nat, want) {
			t.Errorf("nat chain missing %q:\n%s", want, nat)
		}
	}
	if got := m.rules("nat", ChainPost); len(got) != 1 || !strings.Contains(got[0], "-d 10.1.0.9/32") || !strings.Contains(got[0], "MASQUERADE") {
		t.Fatalf("masquerade only for the ingress hop: %v", got)
	}
	if got := m.rules("filter", ChainFwd); len(got) != 2 {
		t.Fatalf("forward accepts = %v, want one per DNAT (none for redirect)", got)
	}
	if ports := f.Ports(); len(ports) != 3 {
		t.Fatalf("ports = %v", ports)
	}
}

// A changed target replaces the old rules (e.g. a sandbox wakes: Redirect →
// DNAT), and re-ensuring the same target never duplicates.
func TestForwarderEnsureReplacesAndIsIdempotent(t *testing.T) {
	m := newMem()
	f := New(m, nil)
	_ = f.Ensure(22000, Target{Kind: Redirect, RedirectPort: 21215})
	if err := f.Ensure(22000, dnat("10.0.0.5:5432", false)); err != nil {
		t.Fatal(err)
	}
	nat := m.rules("nat", ChainNAT)
	if len(nat) != 1 || !strings.Contains(nat[0], "DNAT") {
		t.Fatalf("after wake: nat = %v, want only the DNAT", nat)
	}
	appends := m.appends
	if err := f.Ensure(22000, dnat("10.0.0.5:5432", false)); err != nil {
		t.Fatal(err)
	}
	if m.appends != appends {
		t.Fatal("re-ensuring the same target appended rules")
	}
	// Someone flushed our chain: re-ensure restores it.
	m.chains["nat/"+ChainNAT] = nil
	if err := f.Ensure(22000, dnat("10.0.0.5:5432", false)); err != nil {
		t.Fatal(err)
	}
	if len(m.rules("nat", ChainNAT)) != 1 {
		t.Fatal("re-ensure did not restore a flushed rule")
	}
}

// Unexpose must actually cut access: rules go, and tracked connections for
// that port are flushed. Removing an unknown port is a no-op.
func TestForwarderRemoveFlushesConntrack(t *testing.T) {
	m := newMem()
	fl := &flushLog{}
	f := New(m, fl.flush)
	_ = f.Ensure(22001, dnat("10.1.0.9:22001", true))
	if err := f.Remove(22001); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"nat/" + ChainNAT, "nat/" + ChainPost, "filter/" + ChainFwd} {
		if len(m.chains[c]) != 0 {
			t.Fatalf("%s left rules: %v", c, m.chains[c])
		}
	}
	if len(fl.ports) != 1 || fl.ports[0] != 22001 {
		t.Fatalf("conntrack flushes = %v, want [22001]", fl.ports)
	}
	if err := f.Remove(22001); err != nil || len(fl.ports) != 1 {
		t.Fatalf("second Remove: err=%v flushes=%v, want a no-op", err, fl.ports)
	}
}

// Reconcile after a restart: in-memory state is empty and the kernel holds
// rules. Desired rules that already match are NOT churned (normalized
// listing), stale ones are removed and flushed, and missing ones are added.
func TestForwarderReconcileAgainstNormalizedKernelState(t *testing.T) {
	m := newMem()
	old := New(m, nil)
	_ = old.Ensure(22000, dnat("10.0.0.5:5432", false)) // still desired
	_ = old.Ensure(22001, dnat("10.1.0.9:22001", true)) // unexposed while down
	_ = old.Ensure(22002, dnat("10.0.0.7:80", false))   // target changed while down

	fl := &flushLog{}
	f := New(m, fl.flush) // fresh process: empty memory
	deletesBefore, appendsBefore := m.deletes, m.appends
	desired := map[int]Target{
		22000: dnat("10.0.0.5:5432", false),
		22002: dnat("10.0.0.8:80", false),
		22003: {Kind: Redirect, RedirectPort: 21215},
	}
	if err := f.Reconcile(desired); err != nil {
		t.Fatal(err)
	}
	nat := strings.Join(m.rules("nat", ChainNAT), "\n")
	if strings.Contains(nat, "aerolvm-hp-22001") || strings.Contains(nat, "10.0.0.7") {
		t.Fatalf("stale rules survived reconcile:\n%s", nat)
	}
	for _, want := range []string{"10.0.0.5:5432", "10.0.0.8:80", "--to-ports 21215"} {
		if !strings.Contains(nat, want) {
			t.Fatalf("desired rule %q missing:\n%s", want, nat)
		}
	}
	if len(m.rules("nat", ChainPost)) != 0 {
		t.Fatal("the unexposed port's masquerade survived")
	}
	// 22000 matched (normalized listing) and must not be churned. 22002's
	// accept rule is keyed by host port, so a new target leaves it alone:
	// deletes = 22001's 3 rules + 22002's DNAT = 4.
	if got := m.deletes - deletesBefore; got != 4 {
		t.Fatalf("reconcile deleted %d rules, want 4 (22000 matched and must not churn)", got)
	}
	if got := m.appends - appendsBefore; got != 2 {
		t.Fatalf("reconcile appended %d rules, want 2 (22002 DNAT, 22003 redirect)", got)
	}
	sort.Ints(fl.ports)
	if len(fl.ports) != 1 || fl.ports[0] != 22001 {
		t.Fatalf("flushed %v, want only the unexposed port [22001]", fl.ports)
	}
	if ports := f.Ports(); len(ports) != 3 {
		t.Fatalf("memory after reconcile = %v", ports)
	}
	// A second reconcile with the same desired set is a no-op.
	deletesBefore, appendsBefore = m.deletes, m.appends
	if err := f.Reconcile(desired); err != nil {
		t.Fatal(err)
	}
	if m.deletes != deletesBefore || m.appends != appendsBefore {
		t.Fatal("a steady-state reconcile touched rules")
	}
}

func TestForwarderRejectsInvalidInput(t *testing.T) {
	f := New(newMem(), nil)
	for name, tc := range map[string]struct {
		hp int
		t  Target
	}{
		"hp zero":          {0, dnat("10.0.0.1:1", false)},
		"hp too big":       {70000, dnat("10.0.0.1:1", false)},
		"dnat no port":     {22000, Target{Kind: DNAT, Addr: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0)}},
		"dnat to loopback": {22000, dnat("127.0.0.1:5432", false)},
		"bad redirect":     {22000, Target{Kind: Redirect, RedirectPort: 0}},
		"unknown kind":     {22000, Target{Kind: Kind(9)}},
	} {
		if err := f.Ensure(tc.hp, tc.t); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := f.Reconcile(map[int]Target{0: dnat("10.0.0.1:1", false)}); err == nil {
		t.Fatal("Reconcile accepted an invalid port")
	}
	if err := f.Reconcile(map[int]Target{22000: dnat("127.0.0.1:1", false)}); err == nil {
		t.Fatal("Reconcile accepted a loopback DNAT")
	}
}

func TestForwarderSurfacesBackendErrors(t *testing.T) {
	for _, op := range []string{"ChainExists", "NewChain", "Insert", "Exists", "Append"} {
		m := newMem()
		m.failOn = op
		f := New(m, nil)
		if err := f.Ensure(22000, dnat("10.0.0.5:5432", false)); err == nil {
			t.Errorf("Ensure with %s failing returned nil", op)
		}
	}
	m := newMem()
	f := New(m, nil)
	_ = f.Ensure(22000, dnat("10.0.0.5:5432", false))
	m.failOn = "Delete"
	if err := f.Remove(22000); err == nil {
		t.Fatal("Remove with Delete failing returned nil")
	}
	m.failOn = "List"
	if err := f.Reconcile(map[int]Target{}); err == nil {
		t.Fatal("Reconcile with List failing returned nil")
	}
	fail := New(newMem(), func(int) error { return errors.New("netlink down") })
	_ = fail.Ensure(22000, dnat("10.0.0.5:5432", false))
	if err := fail.Remove(22000); err == nil {
		t.Fatal("a conntrack flush failure must surface")
	}
}

func TestParseRule(t *testing.T) {
	spec, hp, ours := parseRule(`-A AEROLVM-HOSTPORT -p tcp -m tcp --dport 22000 -m comment --comment "aerolvm-hp-22000" -j DNAT --to-destination 10.0.0.5:5432`, ChainNAT)
	if !ours || hp != 22000 || spec[len(spec)-1] != "10.0.0.5:5432" {
		t.Fatalf("parse ours: %v %d %v", spec, hp, ours)
	}
	if _, _, ours := parseRule("-A AEROLVM-HOSTPORT -p tcp -j ACCEPT", ChainNAT); ours {
		t.Fatal("a rule without our comment is not ours")
	}
	if _, _, ours := parseRule("-N AEROLVM-HOSTPORT", ChainNAT); ours {
		t.Fatal("a chain header is not a rule")
	}
	if _, _, ours := parseRule("-A OTHER -m comment --comment aerolvm-hp-1", ChainNAT); ours {
		t.Fatal("a rule from another chain is not ours")
	}
}

// Live finding (cluster-hetero-lite-routing): on a pure ingress node the
// accept rule covered only the original direction, and nothing else enabled
// forwarding. Now bootstrap turns on ip_forward, and the accept rule is keyed
// by the connection's ORIGINAL destination port, so it covers replies too.
func TestForwarderEnablesForwardingAndAcceptsBothDirections(t *testing.T) {
	m := newMem()
	f := New(m, nil)
	before := ipForwardCalls
	if err := f.Ensure(22100, dnat("10.1.0.9:22100", true)); err != nil {
		t.Fatal(err)
	}
	if err := f.Ensure(22101, dnat("10.0.0.5:80", false)); err != nil {
		t.Fatal(err)
	}
	if got := ipForwardCalls - before; got != 1 {
		t.Fatalf("ip_forward enabled %d times, want once at bootstrap", got)
	}
	fwd := strings.Join(m.rules("filter", ChainFwd), "\n")
	for _, hp := range []string{"22100", "22101"} {
		if !strings.Contains(fwd, "--ctstate DNAT --ctorigdstport "+hp) {
			t.Fatalf("accept rule for %s must match the DNAT'd connection by original port (both directions):\n%s", hp, fwd)
		}
	}
	if strings.Contains(fwd, "--dport") {
		t.Fatalf("accept rule still keyed on the post-DNAT destination (original direction only):\n%s", fwd)
	}

	prev := enableIPForward
	enableIPForward = func() error { return errors.New("read-only /proc") }
	defer func() { enableIPForward = prev }()
	if err := New(newMem(), nil).Ensure(22102, dnat("10.1.0.9:22102", true)); err == nil {
		t.Fatal("a host where forwarding cannot be enabled must fail the expose loudly")
	}
}

// ruleMatches reads rules semantically, per chain. Every mismatch must say
// "stale", or Reconcile would keep a rule that forwards somewhere else.
func TestRuleMatchesPerChain(t *testing.T) {
	d := dnat("10.0.0.5:5432", true)
	r := Target{Kind: Redirect, RedirectPort: 21215}
	nat := func(tgt Target) []string { return natSpec(22000, tgt) }
	cases := []struct {
		name  string
		chain string
		spec  []string
		hp    int
		t     Target
		want  bool
	}{
		{"nat dnat match", ChainNAT, nat(d), 22000, d, true},
		{"nat dnat other target", ChainNAT, nat(dnat("10.0.0.6:5432", true)), 22000, d, false},
		{"nat redirect match", ChainNAT, nat(r), 22000, r, true},
		{"nat redirect other port", ChainNAT, nat(Target{Kind: Redirect, RedirectPort: 1}), 22000, r, false},
		{"nat dnat vs redirect", ChainNAT, nat(r), 22000, d, false},
		{"fwd match", ChainFwd, fwdSpec(22000, d), 22000, d, true},
		{"fwd other host port", ChainFwd, fwdSpec(22001, d), 22000, d, false},
		{"fwd for a redirect is stale", ChainFwd, fwdSpec(22000, d), 22000, r, false},
		{"post match", ChainPost, postSpec(22000, d), 22000, d, true},
		{"post without masquerade is stale", ChainPost, postSpec(22000, d), 22000, dnat("10.0.0.5:5432", false), false},
		{"post other target", ChainPost, postSpec(22000, dnat("10.0.0.9:1", true)), 22000, d, false},
		{"unknown chain", "OTHER", nat(d), 22000, d, false},
	}
	for _, tc := range cases {
		if got := ruleMatches(tc.chain, tc.spec, tc.hp, tc.t); got != tc.want {
			t.Errorf("%s: ruleMatches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestForwarderRemoveSurfacesDeleteErrors(t *testing.T) {
	for _, op := range []string{"Exists", "Delete"} {
		m := newMem()
		f := New(m, nil)
		if err := f.Ensure(22200, dnat("10.1.0.9:22200", true)); err != nil {
			t.Fatal(err)
		}
		m.failOn = op
		if err := f.Remove(22200); err == nil {
			t.Fatalf("%s failure on remove: want error", op)
		}
	}
}

// Every backend failure while changing rules surfaces; none is swallowed
// into a silently half-forwarded port.
func TestForwarderSurfacesChangeAndReconcileErrors(t *testing.T) {
	for _, op := range []string{"Exists", "Append"} {
		m := newMem()
		f := New(m, nil)
		if err := f.Ensure(22400, dnat("10.1.0.9:1", true)); err != nil { // chains up
			t.Fatal(err)
		}
		m.failOn = op
		if err := f.Ensure(22401, dnat("10.1.0.9:2", true)); err == nil {
			t.Fatalf("%s failure on ensure: want error", op)
		}
		// A target change deletes the old rules first.
		if err := f.Ensure(22400, dnat("10.1.0.9:3", true)); err == nil {
			t.Fatalf("%s failure on a target change: want error", op)
		}
	}
	for _, op := range []string{"List", "Delete", "Append"} {
		m := newMem()
		old := New(m, nil)
		_ = old.Ensure(22410, dnat("10.1.0.9:1", true))
		m.failOn = op
		if err := New(m, nil).Reconcile(map[int]Target{22411: dnat("10.1.0.9:2", false)}); err == nil {
			t.Fatalf("%s failure on reconcile: want error", op)
		}
	}
	m := newMem()
	_ = New(m, nil).Ensure(22420, dnat("10.1.0.9:1", true))
	boom := func(int) error { return errors.New("netlink") }
	if err := New(m, boom).Reconcile(map[int]Target{}); err == nil {
		t.Fatal("conntrack flush failure on reconcile: want error")
	}
	if err := New(m, nil).Reconcile(map[int]Target{0: dnat("10.1.0.9:1", false)}); err == nil {
		t.Fatal("invalid host port on reconcile: want error")
	}
	if err := New(m, nil).Reconcile(map[int]Target{22421: {Kind: DNAT}}); err == nil {
		t.Fatal("invalid target on reconcile: want error")
	}
}
