package egresspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func mustCompile(t testing.TB, s Spec) *Policy {
	t.Helper()
	p, err := Compile(s)
	if err != nil {
		t.Fatalf("Compile(%+v): %v", s, err)
	}
	return p
}

type probe struct {
	dest    string // host, host:port or IP (MatchHostPort / MatchIP)
	port    uint16
	allowed bool
	rule    string
}

func runProbes(t *testing.T, p *Policy, probes []probe) {
	t.Helper()
	for _, pr := range probes {
		var allowed bool
		var rule string
		if ip, err := netip.ParseAddr(pr.dest); err == nil {
			allowed, rule = p.MatchIP(ip, pr.port)
		} else {
			allowed, rule = p.MatchHostPort(pr.dest, pr.port)
		}
		if allowed != pr.allowed || rule != pr.rule {
			t.Errorf("%s:%d = (%v, %q), want (%v, %q)", pr.dest, pr.port, allowed, rule, pr.allowed, pr.rule)
		}
	}
}

// TestCompilePrecedence is EF-36: the D4 allow-wins precedence table.
func TestCompilePrecedence(t *testing.T) {
	tests := []struct {
		name        string
		spec        Spec
		blockAll    bool
		verdict     Verdict
		gatewayMode bool
		probes      []probe
	}{
		{
			name:        "allow_alone_is_an_allowlist",
			spec:        Spec{AllowOut: []string{"api.example.com", "203.0.113.0/24"}},
			verdict:     VerdictDeny,
			gatewayMode: true,
			probes: []probe{
				{"api.example.com", 443, true, "api.example.com"},
				{"other.com", 443, false, ""},
				{"203.0.113.7", 22, true, "203.0.113.0/24"},
				{"198.51.100.1", 443, false, ""},
			},
		},
		{
			name:    "deny_alone_is_a_deny_list",
			spec:    Spec{DenyOut: []string{"203.0.113.0/24"}},
			verdict: VerdictAllow,
			probes: []probe{
				{"203.0.113.7", 443, false, "203.0.113.0/24"},
				{"198.51.100.1", 443, true, ""},
				{"anything.example", 443, true, ""},
			},
		},
		{
			name:        "both_lists_allow_wins_then_deny_then_accept",
			spec:        Spec{AllowOut: []string{"api.example.com", "203.0.113.0/25"}, DenyOut: []string{"203.0.113.0/24"}},
			verdict:     VerdictAllow,
			gatewayMode: true,
			probes: []probe{
				{"203.0.113.5", 443, true, "203.0.113.0/25"}, // in both: allow wins
				{"203.0.113.200", 443, false, "203.0.113.0/24"},
				{"api.example.com", 443, true, "api.example.com"},
				{"other.com", 443, true, ""}, // default accept
				{"8.8.8.8", 53, true, ""},
			},
		},
		{
			name:        "allow_plus_deny_all_is_an_allowlist",
			spec:        Spec{AllowOut: []string{"api.example.com"}, DenyOut: []string{"0.0.0.0/0"}},
			verdict:     VerdictDeny,
			gatewayMode: true,
			probes: []probe{
				{"api.example.com", 443, true, "api.example.com"},
				{"other.com", 443, false, ""},
				{"8.8.8.8", 443, false, "0.0.0.0/0"},
			},
		},
		{
			name:     "deny_all_alone_is_block_all",
			spec:     Spec{DenyOut: []string{"0.0.0.0/0"}},
			blockAll: true,
			verdict:  VerdictDeny,
			probes: []probe{
				{"api.example.com", 443, false, RuleBlockAll},
				{"8.8.8.8", 443, false, RuleBlockAll},
			},
		},
		{
			name:     "block_all_wins_over_hostnames",
			spec:     Spec{BlockAll: true, AllowOut: []string{"pypi.org"}},
			blockAll: true,
			verdict:  VerdictDeny,
			probes: []probe{
				{"pypi.org", 443, false, RuleBlockAll},
				{"[2001:db8::1]", 443, false, RuleBlockAll},
			},
		},
		{
			name:    "ipv6_deny_all_is_an_ordinary_cidr",
			spec:    Spec{DenyOut: []string{"::/0"}},
			verdict: VerdictAllow,
			probes: []probe{
				{"2001:db8::1", 443, false, "::/0"},
				{"8.8.8.8", 443, true, ""},
			},
		},
		{
			name:    "no_lists_is_open",
			spec:    Spec{},
			verdict: VerdictAllow,
			probes:  []probe{{"anything.example", 443, true, ""}},
		},
		{
			name:        "learn_mode_allows_everything",
			spec:        Spec{Mode: ModeLearn},
			verdict:     VerdictAllow,
			gatewayMode: true,
			probes: []probe{
				{"anything.example", 8080, true, ""},
				{"10.0.0.1", 22, true, ""},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mustCompile(t, tc.spec)
			if p.BlockAll() != tc.blockAll || p.DefaultVerdict() != tc.verdict || p.GatewayMode() != tc.gatewayMode {
				t.Fatalf("blockAll=%v verdict=%v gatewayMode=%v, want %v %v %v",
					p.BlockAll(), p.DefaultVerdict(), p.GatewayMode(), tc.blockAll, tc.verdict, tc.gatewayMode)
			}
			runProbes(t, p, tc.probes)
		})
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{"unknown_mode", Spec{Mode: "audit"}, `network_egress_mode "audit"`},
		{"learn_with_allow", Spec{Mode: ModeLearn, AllowOut: []string{"pypi.org"}}, "requires empty"},
		{"learn_with_deny", Spec{Mode: ModeLearn, DenyOut: []string{"10.0.0.0/8"}}, "requires empty"},
		{"learn_with_block_all", Spec{Mode: ModeLearn, BlockAll: true}, "requires empty"},
		{"bad_allow_entry", Spec{AllowOut: []string{"pypi.org", "*.com"}}, `network_allow_out entry "*.com"`},
		// D15: the isolate legacy row shape is now a 400.
		{"hostname_in_deny", Spec{AllowOut: []string{".example.com"}, DenyOut: []string{"bad.example.com"}}, `network_deny_out entry "bad.example.com"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.spec)
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrInvalid containing %q", err, tc.want)
			}
		})
	}
	t.Run("inline_hostname_cap", func(t *testing.T) {
		var allow []string
		for i := 0; i <= MaxInlineHostnames; i++ {
			allow = append(allow, fmt.Sprintf("h%d.example.com", i))
		}
		if _, err := Compile(Spec{AllowOut: allow}); err == nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("65 inline hostnames accepted: %v", err)
		}
		if _, err := Compile(Spec{AllowOut: allow[:MaxInlineHostnames]}); err != nil {
			t.Fatalf("64 inline hostnames rejected: %v", err)
		}
	})
}

func TestMatchHostSemantics(t *testing.T) {
	p := mustCompile(t, Spec{AllowOut: []string{
		"*.example.com", "api.example.com", "*.api2.example.com", "github.com:22", "github.com:2222",
		"pypi.org", "bücher.example", "203.0.113.0/24", "2001:db8::/32", "10.0.0.0/8", "10.1.0.0/16",
	}})
	runProbes(t, p, []probe{
		// EF-22: any depth under the suffix, never the apex.
		{"x.example.com", 443, true, "*.example.com"},
		{"a.b.example.com", 80, true, "*.example.com"},
		{"example.com", 443, false, ""},
		{"badexample.com", 443, false, ""},
		// An exact rule beats a wildcard; the closest wildcard beats a broader one.
		{"api.example.com", 443, true, "api.example.com"},
		{"x.api2.example.com", 443, true, "*.api2.example.com"},
		// Port semantics: bare = 80/443, host:port = exactly that port.
		{"pypi.org", 443, true, "pypi.org"},
		{"pypi.org", 80, true, "pypi.org"},
		{"pypi.org", 8080, false, ""},
		{"github.com", 22, true, "github.com:22"},
		{"github.com", 2222, true, "github.com:2222"},
		{"github.com", 443, false, ""},
		{"github.com", 0, true, "github.com:22"}, // name-level question
		// A wildcard's port rules apply only with that port.
		{"x.example.com", 8443, false, ""},
		// Normalization of the observed name.
		{"API.Example.COM.", 443, true, "api.example.com"},
		{"BÜCHER.example", 443, true, "xn--bcher-kva.example"},
		{"xn--bcher-kva.example", 443, true, "xn--bcher-kva.example"},
		// Garbage never matches a rule.
		{"evil.com\x00.example.com", 443, false, ""},
		{"", 443, false, ""},
		// IP literals go to the CIDR rules; the narrowest one is reported.
		{"203.0.113.7", 0, true, "203.0.113.0/24"},
		{"[2001:db8::1]", 443, true, "2001:db8::/32"},
		{"::ffff:203.0.113.7", 443, true, "203.0.113.0/24"},
		{"10.1.2.3", 443, true, "10.1.0.0/16"},
		{"10.2.0.1", 443, true, "10.0.0.0/8"},
		{"198.51.100.1", 443, false, ""},
	})
	if ok, rule := p.MatchHost("github.com"); !ok || rule != "github.com:22" {
		t.Fatalf("MatchHost(github.com) = %v %q", ok, rule)
	}
}

func TestPolicyAccessors(t *testing.T) {
	p := mustCompile(t, Spec{
		AllowOut: []string{"pypi.org", "github.com:22", "*.example.com", "10.0.0.0/8", "10.1.0.0/16"},
		DenyOut:  []string{"203.0.113.0/24", "203.0.113.128/25"},
	})
	if !p.HasHostnames() || p.Mode() != ModeEnforce {
		t.Fatal("HasHostnames/Mode")
	}
	if got := entryStrings(p.AllowEntries()); strings.Join(got, ",") != "pypi.org,github.com:22,*.example.com,10.0.0.0/8,10.1.0.0/16" {
		t.Fatalf("AllowEntries = %v", got)
	}
	if got := entryStrings(p.DenyEntries()); strings.Join(got, ",") != "203.0.113.0/24,203.0.113.128/25" {
		t.Fatalf("DenyEntries = %v", got)
	}
	if got := fmt.Sprint(p.AllowCIDRs()); got != "[10.1.0.0/16 10.0.0.0/8]" {
		t.Fatalf("AllowCIDRs = %s (want most specific first)", got)
	}
	if got := fmt.Sprint(p.DenyCIDRs()); got != "[203.0.113.128/25 203.0.113.0/24]" {
		t.Fatalf("DenyCIDRs = %s", got)
	}
	if got := entryStrings(p.HostRules()); strings.Join(got, ",") != "pypi.org,github.com:22,*.example.com" {
		t.Fatalf("HostRules = %v", got)
	}
	if got := entryStrings(p.HostPortRules()); strings.Join(got, ",") != "github.com:22" {
		t.Fatalf("HostPortRules = %v", got)
	}
	// Accessors hand out copies: a caller can't mutate the shared policy.
	p.AllowEntries()[0] = Entry{}
	p.AllowCIDRs()[0] = netip.Prefix{}
	if p.AllowEntries()[0].String() != "pypi.org" || p.AllowCIDRs()[0].String() != "10.1.0.0/16" {
		t.Fatal("accessor returned shared backing storage")
	}

	b := BlockAllPolicy()
	if !b.BlockAll() || b.DefaultVerdict() != VerdictDeny || b.GatewayMode() {
		t.Fatal("BlockAllPolicy must deny everything without gateway work")
	}
	if ok, _ := mustCompile(t, Spec{AllowOut: []string{"10.0.0.0/8"}}).MatchHost("pypi.org"); ok {
		t.Fatal("CIDR-only allowlist must deny names")
	}
}

func TestPolicyHash(t *testing.T) {
	a := mustCompile(t, Spec{AllowOut: []string{"pypi.org", ".example.com", "10.0.0.0/8"}, DenyOut: []string{"203.0.113.0/24"}})
	b := mustCompile(t, Spec{AllowOut: []string{"10.0.0.1/8", "*.example.com", "PYPI.org", "pypi.org"}, DenyOut: []string{"203.0.113.0/24"}})
	if a.Hash() != b.Hash() || len(a.Hash()) != 64 {
		t.Fatalf("equal content hashed differently: %s vs %s", a.Hash(), b.Hash())
	}
	for _, other := range []Spec{
		{AllowOut: []string{"pypi.org", ".example.com", "10.0.0.0/8"}},
		{AllowOut: []string{"pypi.org", ".example.com", "10.0.0.0/8"}, DenyOut: []string{"203.0.113.0/24"}, BlockAll: true},
		{Mode: ModeLearn},
		{},
	} {
		if mustCompile(t, other).Hash() == a.Hash() {
			t.Fatalf("different policy %+v shares hash %s", other, a.Hash())
		}
	}
	if mustCompile(t, Spec{}).Hash() == mustCompile(t, Spec{Mode: ModeLearn}).Hash() {
		t.Fatal("mode must be part of the hash")
	}
}

func TestNeedsGateway(t *testing.T) {
	cases := []struct {
		allow, deny []string
		blockAll    bool
		want        bool
	}{
		{[]string{"pypi.org"}, nil, false, true},
		{[]string{"*.github.com"}, []string{"0.0.0.0/0"}, false, true},
		{[]string{"pypi.org"}, nil, true, false},
		{[]string{"10.0.0.0/8"}, nil, false, false},
		{nil, []string{"10.0.0.0/8"}, false, false},
		{[]string{"bad host!"}, nil, false, false},
		{nil, nil, false, false},
	}
	for _, tc := range cases {
		if got := NeedsGateway(tc.allow, tc.deny, tc.blockAll); got != tc.want {
			t.Errorf("NeedsGateway(%v, %v, %v) = %v, want %v", tc.allow, tc.deny, tc.blockAll, got, tc.want)
		}
	}
}

func TestDenyMessage(t *testing.T) {
	for _, tc := range []struct{ rule, want string }{
		{"", "aerolvm egress policy: host evil.example not allowed (no rule matches)"},
		{RuleBlockAll, "aerolvm egress policy: host evil.example not allowed (network_block_all)"},
		{"10.0.0.0/8", "aerolvm egress policy: host evil.example not allowed (rule 10.0.0.0/8)"},
	} {
		if got := DenyMessage("evil.example", tc.rule); got != tc.want {
			t.Errorf("DenyMessage(%q) = %q, want %q", tc.rule, got, tc.want)
		}
	}
}
