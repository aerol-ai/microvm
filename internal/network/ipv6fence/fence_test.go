package ipv6fence

import (
	"reflect"
	"strings"
	"testing"
)

func TestSpecNormalize(t *testing.T) {
	got, err := Spec{
		Bridges: []string{" docker0 ", "aerolvm0", "docker0"},
		Links:   []string{"fctap*", "fctap*", "veth9"},
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want := Spec{Bridges: []string{"aerolvm0", "docker0"}, Links: []string{"fctap*", "veth9"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize = %+v, want %+v", got, want)
	}
	if got.Key() != "bridges=aerolvm0,docker0;links=fctap*,veth9" {
		t.Fatalf("Key = %q", got.Key())
	}
	if got.Empty() || !(Spec{}).Empty() {
		t.Fatal("Empty")
	}

	for _, bad := range []Spec{
		{Bridges: []string{""}},
		{Bridges: []string{"br*"}},              // a prefix is only for links
		{Bridges: []string{"sixteen-chars-xx"}}, // over IFNAMSIZ-1
		{Bridges: []string{"a/b"}},              // would escape a /proc path
		{Bridges: []string{".."}},               // likewise
		{Links: []string{"*"}},                  // a bare wildcard is every interface
		{Links: []string{"a*b"}},                // '*' only at the end
		{Links: []string{"fifteen-chars-x*"}},   // prefix over 14 bytes
		{Links: []string{"has space"}},          // not an interface name
		{Bridges: []string{"ok0"}, Links: []string{"bad\x00"}},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Fatalf("Normalize(%+v) accepted a bad name", bad)
		}
	}
	// The longest valid names.
	if _, err := (Spec{Bridges: []string{"fifteen-chars-x"}, Links: []string{"fourteen-chars*"}}).Normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestSpecMerge(t *testing.T) {
	a := Spec{Bridges: []string{"docker0"}}
	b := Spec{Bridges: []string{"aerolvm0"}, Links: []string{"fctap*"}}
	m := a.Merge(b)
	if len(m.Bridges) != 2 || len(m.Links) != 1 {
		t.Fatalf("Merge = %+v", m)
	}
	// Merge never aliases its inputs.
	m.Bridges[0] = "x"
	if a.Bridges[0] != "docker0" {
		t.Fatal("Merge aliased its receiver")
	}
}

// TestPlan pins the rule set: every sandbox bridge drops IPv6 between its
// ports, into the host and out of the host at the bridge layer, and every
// bridge and routed link drops IPv6 at the IPv6 layer in all three
// directions.
func TestPlan(t *testing.T) {
	spec, err := Spec{Bridges: []string{"aerolvm0"}, Links: []string{"fctap*"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	got := Plan(spec)
	want := []Rule{
		{FamilyBridge, ChainForward, MatchInBridge, "aerolvm0"},
		{FamilyBridge, ChainInput, MatchInBridge, "aerolvm0"},
		{FamilyBridge, ChainOutput, MatchOutBridge, "aerolvm0"},
		{FamilyIP6, ChainForward, MatchIn, "aerolvm0"},
		{FamilyIP6, ChainForward, MatchOut, "aerolvm0"},
		{FamilyIP6, ChainForward, MatchIn, "fctap*"},
		{FamilyIP6, ChainForward, MatchOut, "fctap*"},
		{FamilyIP6, ChainInput, MatchIn, "aerolvm0"},
		{FamilyIP6, ChainInput, MatchIn, "fctap*"},
		{FamilyIP6, ChainOutput, MatchOut, "aerolvm0"},
		{FamilyIP6, ChainOutput, MatchOut, "fctap*"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan =\n%v\nwant\n%v", got, want)
	}
	// A routed link gets no bridge-family rule: it is not a bridge.
	for _, r := range Plan(Spec{Links: []string{"fctap*"}}) {
		if r.Family == FamilyBridge {
			t.Fatalf("link got a bridge rule: %+v", r)
		}
	}
	if len(Plan(Spec{})) != 0 {
		t.Fatal("empty spec planned rules")
	}
}

func TestChainRulesAndComment(t *testing.T) {
	rules := Plan(Spec{Links: []string{"fctap*"}})
	byChain := ChainRules(rules)
	if len(byChain) != 6 {
		t.Fatalf("ChainRules keys = %d, want every chain of both tables", len(byChain))
	}
	if len(byChain["bridge/forward"]) != 0 || len(byChain["ip6/forward"]) != 2 || len(byChain["ip6/input"]) != 1 {
		t.Fatalf("ChainRules = %v", byChain)
	}
	c := Rule{FamilyIP6, ChainInput, MatchIn, "fctap*"}.Comment()
	if !strings.Contains(c, "ipv6 fence") || !strings.Contains(c, "ip6/input iifname fctap*") {
		t.Fatalf("Comment = %q", c)
	}
	if len(c) > 120 {
		t.Fatalf("comment %d bytes; nft shows at most 128", len(c))
	}
}
