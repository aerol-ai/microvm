package rootpolicy_test

import (
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestLookupTakesTheLargestRuleSet (PR 5b review): the gateway asks about
// every binary a sandbox's rules list. The largest rule set egresspolicy
// accepts (its rule limit, 16 distinct binaries each) must pass the
// helper's lookup rule, or split mode would refuse a per-program flow that
// single mode answers.
func TestLookupTakesTheLargestRuleSet(t *testing.T) {
	var specs []egresspolicy.RuleSpec
	for r := range egresspolicy.MaxRules {
		s := egresspolicy.RuleSpec{Host: fmt.Sprintf("h%d.example.com", r), Ports: []uint16{5432}}
		for b := range 16 {
			s.Binaries = append(s.Binaries, fmt.Sprintf("/opt/tool%d/bin%d", r, b))
		}
		specs = append(specs, s)
	}
	rules, err := egresspolicy.CompileRules(specs, nil)
	if err != nil {
		t.Fatalf("the largest valid rule set: %v", err)
	}
	paths := rules.Binaries()
	if len(paths) != egresspolicy.MaxRules*16 {
		t.Fatalf("%d binaries, want %d", len(paths), egresspolicy.MaxRules*16)
	}
	if _, err := rootpolicy.CheckProcessMatch(4242, "10.88.0.5:40000", "1.2.3.4:5432", paths); err != nil {
		t.Fatalf("the helper refuses a lookup single mode answers: %v", err)
	}
}
