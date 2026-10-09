package egresspolicy

import (
	"slices"
	"testing"
)

// TestRulesBinaries: every listed executable once, in rule order; none
// without per-binary rules.
func TestRulesBinaries(t *testing.T) {
	pol, err := Compile(Spec{AllowOut: []string{"pypi.org", "github.com"}, MaxHostnames: MaxUnionHostnames})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompileRules([]RuleSpec{
		{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/local/bin/pip", "/usr/bin/git"}},
		{Host: "github.com", Ports: []uint16{443}, Binaries: []string{"/usr/bin/git"}},
	}, pol)
	if err != nil {
		t.Fatal(err)
	}
	if got := rs.Binaries(); !slices.Equal(got, []string{"/usr/local/bin/pip", "/usr/bin/git"}) {
		t.Fatalf("Binaries = %v", got)
	}
	var none *Rules
	if none.Binaries() != nil {
		t.Fatal("nil rules list no binaries")
	}
}
