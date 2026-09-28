package safety

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"gopkg.in/yaml.v3"
)

// unreachableUseCases are the cases that no scenario can currently satisfy,
// each with the reason and the work that would unblock it.
//
// An entry here is a DECLARATION, not an excuse: the matrix will show these
// as ⚪ forever, and plans/integration-test-security.md §6.2a is explicit
// that "silently shipping three UCs that can never run is the worst of the
// three" options. Writing the reason down is what stops it being silent.
// unreachableUseCases declares cases that no single scenario can satisfy,
// each with the reason and the work that would unblock it.
//
// An entry here is a DECLARATION, not an excuse: the matrix shows these as ⚪
// forever, and plans/integration-test-security.md §6.2a is explicit that
// "silently shipping UCs that can never run is the worst of the three"
// options. Writing the reason down is what stops it being silent.
//
// Empty, and it should stay that way. §6.2a's open question — whether to
// provision isolate anywhere — was resolved in T10: S4
// (cluster-3-mixed-secrets-enterprise) sets default_with_isolate = true and
// advertises isolate + isolate-jail alongside enterprise, so UC-150/163/164
// have a home. The test below fails if an entry is added that is in fact
// reachable, and fails if a reachable case loses its home.
var unreachableUseCases = map[string]string{}

// A registered, Implemented use case whose required capabilities NO scenario
// provides can never run. It is not a skip that means "not applicable here" —
// it is a test nobody will ever execute, reported as ⚪ on every row of the
// matrix, which reads identically to a case that is simply out of scope.
//
// This is the failure §6.2a named. It costs nothing to check mechanically.
func TestNoUseCaseIsUnreachableByEveryScenario(t *testing.T) {
	// Per SCENARIO, not pooled. A use case needs ONE scenario to satisfy all
	// of its requirements at once: pooling the union across scenarios would
	// call UC-163 reachable because single-node-isolate provides `isolate`
	// and a secrets scenario provides `enterprise`, when in fact no scenario
	// provides both — which is exactly the case §6.2a is about.
	scenarios := readScenarioCaps(t)
	if len(scenarios) == 0 {
		t.Fatal("no scenario caps files were read; this guard would pass having checked nothing")
	}

	var unreachable []string
	for _, uc := range harness.Registry {
		if !uc.Implemented {
			continue
		}
		if _, declared := unreachableUseCases[uc.ID]; declared {
			continue
		}
		if satisfiedBySomeScenario(uc, scenarios) {
			continue
		}
		unreachable = append(unreachable, uc.ID+" (requires "+joinCaps(uc.Requires)+")")
	}
	if len(unreachable) > 0 {
		sort.Strings(unreachable)
		t.Fatalf("these use cases can never run — no SINGLE scenario satisfies all of their requirements, so they report ⚪ on every row and read as 'out of scope' rather than 'untested'.\nEither give a scenario the capabilities, or add the id to unreachableUseCases with the reason and what would unblock it:\n  %s",
			strings.Join(unreachable, "\n  "))
	}

	// And the declarations must not go stale: an entry that IS now reachable
	// is a case being needlessly excused.
	var nowReachable []string
	for id := range unreachableUseCases {
		uc, ok := harness.Lookup(id)
		if !ok {
			nowReachable = append(nowReachable, id+" (no longer in the registry)")
			continue
		}
		if satisfiedBySomeScenario(uc, scenarios) {
			nowReachable = append(nowReachable, id+" (a scenario now satisfies it)")
		}
	}
	if len(nowReachable) > 0 {
		sort.Strings(nowReachable)
		t.Fatalf("remove these from unreachableUseCases: %s", strings.Join(nowReachable, ", "))
	}
}

// scenarioCaps is one scenario's advertised capability set.
type scenarioCaps struct {
	name string
	caps map[harness.Capability]bool
}

func readScenarioCaps(t *testing.T) []scenarioCaps {
	t.Helper()
	dir := filepath.Join("..", "scenarios")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []scenarioCaps
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".caps.yml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Capabilities []harness.Capability `yaml:"capabilities"`
		}
		if err := yaml.Unmarshal(b, &parsed); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		set := map[harness.Capability]bool{}
		for _, c := range parsed.Capabilities {
			set[c] = true
		}
		out = append(out, scenarioCaps{name: strings.TrimSuffix(e.Name(), ".caps.yml"), caps: set})
	}
	return out
}

// satisfiedBySomeScenario reports whether any one scenario provides every
// required capability AND holds none of the excluded ones — the same rule
// harness.Scenario.Satisfies applies at run time.
func satisfiedBySomeScenario(uc harness.UseCase, scenarios []scenarioCaps) bool {
	for _, s := range scenarios {
		ok := true
		for _, c := range uc.Requires {
			if !s.caps[c] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for _, c := range uc.Excludes {
			if s.caps[c] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func joinCaps(caps []harness.Capability) string {
	parts := make([]string, 0, len(caps))
	for _, c := range caps {
		parts = append(parts, string(c))
	}
	return strings.Join(parts, "+")
}
