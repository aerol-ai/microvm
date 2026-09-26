package harness

import "testing"

// These tests run OFFLINE in the normal `go test ./...` / `make test` flow.
// They guard the load-bearing capability logic: a bug in Satisfies silently
// turns an un-runnable use case green, which is the worst failure mode for a
// test harness. No AWS, no network.

func scenario(caps ...Capability) *Scenario {
	m := make(map[Capability]bool)
	for _, c := range caps {
		m[c] = true
	}
	return &Scenario{Name: "test", caps: m}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		name string
		sc   *Scenario
		uc   UseCase
		want bool
	}{
		{"no-requirements always satisfied", scenario(), UseCase{Requires: nil}, true},
		{"single cap present", scenario(CapDocker), UseCase{Requires: []Capability{CapDocker}}, true},
		{"single cap absent", scenario(), UseCase{Requires: []Capability{CapDocker}}, false},
		{"all of multi present", scenario(CapDocker, CapDomain), UseCase{Requires: []Capability{CapDocker, CapDomain}}, true},
		{"one of multi absent", scenario(CapDocker), UseCase{Requires: []Capability{CapDocker, CapDomain}}, false},
		{"extra caps don't hurt", scenario(CapDocker, CapDomain, CapCluster), UseCase{Requires: []Capability{CapDocker}}, true},
		{"firecracker needs fc worker", scenario(CapDocker), UseCase{Requires: []Capability{CapFirecracker}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sc.Satisfies(tc.uc); got != tc.want {
				t.Fatalf("Satisfies = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMissingCaps(t *testing.T) {
	sc := scenario(CapDocker)
	uc := UseCase{Requires: []Capability{CapDocker, CapDomain, CapWasm}}
	missing := sc.MissingCaps(uc)
	if len(missing) != 2 {
		t.Fatalf("missing = %v, want 2 entries (domain, wasm)", missing)
	}
}

func TestParseCaps(t *testing.T) {
	raw := []byte("name: single-node\ncapabilities: [docker, domain]\n")
	cf, err := parseCaps(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cf.Name != "single-node" {
		t.Fatalf("name = %q", cf.Name)
	}
	if len(cf.Capabilities) != 2 || cf.Capabilities[0] != CapDocker || cf.Capabilities[1] != CapDomain {
		t.Fatalf("caps = %v", cf.Capabilities)
	}
}

// Registry sanity: every Implemented use case must be reachable by the scenario
// that owns it (i.e. its required caps are a real subset of some scenario), and
// no duplicate IDs. Cheap guard against a typo'd capability that would make a UC
// permanently skip everywhere.
func TestRegistryWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, uc := range Registry {
		if uc.ID == "" {
			t.Fatalf("use case with empty ID: %+v", uc)
		}
		if seen[uc.ID] {
			t.Fatalf("duplicate use case ID %q", uc.ID)
		}
		seen[uc.ID] = true
		for _, c := range uc.Requires {
			if !KnownCapabilities[c] {
				t.Fatalf("%s requires unknown capability %q", uc.ID, c)
			}
		}
		// Excludes was never checked. A typo there fails OPEN — the case runs
		// on the profile it was meant to avoid and takes the node down, which
		// is the exact destruction the field exists to prevent.
		for _, c := range uc.Excludes {
			if !KnownCapabilities[c] {
				t.Fatalf("%s excludes unknown capability %q", uc.ID, c)
			}
		}
	}
}

// TestSatisfiesExcludes guards the fail-closed property of Excludes. The whole
// reason the field exists is that UC-116 (backup count 1) and UC-123 (zero
// retention) push daemon config into states internal/config refuses under
// SB_ENTERPRISE_MODE — running them on an enterprise scenario takes the node
// down instead of asserting. A bug here is silent and destructive, so the
// exclusion is tested as its own table alongside Satisfies.
func TestSatisfiesExcludes(t *testing.T) {
	cases := []struct {
		name string
		sc   *Scenario
		uc   UseCase
		want bool
	}{
		{
			"excluded cap present blocks an otherwise-satisfied case",
			scenario(CapCluster, CapEnterprise),
			UseCase{Requires: []Capability{CapCluster}, Excludes: []Capability{CapEnterprise}},
			false,
		},
		{
			"excluded cap absent leaves the case runnable",
			scenario(CapCluster),
			UseCase{Requires: []Capability{CapCluster}, Excludes: []Capability{CapEnterprise}},
			true,
		},
		{
			"exclusion wins when a cap is both required and excluded",
			scenario(CapEnterprise),
			UseCase{Requires: []Capability{CapEnterprise}, Excludes: []Capability{CapEnterprise}},
			false,
		},
		{
			"missing requirement still blocks even with no exclusion hit",
			scenario(),
			UseCase{Requires: []Capability{CapCluster}, Excludes: []Capability{CapEnterprise}},
			false,
		},
		{
			"any one of several exclusions is enough to block",
			scenario(CapCluster, CapSecretsKMS),
			UseCase{Requires: []Capability{CapCluster}, Excludes: []Capability{CapEnterprise, CapSecretsKMS}},
			false,
		},
		{
			"nil Excludes behaves exactly as before",
			scenario(CapCluster, CapEnterprise),
			UseCase{Requires: []Capability{CapCluster}},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sc.Satisfies(tc.uc); got != tc.want {
				t.Fatalf("Satisfies = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBlockingCaps checks the skip message can name the real reason. Reporting
// an exclusion as a "missing capability" sends a reader looking for a cap to
// add to the scenario, which is the opposite of the fix.
func TestBlockingCaps(t *testing.T) {
	sc := scenario(CapCluster, CapEnterprise)
	uc := UseCase{Requires: []Capability{CapCluster}, Excludes: []Capability{CapEnterprise, CapSecretsKMS}}

	blocking := sc.BlockingCaps(uc)
	if len(blocking) != 1 || blocking[0] != CapEnterprise {
		t.Fatalf("BlockingCaps = %v, want [%s]", blocking, CapEnterprise)
	}
	// An exclusion is not a missing requirement; the two lists must not blur.
	if missing := sc.MissingCaps(uc); len(missing) != 0 {
		t.Fatalf("MissingCaps = %v, want empty (the requirement IS met)", missing)
	}
	// No exclusions held => nothing blocking.
	if got := scenario(CapCluster).BlockingCaps(uc); len(got) != 0 {
		t.Fatalf("BlockingCaps on a non-enterprise scenario = %v, want empty", got)
	}
}
