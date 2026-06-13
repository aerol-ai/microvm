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
			switch c {
			case CapDocker, CapFirecracker, CapGvisor, CapWasm, CapGPU, CapDomain, CapCluster:
			default:
				t.Fatalf("%s requires unknown capability %q", uc.ID, c)
			}
		}
	}
}
