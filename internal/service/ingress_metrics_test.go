package service

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestHashPlacementViewStable asserts the hash is order-independent and only
// shifts when the inputs the reconciler actually consumes change. This is the
// load-bearing claim behind the idle-skip path: at steady state we must NOT
// flap the hash between ticks, otherwise we'd keep hammering Caddy admin.
func TestHashPlacementViewStable(t *testing.T) {
	a := cluster.Placement{
		SandboxID:          "sb-1",
		OwnerNodeID:        "node-a",
		OwnerAPIURL:        "http://a:21212",
		OwnerDataPlaneHost: "a.lan",
		Version:            5,
	}
	b := cluster.Placement{
		SandboxID:          "sb-2",
		OwnerNodeID:        "node-b",
		OwnerAPIURL:        "http://b:21212",
		OwnerDataPlaneHost: "b.lan",
		Version:            7,
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			3000: {Protocol: models.ExposedPortProtocolHTTP},
			5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22432},
		},
	}

	h1, _, _ := hashPlacementView("self", []cluster.Placement{a, b})
	h2, _, _ := hashPlacementView("self", []cluster.Placement{b, a}) // reversed
	if h1 != h2 {
		t.Fatalf("hash is order-dependent: %x vs %x", h1, h2)
	}
}

// TestHashPlacementViewChangesOnVersion confirms a placement.Version bump is
// observable through the hash — that's how the reconciler notices an
// ExposePort or owner change.
func TestHashPlacementViewChangesOnVersion(t *testing.T) {
	a := cluster.Placement{
		SandboxID:   "sb-1",
		OwnerNodeID: "node-a",
		Version:     5,
	}
	h1, _, _ := hashPlacementView("self", []cluster.Placement{a})
	a.Version = 6
	h2, _, _ := hashPlacementView("self", []cluster.Placement{a})
	if h1 == h2 {
		t.Fatalf("hash did not change after Version bump")
	}
}

// TestHashPlacementViewIgnoresSelfOwned confirms placements that the
// reconciler would skip (owner==self) don't move the hash — otherwise an
// ingress node owning sandboxes locally would defeat its own idle-skip
// every time the local sandbox set churned.
func TestHashPlacementViewIgnoresSelfOwned(t *testing.T) {
	mine := cluster.Placement{SandboxID: "sb-mine", OwnerNodeID: "self", Version: 1}
	theirs := cluster.Placement{SandboxID: "sb-theirs", OwnerNodeID: "other", Version: 1}
	h1, _, _ := hashPlacementView("self", []cluster.Placement{theirs})
	h2, _, _ := hashPlacementView("self", []cluster.Placement{mine, theirs})
	if h1 != h2 {
		t.Fatalf("self-owned placement leaked into hash: %x vs %x", h1, h2)
	}
}

// TestHashPlacementViewCounts checks the per-protocol counters that feed
// the route-count expvars.
func TestHashPlacementViewCounts(t *testing.T) {
	p := cluster.Placement{
		SandboxID:   "sb",
		OwnerNodeID: "remote",
		Version:     1,
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			3000: {Protocol: models.ExposedPortProtocolHTTP},
			8443: {Protocol: models.ExposedPortProtocolTLS},
			5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22432},
		},
	}
	_, counts, maxVersion := hashPlacementView("self", []cluster.Placement{p})
	// The sandbox itself contributes one HTTP-or-TLS entry to counts.http
	// (the reconciler picks the protocol at apply time).
	if counts.http != 2 || counts.tls != 1 || counts.tcp != 1 {
		t.Fatalf("counts mismatch: http=%d tls=%d tcp=%d", counts.http, counts.tls, counts.tcp)
	}
	if maxVersion != 1 {
		t.Fatalf("maxVersion = %d, want 1", maxVersion)
	}
}
