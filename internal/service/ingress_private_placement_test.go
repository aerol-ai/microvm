package service

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// These tests pin the cluster half of the private-by-default contract: the
// ingress reconciler must install ZERO routes on any node for a placement
// whose replicated spec has allow_public_traffic=false — the gate
// (placementAllowsPublicTraffic in buildClusterIngressIntents) runs before
// intent construction, including the in-flux branch. Without this gate a
// single ingress tick would re-publish every private sandbox cluster-wide,
// silently undoing both the privacy contract and the zero-caddy-on-boot
// latency win the flag exists for.

func privateFlag(v bool) *bool { return &v }

func ingressTestService(domain string) *Service {
	return &Service{
		cfg:   config.Config{EnableCluster: true, Domain: domain, L4TLSListen: ":8443"},
		caddy: caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}
}

// publicishPlacement returns a placement that would produce a full set of
// intents (root SNI + port routes + custom hostname) if it were public. The
// private tests reuse it verbatim with only the flag flipped, so the zero
// result can only come from the gate — not from the payload being empty.
func publicishPlacement(id string, allow *bool) cluster.Placement {
	return cluster.Placement{
		SandboxID:   id,
		OwnerNodeID: "peer-1",
		OwnerAPIURL: "http://10.0.0.2:8080",
		Version:     3,
		Spec:        &models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: allow},
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			8080: {Protocol: models.ExposedPortProtocolHTTP},
			5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 25432},
			8443: {Protocol: models.ExposedPortProtocolTLS},
			9090: {},
		},
		CustomHostnames: []string{"api.acme.test"},
	}
}

func TestClusterIngressSkipsPrivatePlacements(t *testing.T) {
	svc := ingressTestService("sb.example.com")

	// Private placement — even one that (through a bug or stale state)
	// carries port routes and custom hostnames — must produce zero intents.
	private := publicishPlacement("sb-private", privateFlag(false))
	intents, _ := svc.buildClusterIngressIntents([]cluster.Placement{private}, "self")
	if len(intents) != 0 {
		t.Fatalf("private placement produced %d ingress intents, want 0: %v", len(intents), intentKeys(intents))
	}

	// Control: the identical placement with the flag flipped produces the
	// full route set — proving the zero above came from the gate.
	public := publicishPlacement("sb-public", privateFlag(true))
	intents, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{public}, "self")
	if len(intents) == 0 {
		t.Fatal("public placement produced no intents; control is broken")
	}
	if !needL4 {
		t.Fatal("public placement with tcp/tls exposure should need L4")
	}

	// Missing replicated policy fails private; incomplete state must never
	// synthesize public ingress.
	missing := publicishPlacement("sb-missing-policy", nil)
	missing.Spec = nil
	intents, _ = svc.buildClusterIngressIntents([]cluster.Placement{missing}, "self")
	if len(intents) != 0 {
		t.Fatalf("missing-policy placement produced %d intents, want zero", len(intents))
	}
}

func TestClusterIngressSkipsPrivateInFluxPlacements(t *testing.T) {
	svc := ingressTestService("sb.example.com")

	// The in-flux branch (owner unknown mid-failover) runs AFTER the public
	// gate: a private sandbox must not get an in-flux holding route either —
	// that route answers on the sandbox's hostname, which is exactly what
	// private forbids.
	private := publicishPlacement("sb-private-flux", privateFlag(false))
	private.OwnerNodeID = ""
	private.OwnerAPIURL = ""
	intents, _ := svc.buildClusterIngressIntents([]cluster.Placement{private}, "self")
	if len(intents) != 0 {
		t.Fatalf("private in-flux placement produced %d intents, want 0: %v", len(intents), intentKeys(intents))
	}

	// Control: the public in-flux placement gets its holding route.
	public := publicishPlacement("sb-public-flux", privateFlag(true))
	public.OwnerNodeID = ""
	public.OwnerAPIURL = ""
	intents, _ = svc.buildClusterIngressIntents([]cluster.Placement{public}, "self")
	if _, ok := intents[ingressIntentKey(ingressSurfaceHTTP, caddy.InFluxSandboxRouteID("sb-public-flux"))]; !ok {
		t.Fatalf("public in-flux placement missing holding route: %v", intentKeys(intents))
	}
}

func TestClusterIngressSkipsPrivatePlacementsIPMode(t *testing.T) {
	// Same gate, IP mode (no Domain): the HTTP peer-forward branch must be
	// skipped for private placements too.
	svc := ingressTestService("")

	private := publicishPlacement("sb-private-ip", privateFlag(false))
	intents, _ := svc.buildClusterIngressIntents([]cluster.Placement{private}, "self")
	if len(intents) != 0 {
		t.Fatalf("private placement (IP mode) produced %d intents, want 0: %v", len(intents), intentKeys(intents))
	}

	public := publicishPlacement("sb-public-ip", privateFlag(true))
	intents, _ = svc.buildClusterIngressIntents([]cluster.Placement{public}, "self")
	if _, ok := intents[ingressIntentKey(ingressSurfaceHTTP, "sandbox-sb-public-ip")]; !ok {
		t.Fatalf("public placement (IP mode) missing peer-forward route: %v", intentKeys(intents))
	}
}

func intentKeys(intents map[string]ingressRouteIntent) []string {
	keys := make([]string, 0, len(intents))
	for k := range intents {
		keys = append(keys, k)
	}
	return keys
}
