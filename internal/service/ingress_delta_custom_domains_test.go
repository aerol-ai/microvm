package service

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestBuildClusterIngressIntents_DomainModeAddsPerCustomHostnameSNI:
// cluster ingress on a non-owner node must install one SNI passthrough
// route per FSM-known custom hostname so a TLS connection for
// `api.acme.com` lands on this node and forwards raw to the owner's L4
// TLS listener. Without this, custom-domain requests that hit a
// non-owner node have no matcher and fail to route.
func TestBuildClusterIngressIntents_DomainModeAddsPerCustomHostnameSNI(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			EnableCluster: true,
			Domain:        "sb.example.com",
			L4TLSListen:   ":8443",
		},
	}

	placement := cluster.Placement{
		SandboxID:       "sb-alpha",
		OwnerNodeID:     "peer-1",
		OwnerAPIURL:     "http://10.0.0.7:21212",
		Version:         1,
		CustomHostnames: []string{"api.acme.com", "shop.beta.io"},
	}

	intents, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{placement}, "self")
	if !needL4 {
		t.Fatal("needL4 = false; domain mode must request L4 bootstrap")
	}

	// Default SNI route must still be present.
	defaultKey := ingressIntentKey(ingressSurfaceTLS, caddy.IngressSandboxSNIRouteID("sb-alpha"))
	if _, ok := intents[defaultKey]; !ok {
		t.Fatalf("default SNI intent missing: %s", defaultKey)
	}

	// One SNI intent per custom hostname.
	for _, h := range placement.CustomHostnames {
		key := ingressIntentKey(ingressSurfaceTLS, caddy.IngressCustomDomainSNIRouteID("sb-alpha", h))
		if _, ok := intents[key]; !ok {
			t.Fatalf("custom-hostname SNI intent missing for %q: %s", h, key)
		}
	}
}

// TestBuildClusterIngressIntents_CustomHostnameDeltaFiresApply: a
// hostname added on the next FSM version must produce a single new
// intent (and bump the placement version so the delta planner emits an
// apply for it). Catches the "added hostname but route never installed"
// failure mode where the version doesn't carry into the fingerprint.
func TestBuildClusterIngressIntents_CustomHostnameDeltaFiresApply(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			EnableCluster: true,
			Domain:        "sb.example.com",
			L4TLSListen:   ":8443",
		},
		ingressRouteCache: map[string]ingressRouteIntent{},
	}

	base := cluster.Placement{
		SandboxID:       "sb-alpha",
		OwnerNodeID:     "peer-1",
		OwnerAPIURL:     "http://10.0.0.7:21212",
		Version:         1,
		CustomHostnames: []string{"api.acme.com"},
	}
	initial, _ := svc.buildClusterIngressIntents([]cluster.Placement{base}, "self")
	ops, commit := svc.planClusterIngressDelta(initial)
	if len(ops) != len(initial) {
		t.Fatalf("initial delta ops=%d, want %d", len(ops), len(initial))
	}
	commit()

	// Add a second custom hostname; bump version so the FSM signals a
	// route-affecting change.
	next := base
	next.Version = 2
	next.CustomHostnames = []string{"api.acme.com", "shop.beta.io"}
	updated, _ := svc.buildClusterIngressIntents([]cluster.Placement{next}, "self")
	ops, _ = svc.planClusterIngressDelta(updated)

	// Two ops expected: default SNI route's fingerprint changed (version
	// bump), and one new custom-hostname SNI route appears. The first
	// custom hostname's route was cached and the fingerprint includes
	// hostname so it also reapplies — 3 ops total.
	if len(ops) < 1 {
		t.Fatalf("delta produced 0 ops; expected at least 1 for added hostname")
	}

	newKey := ingressIntentKey(ingressSurfaceTLS, caddy.IngressCustomDomainSNIRouteID("sb-alpha", "shop.beta.io"))
	if _, ok := updated[newKey]; !ok {
		t.Fatalf("added hostname missing from desired intents: %s", newKey)
	}
}

// TestBuildClusterIngressIntents_IPModePropagatesHostnamesInFingerprint:
// IP mode doesn't host-match cross-node, but the fingerprint must
// include CustomHostnames so a future FSM hostname change still triggers
// a reapply (caddy.UpsertSandboxRouteToPeer is idempotent — the cost of
// an unnecessary apply is one PATCH, but a missed apply silently leaves
// stale state). Guards the plumbing even though current configs reject
// custom domains in IP mode at the service layer.
func TestBuildClusterIngressIntents_IPModePropagatesHostnamesInFingerprint(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true, Domain: ""}}

	base := cluster.Placement{
		SandboxID:       "sb-ip",
		OwnerNodeID:     "peer-1",
		OwnerAPIURL:     "http://10.0.0.7:21212",
		Version:         1,
		CustomHostnames: nil,
	}
	without, _ := svc.buildClusterIngressIntents([]cluster.Placement{base}, "self")

	hosted := base
	hosted.CustomHostnames = []string{"api.acme.com"}
	with, _ := svc.buildClusterIngressIntents([]cluster.Placement{hosted}, "self")

	key := ingressIntentKey(ingressSurfaceHTTP, "sandbox-sb-ip")
	if withFP, withoutFP := with[key].fingerprint, without[key].fingerprint; withFP == withoutFP {
		t.Fatalf("fingerprint did not change when CustomHostnames went nil → [%q]; without=%d with=%d",
			"api.acme.com", withoutFP, withFP)
	}
}

func TestBuildClusterIngressIntentsSkipAndInfluxBranches(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true, Domain: "sb.example.com"}}

	intents, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{
		{SandboxID: "", OwnerNodeID: "peer-1"},
		{SandboxID: "sb-self", OwnerNodeID: "self", OwnerAPIURL: "http://self", Version: 1},
		{
			SandboxID:   "sb-influx",
			OwnerNodeID: "",
			Version:     7,
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				8080: {Protocol: models.ExposedPortProtocolHTTP},
			},
		},
	}, "self")
	if !needL4 {
		t.Fatal("needL4 should be true when adding an in-flux placement")
	}
	key := ingressIntentKey(ingressSurfaceHTTP, caddy.InFluxSandboxRouteID("sb-influx"))
	if _, ok := intents[key]; !ok {
		t.Fatalf("in-flux intent missing for %s", key)
	}
}

func TestBuildClusterIngressIntentsDomainWithoutTLSPortSkipsRoutes(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			EnableCluster: true,
			Domain:        "sb.example.com",
		},
	}

	intents, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{
		{
			SandboxID:       "sb-no-l4",
			OwnerNodeID:     "peer-1",
			OwnerAPIURL:     "http://10.0.0.2:21212",
			Version:         3,
			CustomHostnames: []string{"api.acme.com"},
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				8080: {Protocol: models.ExposedPortProtocolHTTP},
			},
		},
	}, "self")
	if !needL4 {
		t.Fatal("needL4 should stay true in domain mode")
	}
	if len(intents) != 0 {
		t.Fatalf("expected no routes when L4 TLS listener port is absent, got %d", len(intents))
	}
}
