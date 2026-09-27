package service

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A dedicated ingress only ever sees redacted placements (no Spec). It must
// still build the L4 route for a public sandbox's TCP exposure from the
// hot-row flag — before, it skipped every remote sandbox (T18, UC-34).
func TestIngressIntentsUseTheHotRowPublicFlag(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	redacted := func(public bool) cluster.Placement {
		return cluster.Placement{
			SandboxID: "sb-tcp", OwnerNodeID: "worker-1", OwnerDataPlaneHost: "10.0.0.2",
			PublicTraffic: public,
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22432},
			},
		}
	}
	intents, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{redacted(true)}, "ingress-1")
	if _, ok := intents[ingressIntentKey(ingressSurfaceTCP, "tcp-port-22432")]; !ok || !needL4 {
		t.Fatalf("public redacted placement produced no TCP route (needL4=%v, intents=%d)", needL4, len(intents))
	}
	intents, _ = svc.buildClusterIngressIntents([]cluster.Placement{redacted(false)}, "ingress-1")
	if len(intents) != 0 {
		t.Fatalf("a private sandbox got %d ingress routes", len(intents))
	}
}
