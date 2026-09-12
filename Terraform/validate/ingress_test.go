package validate

import (
	"fmt"
	"testing"
)

func TestIngressCapableMirrorsLocals(t *testing.T) {
	cases := map[string]bool{
		"":                 true, // default role is mixed
		"mixed":            true,
		"ingress":          true,
		"worker,ingress":   true,
		"server, ingress":  true,
		"server":           false,
		"worker":           false,
		"server,worker":    false,
		"  worker ,server": false,
	}
	for role, want := range cases {
		if got := IngressCapable(role); got != want {
			t.Errorf("IngressCapable(%q) = %v, want %v", role, got, want)
		}
	}
}

// Mirrors the plan-time precondition: the repo's own provisioning must not
// produce an ingress tier the daemon refuses to boot.
func TestIngressTierAllowedNeedsShardAwareOptInAboveTheCap(t *testing.T) {
	roles := map[string]string{"seed": "server", "w1": "worker"}
	for i := 0; i < MaxReplicatedIngressRouteNodes; i++ {
		roles[fmt.Sprintf("ingress-%02d", i)] = "ingress"
	}
	if !IngressTierAllowed(roles, false) {
		t.Fatalf("%d ingress nodes must plan without the opt-in", MaxReplicatedIngressRouteNodes)
	}
	roles["edge"] = "worker,ingress" // the 11th ingress-capable node
	if IngressTierAllowed(roles, false) {
		t.Fatal("11 ingress-capable nodes planned without shard_aware_ingress")
	}
	if !IngressTierAllowed(roles, true) {
		t.Fatal("shard_aware_ingress = true must allow the large tier")
	}
	if !IngressTierAllowed(map[string]string{}, false) {
		t.Fatal("empty node map must be allowed")
	}
}
