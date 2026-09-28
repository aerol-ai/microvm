package service

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type ownerRefPlacementCluster struct {
	*cluster.Noop
	ownerRef string
}

func (c *ownerRefPlacementCluster) PlacementOf(sandboxID string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: sandboxID, OwnerRef: c.ownerRef}, true
}

func TestOwnerRefForCreateOrRecreateUsesPlacement(t *testing.T) {
	svc := &Service{
		cluster: &ownerRefPlacementCluster{
			Noop:     cluster.NewNoop("node-a", "", ""),
			ownerRef: "tenant-from-placement",
		},
	}
	// Unscoped context (owner watcher): must recover OwnerRef from Placement.
	got := svc.ownerRefForCreateOrRecreate(context.Background(), "sb-failover")
	if got != "tenant-from-placement" {
		t.Fatalf("got %q, want placement OwnerRef", got)
	}

	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "tenant-from-token"},
	})
	got = svc.ownerRefForCreateOrRecreate(ctx, "sb-failover")
	if got != "tenant-from-token" {
		t.Fatalf("scoped create got %q, want token OwnerRef", got)
	}
}
