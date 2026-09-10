package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type authPlacementsCluster struct {
	*cluster.Noop
	err        error
	placements map[string]cluster.Placement
}

func (c *authPlacementsCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.placements, nil
}

func TestOwnerRefForCreateExported(t *testing.T) {
	if got := OwnerRefForCreate(context.Background()); got != "" {
		t.Fatalf("unscoped = %q", got)
	}
	if got := OwnerRefForCreate(controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})); got != "" {
		t.Fatalf("operator = %q", got)
	}
	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acme"}})
	if got := OwnerRefForCreate(ctx); got != "acme" {
		t.Fatalf("user = %q", got)
	}
}

func TestDeleteClusterSecretsForAuthoritativePlacementGuards(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb"); err != nil {
		t.Fatalf("nil service = %v", err)
	}
	if err := (&Service{}).DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("no cluster = %v", err)
	}

	svc := &Service{cluster: &authPlacementsCluster{Noop: cluster.NewNoop("self", "", ""), err: errors.New("raft down")}}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-1"); err == nil || !strings.Contains(err.Error(), "authoritative placement read") {
		t.Fatalf("read error = %v", err)
	}

	svc.cluster = &authPlacementsCluster{Noop: cluster.NewNoop("self", "", ""), placements: map[string]cluster.Placement{}}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-1"); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("missing placement = %v", err)
	}

	svc.cluster = &authPlacementsCluster{Noop: cluster.NewNoop("self", "", ""), placements: map[string]cluster.Placement{
		"sb-1": {SandboxID: "sb-1"},
	}}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-1"); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("missing incarnation = %v", err)
	}
}
