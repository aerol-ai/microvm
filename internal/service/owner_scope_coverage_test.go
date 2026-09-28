package service

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

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
