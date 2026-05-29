package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func userCtx(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(),
		controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}})
}

func operatorCtx() context.Context {
	return controlplane.ContextWithAccess(context.Background(),
		controlplane.Access{Operator: true})
}

func TestOwnerScope(t *testing.T) {
	// No Access in ctx → unscoped (internal/background callers).
	if owner, scoped := ownerScope(context.Background()); scoped || owner != "" {
		t.Fatalf("bare ctx: got (%q, %v), want (\"\", false)", owner, scoped)
	}
	// Operator → unscoped.
	if owner, scoped := ownerScope(operatorCtx()); scoped || owner != "" {
		t.Fatalf("operator ctx: got (%q, %v), want (\"\", false)", owner, scoped)
	}
	// User token → scoped to its owner.
	if owner, scoped := ownerScope(userCtx("acme")); !scoped || owner != "acme" {
		t.Fatalf("user ctx: got (%q, %v), want (\"acme\", true)", owner, scoped)
	}
}

func TestEnforceOwner(t *testing.T) {
	own := &models.Sandbox{ID: "sb1", OwnerRef: "acme"}

	// Operator and internal callers always pass.
	if err := enforceOwner(operatorCtx(), own); err != nil {
		t.Fatalf("operator should pass, got %v", err)
	}
	if err := enforceOwner(context.Background(), own); err != nil {
		t.Fatalf("internal should pass, got %v", err)
	}
	// Matching owner passes.
	if err := enforceOwner(userCtx("acme"), own); err != nil {
		t.Fatalf("matching owner should pass, got %v", err)
	}
	// Cross-owner is denied as ErrNotFound (no existence leak).
	if err := enforceOwner(userCtx("evil"), own); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-owner: got %v, want ErrNotFound", err)
	}
	// A user token never matches an owner-less (operator-created) sandbox.
	if err := enforceOwner(userCtx("acme"), &models.Sandbox{ID: "sb2", OwnerRef: ""}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("owner-less sandbox vs user: got %v, want ErrNotFound", err)
	}
}

func TestFilterByOwnerScope(t *testing.T) {
	all := []*models.Sandbox{
		{ID: "a", OwnerRef: "acme"},
		{ID: "b", OwnerRef: "globex"},
		{ID: "c", OwnerRef: "acme"},
		{ID: "d", OwnerRef: ""},
	}
	// Operator sees everything.
	if got := filterByOwnerScope(operatorCtx(), all); len(got) != 4 {
		t.Fatalf("operator: got %d, want 4", len(got))
	}
	// User sees only its own.
	got := filterByOwnerScope(userCtx("acme"), all)
	if len(got) != 2 {
		t.Fatalf("user acme: got %d, want 2", len(got))
	}
	for _, sb := range got {
		if sb.OwnerRef != "acme" {
			t.Fatalf("user acme leaked %q (owner %q)", sb.ID, sb.OwnerRef)
		}
	}
}

func TestOwnerRefForCreate(t *testing.T) {
	if got := ownerRefForCreate(operatorCtx()); got != "" {
		t.Fatalf("operator create owner = %q, want empty", got)
	}
	if got := ownerRefForCreate(context.Background()); got != "" {
		t.Fatalf("internal create owner = %q, want empty", got)
	}
	if got := ownerRefForCreate(userCtx("acme")); got != "acme" {
		t.Fatalf("user create owner = %q, want acme", got)
	}
}
