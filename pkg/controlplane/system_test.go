package controlplane

import (
	"context"
	"testing"
)

func TestSystemPrincipal(t *testing.T) {
	cases := []struct {
		subsystem string
		wantID    string
	}{
		{"reconcile", "system:reconcile"},
		{" lifecycle ", "system:lifecycle"},
		{"", "system:daemon"},
	}
	for _, tc := range cases {
		got := SystemPrincipal(tc.subsystem)
		if got.Kind != PrincipalSystem || got.ID != tc.wantID || got.Name != "" {
			t.Errorf("SystemPrincipal(%q) = %+v, want kind system id %s", tc.subsystem, got, tc.wantID)
		}
	}
}

func TestSystemCallerContext(t *testing.T) {
	if _, ok := SystemCallerFromContext(context.Background()); ok {
		t.Fatal("a plain context carries no system caller")
	}
	if _, ok := SystemCallerFromContext(nil); ok {
		t.Fatal("a nil context carries no system caller")
	}
	ctx := ContextWithSystemCaller(context.Background(), "failover")
	p, ok := SystemCallerFromContext(ctx)
	if !ok || p.ID != "system:failover" {
		t.Fatalf("round trip = %+v, %v", p, ok)
	}
	// The innermost tag wins: a loop that calls a tagged helper names the
	// helper's subsystem.
	inner := ContextWithSystemCaller(ctx, "reconcile")
	if p, _ := SystemCallerFromContext(inner); p.ID != "system:reconcile" {
		t.Fatalf("nested tag = %s, want system:reconcile", p.ID)
	}
	// Attribution only: a system caller never becomes an Access, so owner
	// scoping still sees background work as unscoped.
	if _, ok := AccessFromContext(inner); ok {
		t.Fatal("a system caller must not attach an Access")
	}
	if p, ok := SystemCallerFromContext(ContextWithSystemCaller(nil, "gc")); !ok || p.ID != "system:gc" {
		t.Fatalf("nil parent = %+v, %v", p, ok)
	}
}
