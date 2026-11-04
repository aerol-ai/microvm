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
		controlplane.Access{Fleet: true})
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

// TestOwnerRefForCreateFleetRunner (eng review ET9, plan §5.1): a runner
// bound to every team creates exactly as the PAT does. Its sandboxes carry
// owner "", and a create resolves only operator-published ("") snapshots by
// name, never a team's (snapshotResolvableForCreate, #7), although it can
// SEE every team's snapshot.
func TestOwnerRefForCreateFleetRunner(t *testing.T) {
	fleetRunner := boundCtx(controlplane.PrincipalToken, controlplane.RoleRunner, controlplane.FleetTeam)
	if got := ownerRefForCreate(fleetRunner); got != "" {
		t.Fatalf("fleet runner create owner = %q, want empty", got)
	}
	team := &models.SandboxSnapshot{Name: "s", OwnerRef: controlplane.TeamOwnerRef("payments")}
	operator := &models.SandboxSnapshot{Name: "s"}
	if snapshotResolvableForCreate(fleetRunner, team) || !snapshotResolvableForCreate(fleetRunner, operator) {
		t.Fatal("a fleet runner's create must resolve only operator-published snapshots by name")
	}
	if !snapshotVisible(fleetRunner, team) {
		t.Fatal("a fleet runner sees every team's snapshots")
	}

	// Through the create path: a tenant that registered a snapshot named
	// after a public image does not capture the fleet runner's create.
	svc, _, _ := newSnapshotOwnerService(t)
	if _, err := svc.RegisterSnapshot(userCtx("globex"), &models.SandboxSnapshot{Name: "ubuntu:22.04", Image: "ghcr.io/globex/backdoor:latest"}); err != nil {
		t.Fatal(err)
	}
	req := models.CreateSandboxRequest{Image: "ubuntu:22.04"}
	if err := svc.NormalizeCreateImageDistribution(fleetRunner, &req); err != nil || req.Image != "ubuntu:22.04" {
		t.Fatalf("fleet runner create image = %q, %v; want the plain base image", req.Image, err)
	}

	// And the sandbox row it creates carries owner "".
	created, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := created.CreateSandboxWithID(fleetRunner, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-fleet-runner"); err != nil {
		t.Fatalf("fleet runner create: %v", err)
	}
	row, err := st.Get(context.Background(), "sb-fleet-runner")
	if err != nil || row.OwnerRef != "" {
		t.Fatalf("fleet runner sandbox = %+v, %v; want owner \"\"", row, err)
	}
}
