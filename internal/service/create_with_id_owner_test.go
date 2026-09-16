package service

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreateSandboxWithIDRejectsForeignOwner pins the second half of the E2B
// cross-tenant disclosure closed. The fast path returns a fully-hydrated row
// (toolbox token included), so a caller scoped to another tenant must be
// refused even when it supplies a valid existing id. The owner-watcher and
// failover recreate paths carry no Access and must keep working.
func TestCreateSandboxWithIDRejectsForeignOwner(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil

	const id = "sb-owner-fence"
	created, err := svc.CreateSandboxWithID(userCtx("tenant-a"), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	if created.Sandbox.OwnerRef != "tenant-a" {
		t.Fatalf("seeded owner_ref = %q, want tenant-a", created.Sandbox.OwnerRef)
	}
	if created.Sandbox.ToolboxToken == "" {
		t.Skip("runtime harness does not issue a toolbox token; the disclosure surface is not exercised")
	}

	if _, err := svc.CreateSandboxWithID(userCtx("tenant-b"), models.CreateSandboxRequest{Image: "alpine:3.20"}, id); !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("cross-tenant CreateSandboxWithID error = %v, want ErrSandboxExists", err)
	}

	// Same tenant replays the existing row.
	replay, err := svc.CreateSandboxWithID(userCtx("tenant-a"), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
	if err != nil {
		t.Fatalf("same-tenant replay error = %v", err)
	}
	if replay.Sandbox.ID != id {
		t.Fatalf("same-tenant replay id = %q, want %q", replay.Sandbox.ID, id)
	}

	// The owner watcher / failover recreate path is unscoped and must pass.
	internalReplay, err := svc.CreateSandboxWithID(t.Context(), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
	if err != nil {
		t.Fatalf("internal recreate error = %v", err)
	}
	if internalReplay.Sandbox.ID != id {
		t.Fatalf("internal recreate id = %q, want %q", internalReplay.Sandbox.ID, id)
	}

	// Operator tokens keep fleet-wide reach.
	operatorReplay, err := svc.CreateSandboxWithID(operatorCtx(), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
	if err != nil {
		t.Fatalf("operator recreate error = %v", err)
	}
	if operatorReplay.Sandbox.ID != id {
		t.Fatalf("operator recreate id = %q, want %q", operatorReplay.Sandbox.ID, id)
	}
}
