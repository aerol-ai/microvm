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

// TestLoadEnvFailsLoudWhenSealedRowIsMissing pins the fail-loud contract for
// sealed environments. A sandbox created WITH an environment whose sandbox_env
// row then disappears must not read back as "this sandbox has no environment":
// that is how a start or wake without a replicated spec silently boots a
// sandbox stripped of the credentials it was created with.
func TestLoadEnvFailsLoudWhenSealedRowIsMissing(t *testing.T) {
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	ctx := t.Context()

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20",
		Env:   map[string]string{"TOKEN": "s3cret"},
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	id := resp.Sandbox.ID

	env, err := svc.loadEnv(ctx, id, resp.Sandbox.AuditIncarnationID)
	if err != nil || env["TOKEN"] != "s3cret" {
		t.Fatalf("loadEnv = %v, %v; want the sealed environment", env, err)
	}

	if err := st.DeleteEnv(ctx, id); err != nil {
		t.Fatalf("DeleteEnv: %v", err)
	}
	if _, err := svc.loadEnv(ctx, id, resp.Sandbox.AuditIncarnationID); err == nil {
		t.Fatal("loadEnv returned an environment after its sealed row was deleted")
	}

	// A sandbox genuinely created without an environment still reads as empty,
	// because create writes an empty row rather than no row at all.
	bare, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox without env: %v", err)
	}
	env, err = svc.loadEnv(ctx, bare.Sandbox.ID, bare.Sandbox.AuditIncarnationID)
	if err != nil {
		t.Fatalf("loadEnv for an env-less sandbox = %v", err)
	}
	if len(env) != 0 {
		t.Fatalf("loadEnv for an env-less sandbox = %v, want empty", env)
	}
}
