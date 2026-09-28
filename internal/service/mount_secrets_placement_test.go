package service

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A credential outside `credentials` would be replicated in the clear with
// the placement spec. A new request is refused with a pointer to the right
// field; a stored spec replayed for a failover recreate is already
// replicated, so there the rule only warns and the recreate proceeds.
func TestCreateSandboxRefusesCredentialsOutsideCredentialsExceptOnReplay(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	mounts := []models.MountSpec{{
		Type:   models.MountTypeRclone,
		Target: "/data",
		Source: ":s3,provider=AWS,access_key_id=AKIA,secret_access_key=XYZ:bucket",
	}}

	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Mounts: mounts})
	if err == nil || !strings.Contains(err.Error(), "mount 0") || !strings.Contains(err.Error(), "put it in credentials") {
		t.Fatalf("CreateSandbox() error = %v, want the placement rule naming mount 0 and credentials", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
	}

	if err := svc.validateCreateMounts(ctx, mounts, ""); err == nil {
		t.Fatal("new request must be refused")
	}
	if err := svc.validateCreateMounts(contextWithStoredSpecReplay(ctx), mounts, "sb-replayed"); err != nil {
		t.Fatalf("stored-spec replay must proceed (warn only): %v", err)
	}
	// Shape errors are not downgraded on replay: a spec that cannot mount at
	// all still fails.
	broken := []models.MountSpec{{Type: models.MountTypeS3, Target: "relative", Source: "bucket"}}
	if err := svc.validateCreateMounts(contextWithStoredSpecReplay(ctx), broken, "sb-replayed"); err == nil {
		t.Fatal("replay must still enforce the mount shape rules")
	}
	if isStoredSpecReplay(ctx) || !isStoredSpecReplay(contextWithStoredSpecReplay(ctx)) {
		t.Fatal("replay marker did not round-trip")
	}
}
