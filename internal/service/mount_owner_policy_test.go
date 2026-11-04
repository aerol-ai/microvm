package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func ownerScopedCtx(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{ExternalID: "user-" + owner, OwnerRef: owner},
	})
}

// A validated user token is not a host operator, so a raw mount (which runs
// host-side as the daemon user, pr-review.md §5) must be refused for an
// owner-scoped caller, while operator/PAT and internal replay/failover
// (unscoped) callers keep the capability.
func TestValidateCreateMounts_RawMountsAreOperatorOnly(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	raw := []models.MountSpec{{Type: models.MountTypeNFS, Target: "/loot", Source: "nfs.internal:/exports/aerolvm"}}

	if err := svc.validateCreateMounts(ownerScopedCtx("tenant-a"), raw, "sb-a"); !errors.Is(err, models.ErrMountOperatorOnly) {
		t.Fatalf("owner-scoped raw mount error = %v, want ErrMountOperatorOnly", err)
	}
	// Operator (PAT) is unscoped: the raw mount is accepted by policy and only
	// subject to the normal shape/placement checks.
	if err := svc.validateCreateMounts(operatorCtx(), raw, "sb-op"); err != nil {
		t.Fatalf("operator raw mount rejected: %v", err)
	}
	// Internal callers with no Access (failover recreate, background loops) pass.
	if err := svc.validateCreateMounts(context.Background(), raw, "sb-bg"); err != nil {
		t.Fatalf("internal raw mount rejected: %v", err)
	}
	// An owner-scoped caller with NO raw mounts is unaffected (platform volumes
	// are a separate field and stay available to tenants).
	if err := svc.validateCreateMounts(ownerScopedCtx("tenant-a"), nil, "sb-a2"); err != nil {
		t.Fatalf("owner-scoped create without raw mounts rejected: %v", err)
	}
}
