package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeSandboxMetaFetcher struct {
	ownerRef string
	ok       bool
	err      error
}

func (f *fakeSandboxMetaFetcher) FetchSandboxOwnerRef(context.Context, string, string) (string, bool, error) {
	return f.ownerRef, f.ok, f.err
}

type placementOnlyCluster struct {
	*cluster.Noop
	placement     cluster.Placement
	auditOwner    string
	auditExists   bool
	auditOwnerErr error
}

func (c *placementOnlyCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.placement.SandboxID != ""
}

func (c *placementOnlyCluster) AuditOwnerRef(context.Context, string) (string, bool, error) {
	return c.auditOwner, c.auditExists, c.auditOwnerErr
}

func TestAuthorizeSandboxAuditAccessViaOwnerMeta(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(config.Config{DBPath: filepath.Join(t.TempDir(), "x.db")}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.cluster = &placementOnlyCluster{
		Noop: cluster.NewNoop("ingress", "http://ingress", ""),
		placement: cluster.Placement{
			SandboxID:   "sb-remote",
			OwnerNodeID: "owner",
			OwnerAPIURL: "http://owner",
		},
	}
	svc.testSandboxMetaFetcher = &fakeSandboxMetaFetcher{ownerRef: "acme", ok: true}

	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(ctx, "sb-remote"); err != nil {
		t.Fatalf("owner tenant: %v", err)
	}
	evil := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "evil"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(evil, "sb-remote"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("evil tenant = %v, want ErrNotFound", err)
	}
	op := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	if err := svc.AuthorizeSandboxAuditAccess(op, "sb-remote"); err != nil {
		t.Fatalf("operator: %v", err)
	}
}

func TestAuthorizeSandboxAuditAccessLocalRow(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-local", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		OwnerRef: "acme", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	svc := New(config.Config{}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("n", "http://n", ""))
	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(ctx, "sb-local"); err != nil {
		t.Fatalf("local owner: %v", err)
	}
}

func TestAuthorizeSandboxAuditAccessAfterDeleteViaRaftACL(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(config.Config{}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.cluster = &placementOnlyCluster{
		Noop:        cluster.NewNoop("ingress", "http://ingress", ""),
		auditOwner:  "acme",
		auditExists: true,
	}

	owner := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(owner, "sb-deleted"); err != nil {
		t.Fatalf("retained owner ACL: %v", err)
	}
	other := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "other"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(other, "sb-deleted"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign tenant = %v, want ErrNotFound", err)
	}

	svc.cluster.(*placementOnlyCluster).auditOwnerErr = errors.New("raft unavailable")
	if err := svc.AuthorizeSandboxAuditAccess(owner, "sb-deleted"); err == nil || err.Error() != "raft unavailable" {
		t.Fatalf("raft failure = %v, want fail-closed error", err)
	}
}
