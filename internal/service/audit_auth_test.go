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

func authorizeSandboxAuditAccess(s *Service, ctx context.Context, sandboxID, incarnationID string) error {
	_, err := s.AuthorizeSandboxAuditAccess(ctx, sandboxID, incarnationID)
	return err
}

type placementOnlyCluster struct {
	*cluster.Noop
	placement     cluster.Placement
	auditOwner    string
	auditInc      string
	auditExists   bool
	auditOwnerErr error
}

func (c *placementOnlyCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.placement.SandboxID != ""
}

func (c *placementOnlyCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement)
	for _, id := range ids {
		if id == c.placement.SandboxID && id != "" {
			out[id] = c.placement
		}
	}
	return out
}

func (c *placementOnlyCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	return c.PlacementsByIDs(ids), nil
}

func (c *placementOnlyCluster) AuditOwnerRef(context.Context, string) (string, bool, error) {
	return c.auditOwner, c.auditExists, c.auditOwnerErr
}

func (c *placementOnlyCluster) AuditACLForSandbox(context.Context, string, string) (cluster.AuditACL, bool, error) {
	return cluster.AuditACL{OwnerRef: c.auditOwner, IncarnationID: c.auditInc}, c.auditExists, c.auditOwnerErr
}

func TestAuthorizeSandboxAuditAccessViaPlacementOwnerRef(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(config.Config{DBPath: filepath.Join(t.TempDir(), "x.db")}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.cluster = &placementOnlyCluster{
		Noop: cluster.NewNoop("ingress", "http://ingress", ""),
		placement: cluster.Placement{
			SandboxID:     "sb-remote",
			OwnerNodeID:   "owner",
			OwnerAPIURL:   "http://owner",
			OwnerRef:      "acme",
			IncarnationID: "inc-remote",
		},
	}

	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})
	if incarnationID, err := svc.AuthorizeSandboxAuditAccess(ctx, "sb-remote", ""); err != nil || incarnationID != "inc-remote" {
		t.Fatalf("owner tenant: incarnation=%q err=%v", incarnationID, err)
	}
	evil := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "evil"},
	})
	if err := authorizeSandboxAuditAccess(svc, evil, "sb-remote", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("evil tenant = %v, want ErrNotFound", err)
	}
	op := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	if err := authorizeSandboxAuditAccess(svc, op, "sb-remote", ""); err != nil {
		t.Fatalf("operator: %v", err)
	}
	svc.cluster.(*placementOnlyCluster).placement.OwnerRef = ""
	if err := authorizeSandboxAuditAccess(svc, ctx, "sb-remote", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("placement without replicated owner ref = %v, want fail closed", err)
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
		AuditIncarnationID: "inc-local",
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	svc := New(config.Config{}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("n", "http://n", ""))
	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})
	if err := authorizeSandboxAuditAccess(svc, ctx, "sb-local", ""); err != nil {
		t.Fatalf("local owner: %v", err)
	}
}

func TestAuthorizeSandboxAuditAccessRejectsUnscopedLifecycleMetadata(t *testing.T) {
	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	svc := &Service{cluster: &placementOnlyCluster{
		Noop:      cluster.NewNoop("ingress", "http://ingress", ""),
		placement: cluster.Placement{SandboxID: "sb-live", OwnerNodeID: "owner"},
	}}
	if err := authorizeSandboxAuditAccess(svc, ctx, "sb-live", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("placement without incarnation = %v, want ErrNotFound", err)
	}

	svc.cluster = &placementOnlyCluster{
		Noop:        cluster.NewNoop("ingress", "http://ingress", ""),
		auditOwner:  "tenant-a",
		auditExists: true,
	}
	if err := authorizeSandboxAuditAccess(svc, ctx, "sb-deleted", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("retained ACL without incarnation = %v, want ErrNotFound", err)
	}
}

func TestRetainSandboxAuditACLDoesNotAdoptNewerClusterLifecycle(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(config.Config{}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.cluster = &placementOnlyCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID:     "sb-ownerless-finalizer",
			OwnerNodeID:   "node-a",
			IncarnationID: "inc-current",
		},
	}
	sb := &models.Sandbox{ID: "sb-ownerless-finalizer", AuditIncarnationID: "inc-local"}
	if err := svc.retainSandboxAuditACL(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	exists, err := st.HasSandboxAuditACL(context.Background(), sb.ID, "inc-local")
	if err != nil || !exists {
		t.Fatalf("incarnation ACL exists=%v err=%v", exists, err)
	}
	if exists, err := st.HasSandboxAuditACL(context.Background(), sb.ID, "inc-current"); err != nil || exists {
		t.Fatalf("newer cluster lifecycle must not be retained from stale local row: exists=%v err=%v", exists, err)
	}
}

func TestAuthorizeSandboxAuditAccessDoesNotBindStaleLocalOwnerToNewPlacement(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-reused", Image: "alpine", Status: models.SandboxStatusStarted,
		OwnerRef: "tenant-old", AuditIncarnationID: "inc-old",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc := New(config.Config{}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.cluster = &placementOnlyCluster{
		Noop: cluster.NewNoop("ingress", "http://ingress", ""),
		placement: cluster.Placement{
			SandboxID: "sb-reused", OwnerNodeID: "new-owner", OwnerRef: "tenant-new", IncarnationID: "inc-new",
		},
	}
	oldTenant := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "tenant-old"},
	})
	if err := authorizeSandboxAuditAccess(svc, oldTenant, "sb-reused", "inc-new"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("stale local tenant authorized for new lifecycle: %v", err)
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
		auditInc:    "inc-retained",
		auditExists: true,
	}

	owner := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})
	if incarnationID, err := svc.AuthorizeSandboxAuditAccess(owner, "sb-deleted", ""); err != nil || incarnationID != "inc-retained" {
		t.Fatalf("retained owner ACL: incarnation=%q err=%v", incarnationID, err)
	}
	if err := authorizeSandboxAuditAccess(svc, owner, "sb-deleted", "inc-other"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("wrong retained incarnation = %v, want ErrNotFound", err)
	}
	operator := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	if err := authorizeSandboxAuditAccess(svc, operator, "sb-deleted", "inc-other"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("operator wrong retained incarnation = %v, want ErrNotFound", err)
	}
	other := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "other"},
	})
	if err := authorizeSandboxAuditAccess(svc, other, "sb-deleted", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign tenant = %v, want ErrNotFound", err)
	}

	svc.cluster.(*placementOnlyCluster).auditOwnerErr = errors.New("raft unavailable")
	if err := authorizeSandboxAuditAccess(svc, owner, "sb-deleted", ""); err == nil || err.Error() != "raft unavailable" {
		t.Fatalf("raft failure = %v, want fail-closed error", err)
	}
}

func TestAuditAuthorizationNilAndClosedStorePaths(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).retainSandboxAuditACL(ctx, &models.Sandbox{ID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).retainSandboxAuditACL(ctx, &models.Sandbox{ID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{store: &storepkg.Store{}}).retainSandboxAuditACL(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := authorizeSandboxAuditAccess(nil, ctx, "sb", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("nil authorize = %v", err)
	}
	if err := authorizeSandboxAuditAccess(&Service{}, ctx, " ", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("blank authorize = %v", err)
	}
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st}
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-meta", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 128, Runtime: models.RuntimeDocker,
		OwnerRef: "tenant-meta", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.retainSandboxAuditACL(ctx, sb); err == nil {
		t.Fatal("closed store ACL retention must fail")
	}
	if err := authorizeSandboxAuditAccess(svc, ctx, sb.ID, ""); err == nil {
		t.Fatal("closed store authorization must fail")
	}
}

func TestAuthorizeSandboxAuditAccessACLAndIncarnationBranches(t *testing.T) {
	ctx := context.Background()
	operator := controlplane.ContextWithAccess(ctx, controlplane.Access{Operator: true})
	tenant := controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: "tenant-a"}})
	foreign := controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: "tenant-b"}})

	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertSandboxAuditACL(ctx, "sb-retained", "tenant-a", "inc-a"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st}
	if err := authorizeSandboxAuditAccess(svc, operator, "sb-retained", "inc-a"); err != nil {
		t.Fatalf("operator retained ACL: %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, operator, "sb-retained", "inc-b"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("operator wrong incarnation = %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, tenant, "sb-retained", "inc-a"); err != nil {
		t.Fatalf("tenant retained ACL: %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, tenant, "sb-retained", ""); err != nil {
		t.Fatalf("tenant retained ACL with implicit latest incarnation: %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, foreign, "sb-retained", "inc-a"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign retained ACL = %v", err)
	}

	remote := &placementOnlyCluster{
		Noop: cluster.NewNoop("ingress", "http://ingress", ""),
		placement: cluster.Placement{
			SandboxID: "sb-live", OwnerNodeID: "owner", OwnerRef: "tenant-a", IncarnationID: "inc-live",
		},
	}
	svc = &Service{cluster: remote}
	if err := authorizeSandboxAuditAccess(svc, operator, "sb-live", "inc-other"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("operator live wrong incarnation = %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, tenant, "sb-live", "inc-live"); err != nil {
		t.Fatalf("tenant live placement: %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, foreign, "sb-live", "inc-live"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign live placement = %v", err)
	}

	remote.placement = cluster.Placement{}
	remote.auditOwner, remote.auditInc, remote.auditExists = "tenant-a", "inc-raft", true
	if err := authorizeSandboxAuditAccess(svc, operator, "sb-raft", "inc-raft"); err != nil {
		t.Fatalf("operator raft ACL: %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, tenant, "sb-raft", "inc-raft"); err != nil {
		t.Fatalf("tenant raft ACL: %v", err)
	}
	if err := authorizeSandboxAuditAccess(svc, foreign, "sb-raft", "inc-raft"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign raft ACL = %v", err)
	}
	remote.auditOwnerErr = errors.New("raft unavailable")
	if err := authorizeSandboxAuditAccess(svc, operator, "sb-raft", "inc-raft"); !errors.Is(err, remote.auditOwnerErr) {
		t.Fatalf("operator raft error = %v", err)
	}
}
