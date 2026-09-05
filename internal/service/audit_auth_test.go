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
	auditInc      string
	auditExists   bool
	auditOwnerErr error
}

func (c *placementOnlyCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.placement.SandboxID != ""
}

func (c *placementOnlyCluster) AuditOwnerRef(context.Context, string) (string, bool, error) {
	return c.auditOwner, c.auditExists, c.auditOwnerErr
}

func (c *placementOnlyCluster) AuditACLForSandbox(context.Context, string) (cluster.AuditACL, bool, error) {
	return cluster.AuditACL{OwnerRef: c.auditOwner, IncarnationID: c.auditInc}, c.auditExists, c.auditOwnerErr
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
	if err := svc.AuthorizeSandboxAuditAccess(ctx, "sb-remote", ""); err != nil {
		t.Fatalf("owner tenant: %v", err)
	}
	evil := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "evil"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(evil, "sb-remote", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("evil tenant = %v, want ErrNotFound", err)
	}
	op := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	if err := svc.AuthorizeSandboxAuditAccess(op, "sb-remote", ""); err != nil {
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
	if err := svc.AuthorizeSandboxAuditAccess(ctx, "sb-local", ""); err != nil {
		t.Fatalf("local owner: %v", err)
	}
}

func TestRetainSandboxAuditACLUsesCurrentIncarnationForOwnerlessSandbox(t *testing.T) {
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
	sb := &models.Sandbox{ID: "sb-ownerless-finalizer"}
	if err := svc.retainSandboxAuditACL(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	exists, err := st.HasSandboxAuditACL(context.Background(), sb.ID, "inc-current")
	if err != nil || !exists {
		t.Fatalf("incarnation ACL exists=%v err=%v", exists, err)
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
	if err := svc.AuthorizeSandboxAuditAccess(owner, "sb-deleted", ""); err != nil {
		t.Fatalf("retained owner ACL: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(owner, "sb-deleted", "inc-other"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("wrong retained incarnation = %v, want ErrNotFound", err)
	}
	operator := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	if err := svc.AuthorizeSandboxAuditAccess(operator, "sb-deleted", "inc-other"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("operator wrong retained incarnation = %v, want ErrNotFound", err)
	}
	other := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "other"},
	})
	if err := svc.AuthorizeSandboxAuditAccess(other, "sb-deleted", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign tenant = %v, want ErrNotFound", err)
	}

	svc.cluster.(*placementOnlyCluster).auditOwnerErr = errors.New("raft unavailable")
	if err := svc.AuthorizeSandboxAuditAccess(owner, "sb-deleted", ""); err == nil || err.Error() != "raft unavailable" {
		t.Fatalf("raft failure = %v, want fail-closed error", err)
	}
}

func TestAuditAuthorizationNilAndLocalMetadataPaths(t *testing.T) {
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
	if err := (*Service)(nil).AuthorizeSandboxAuditAccess(ctx, "sb", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("nil authorize = %v", err)
	}
	if err := (&Service{}).AuthorizeSandboxAuditAccess(ctx, " ", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("blank authorize = %v", err)
	}
	if owner, ok, err := (*Service)(nil).SandboxOwnerRefLocal(ctx, "sb"); owner != "" || ok || err != nil {
		t.Fatalf("nil local metadata = %q %v %v", owner, ok, err)
	}
	if owner, ok, err := (&Service{}).SandboxOwnerRefLocal(ctx, "sb"); owner != "" || ok || err != nil {
		t.Fatalf("storeless local metadata = %q %v %v", owner, ok, err)
	}
	if got := (*Service)(nil).sandboxMetaFetcher(); got != nil {
		t.Fatalf("nil meta fetcher = %#v", got)
	}

	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st}
	if owner, ok, err := svc.SandboxOwnerRefLocal(ctx, "missing"); owner != "" || ok || err != nil {
		t.Fatalf("missing local metadata = %q %v %v", owner, ok, err)
	}
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-meta", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 128, Runtime: models.RuntimeDocker,
		OwnerRef: "tenant-meta", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if owner, ok, err := svc.SandboxOwnerRefLocal(ctx, sb.ID); owner != "tenant-meta" || !ok || err != nil {
		t.Fatalf("local metadata = %q %v %v", owner, ok, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.SandboxOwnerRefLocal(ctx, sb.ID); err == nil {
		t.Fatal("closed store metadata read must fail")
	}
	if err := svc.retainSandboxAuditACL(ctx, sb); err == nil {
		t.Fatal("closed store ACL retention must fail")
	}
	if err := svc.AuthorizeSandboxAuditAccess(ctx, sb.ID, ""); err == nil {
		t.Fatal("closed store authorization must fail")
	}
}

func TestSandboxOwnerRefFetchFailsClosed(t *testing.T) {
	ctx := context.Background()
	p := cluster.Placement{SandboxID: "sb", OwnerNodeID: "node-a"}
	svc := &Service{}
	if _, err := svc.fetchSandboxOwnerRef(ctx, p); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("missing fetcher = %v", err)
	}

	fetcher := &fakeSandboxMetaFetcher{}
	svc.testSandboxMetaFetcher = fetcher
	if got := svc.sandboxMetaFetcher(); got != fetcher {
		t.Fatalf("test fetcher = %#v", got)
	}
	if _, err := svc.fetchSandboxOwnerRef(ctx, cluster.Placement{SandboxID: "sb"}); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("missing owner node = %v", err)
	}
	if _, err := svc.fetchSandboxOwnerRef(ctx, p); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("absent peer sandbox = %v", err)
	}
	fetcher.err = errors.New("peer unavailable")
	if _, err := svc.fetchSandboxOwnerRef(ctx, p); !errors.Is(err, fetcher.err) {
		t.Fatalf("peer error = %v", err)
	}
	fetcher.err = nil
	fetcher.ok = true
	fetcher.ownerRef = " tenant-a "
	if owner, err := svc.fetchSandboxOwnerRef(ctx, p); err != nil || owner != "tenant-a" {
		t.Fatalf("peer owner = %q err=%v", owner, err)
	}

	svc.testSandboxMetaFetcher = nil
	svc.cluster = cluster.NewNoop("node-a", "http://node-a", "")
	if svc.sandboxMetaFetcher() == nil {
		t.Fatal("cluster sandbox metadata capability was not discovered")
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
	if err := svc.AuthorizeSandboxAuditAccess(operator, "sb-retained", "inc-a"); err != nil {
		t.Fatalf("operator retained ACL: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(operator, "sb-retained", "inc-b"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("operator wrong incarnation = %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(tenant, "sb-retained", "inc-a"); err != nil {
		t.Fatalf("tenant retained ACL: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(tenant, "sb-retained", ""); err != nil {
		t.Fatalf("tenant retained ACL with implicit latest incarnation: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(foreign, "sb-retained", "inc-a"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign retained ACL = %v", err)
	}

	remote := &placementOnlyCluster{
		Noop: cluster.NewNoop("ingress", "http://ingress", ""),
		placement: cluster.Placement{
			SandboxID: "sb-live", OwnerNodeID: "owner", OwnerRef: "tenant-a", IncarnationID: "inc-live",
		},
	}
	svc = &Service{cluster: remote}
	if err := svc.AuthorizeSandboxAuditAccess(operator, "sb-live", "inc-other"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("operator live wrong incarnation = %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(tenant, "sb-live", "inc-live"); err != nil {
		t.Fatalf("tenant live placement: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(foreign, "sb-live", "inc-live"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign live placement = %v", err)
	}

	remote.placement = cluster.Placement{}
	remote.auditOwner, remote.auditInc, remote.auditExists = "tenant-a", "inc-raft", true
	if err := svc.AuthorizeSandboxAuditAccess(operator, "sb-raft", "inc-raft"); err != nil {
		t.Fatalf("operator raft ACL: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(tenant, "sb-raft", "inc-raft"); err != nil {
		t.Fatalf("tenant raft ACL: %v", err)
	}
	if err := svc.AuthorizeSandboxAuditAccess(foreign, "sb-raft", "inc-raft"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("foreign raft ACL = %v", err)
	}
	remote.auditOwnerErr = errors.New("raft unavailable")
	if err := svc.AuthorizeSandboxAuditAccess(operator, "sb-raft", "inc-raft"); !errors.Is(err, remote.auditOwnerErr) {
		t.Fatalf("operator raft error = %v", err)
	}
}
