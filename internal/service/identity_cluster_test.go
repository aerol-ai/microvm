package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeIdentityCluster is the replicated identity store several nodes share:
// the FSM's rules (generation CAS on the key set, idempotent role puts) in
// memory, so two Services can act as two nodes of one cluster.
type fakeIdentityCluster struct {
	*cluster.Noop
	mu      sync.Mutex
	keys    cloudidentity.KeySet
	roles   map[cluster.IdentityRoleKey]cluster.IdentityRoleRecord
	allowed bool
	readErr error
}

func newFakeIdentityCluster() *fakeIdentityCluster {
	return &fakeIdentityCluster{Noop: cluster.NewNoop("node-a", "", ""), roles: map[cluster.IdentityRoleKey]cluster.IdentityRoleRecord{}, allowed: true}
}

func (f *fakeIdentityCluster) IdentityAllowed() bool { return f.allowed }

func (f *fakeIdentityCluster) WriteIdentity(_ context.Context, req cluster.IdentityWriteRequest) (cluster.IdentityWriteResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case req.Keys != nil:
		if req.Keys.ExpectedGeneration != f.keys.Generation {
			return cluster.IdentityWriteResponse{}, cluster.ErrIdentityKeysConflict
		}
		next := cloudidentity.KeySet{Generation: f.keys.Generation + 1, Keys: req.Keys.Keys}.Clone()
		if err := next.Validate(); err != nil {
			return cluster.IdentityWriteResponse{}, cluster.ErrIdentityInvalid
		}
		f.keys = next
		out := next.Clone()
		return cluster.IdentityWriteResponse{Keys: &out, Changed: true}, nil
	case req.Role != nil && req.DeleteRole:
		delete(f.roles, cluster.IdentityRoleKey{Owner: req.Role.Owner, Tag: req.Role.Tag})
		return cluster.IdentityWriteResponse{Changed: true}, nil
	case req.Role != nil:
		if !cloudidentity.ValidMinRole(req.Role.MinRole) {
			return cluster.IdentityWriteResponse{}, cluster.ErrIdentityInvalid
		}
		rec := *req.Role
		rec.CreatedUnixNano, rec.UpdatedUnixNano = 1, 2
		f.roles[cluster.IdentityRoleKey{Owner: rec.Owner, Tag: rec.Tag}] = rec
		return cluster.IdentityWriteResponse{Role: &rec, Changed: true}, nil
	}
	return cluster.IdentityWriteResponse{}, cluster.ErrClusterVersion
}

func (f *fakeIdentityCluster) ReadIdentity(_ context.Context, req cluster.IdentityReadRequest) (cluster.IdentityReadResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return cluster.IdentityReadResponse{}, f.readErr
	}
	out := cluster.IdentityReadResponse{Authoritative: true}
	if req.Keys {
		keys := f.keys.Clone()
		out.Keys = &keys
	}
	for _, tag := range req.Tags {
		if rec, ok := f.roles[cluster.IdentityRoleKey{Owner: req.Owner, Tag: tag}]; ok {
			out.Roles = append(out.Roles, rec)
		}
	}
	if req.RolePage {
		for k, rec := range f.roles {
			if k.Owner == req.Owner && k.Tag > req.After {
				out.Roles = append(out.Roles, rec)
			}
		}
	}
	return out, nil
}

func clusterIdentityNode(t *testing.T, shared *fakeIdentityCluster, cipherFrom *identityHarness) *identityHarness {
	t.Helper()
	h := newIdentityHarness(t)
	h.svc.cfg.EnableCluster = true
	h.svc.AttachCluster(shared)
	if cipherFrom != nil {
		// Every node of a cluster shares one server key.
		h.svc.cipher = cipherFrom.svc.cipher
	}
	return h
}

// The cluster check of section 5: a token signed on one node verifies with
// the JWKS another node serves, before and after a rotation made on the
// second node.
func TestIdentityTokenSignedOnOneNodeVerifiesOnAnother(t *testing.T) {
	shared := newFakeIdentityCluster()
	a := clusterIdentityNode(t, shared, nil)
	b := clusterIdentityNode(t, shared, a)
	ctx := context.Background()
	now := time.Now()
	signer, err := a.svc.currentIdentitySigner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.signer.Issue(cloudidentity.IssueRequest{Issuer: testIssuer, OwnerRef: "team:p", SandboxID: "sb-a", RoleTag: "deploy", Audience: "a", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := cloudidentity.Verify(tok.Raw, b.jwks(t), now); err != nil || claims.Sandbox != "sb-a" {
		t.Fatalf("node B verifying node A's token = %+v %v", claims, err)
	}
	// Node B rotates; node A's old token still verifies with B's JWKS, and
	// A signs with the new key once it re-reads the set.
	out, err := b.svc.RotateIdentityKey(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cloudidentity.Verify(tok.Raw, b.jwks(t), now.Add(time.Minute)); err != nil {
		t.Fatalf("pre-rotation token on node B: %v", err)
	}
	a.svc.identity.now = func() time.Time { return time.Now().Add(identitySignerTTL + time.Second) }
	s, err := a.svc.currentIdentitySigner(ctx)
	if err != nil || s.signer.KeyID != out.ActiveKeyID {
		t.Fatalf("node A after the TTL: %v; want key %s", err, out.ActiveKeyID)
	}
	// Roles written on one node gate creates on the other.
	if _, err := a.svc.PutIdentityRole(adminCtx(), "p", "deploy", models.IdentityRoleRequest{MinRole: "runner"}); err != nil {
		t.Fatal(err)
	}
	runner := controlplane.ContextWithAccess(context.Background(), controlplane.TokenAccess("tok", "t", controlplane.RoleRunner, "p", time.Now().Add(time.Hour)))
	req := models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}
	if err := b.svc.prepareCreateIdentity(runner, &req, "team:p", models.RuntimeDocker); err != nil {
		t.Fatalf("node B create check: %v", err)
	}
	if list, err := b.svc.ListIdentityRoles(adminCtx(), "p", "", 0); err != nil || len(list.Roles) != 1 || list.Roles[0].CreatedAt.IsZero() {
		t.Fatalf("node B list = %+v %v", list, err)
	}
	if err := b.svc.DeleteIdentityRole(adminCtx(), "p", "deploy"); err != nil {
		t.Fatal(err)
	}
	req = models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}
	if err := a.svc.prepareCreateIdentity(runner, &req, "team:p", models.RuntimeDocker); !errors.Is(err, ErrIdentityRoleDenied) {
		t.Fatalf("node A after node B deleted the tag = %v", err)
	}
	// Two nodes making the first key at once: one wins, both use it.
	fresh := newFakeIdentityCluster()
	c := clusterIdentityNode(t, fresh, a)
	d := clusterIdentityNode(t, fresh, a)
	var wg sync.WaitGroup
	for _, n := range []*identityHarness{c, d} {
		wg.Add(1)
		go func(n *identityHarness) {
			defer wg.Done()
			if err := n.svc.EnsureIdentityKeysReady(ctx); err != nil {
				t.Error(err)
			}
		}(n)
	}
	wg.Wait()
	if fresh.keys.Generation != 1 || c.svc.identity.signer.Load().signer.KeyID != d.svc.identity.signer.Load().signer.KeyID {
		t.Fatalf("racing first keys: generation %d", fresh.keys.Generation)
	}
}

func TestClusterIdentityFailures(t *testing.T) {
	shared := newFakeIdentityCluster()
	h := clusterIdentityNode(t, shared, nil)
	ctx := adminCtx()
	// The rolling-upgrade gate closes identity creates.
	shared.allowed = false
	req := models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}
	if err := h.svc.prepareCreateIdentity(ctx, &req, "", models.RuntimeDocker); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("gate closed = %v", err)
	}
	shared.allowed = true
	// FSM refusals map to the service's errors.
	if _, _, err := h.svc.identityBackend().PutIdentityRole(ctx, "", "x", "viewer", time.Now()); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("FSM refusal = %v", err)
	}
	if _, err := h.svc.identityBackend().WriteIdentityKeys(ctx, 9, nil); !errors.Is(err, ErrIdentityKeysConflict) {
		t.Fatalf("stale CAS = %v", err)
	}
	if err := clusterIdentityError(cluster.ErrClusterVersion); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("cluster version = %v", err)
	}
	if _, err := (clusterIdentity{&emptyReplyCluster{}}).WriteIdentityKeys(ctx, 0, nil); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("no key set in the reply = %v", err)
	}
	if _, _, err := (clusterIdentity{&emptyReplyCluster{}}).PutIdentityRole(ctx, "", "x", "runner", time.Now()); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("no role in the reply = %v", err)
	}
	if set, err := (clusterIdentity{&emptyReplyCluster{}}).ReadIdentityKeys(ctx); err != nil || set.Generation != 0 {
		t.Fatalf("no key set yet = %+v %v", set, err)
	}
	// The server tier unreachable: every read is a 503.
	shared.readErr = errors.New("server tier unreachable")
	b := h.svc.identityBackend()
	if _, err := b.ReadIdentityKeys(ctx); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("read keys = %v", err)
	}
	if _, err := b.GetIdentityRole(ctx, "", "x"); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("get role = %v", err)
	}
	if _, err := b.ListIdentityRoles(ctx, "", "", 1); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("list roles = %v", err)
	}
	// A cluster whose client has no replicated store refuses every call.
	h.svc.AttachCluster(cluster.NewNoop("node-a", "", ""))
	if _, err := h.svc.identityBackend().WriteIdentityKeys(ctx, 0, nil); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("no replicated store = %v", err)
	}
	if err := h.svc.EnsureIdentityKeysReady(ctx); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("bootstrap with no replicated store = %v", err)
	}
}

// emptyReplyCluster answers every write with an empty body: a leader on a
// build that ignored the request's fields.
type emptyReplyCluster struct{}

func (emptyReplyCluster) WriteIdentity(context.Context, cluster.IdentityWriteRequest) (cluster.IdentityWriteResponse, error) {
	return cluster.IdentityWriteResponse{}, nil
}

func (emptyReplyCluster) ReadIdentity(context.Context, cluster.IdentityReadRequest) (cluster.IdentityReadResponse, error) {
	return cluster.IdentityReadResponse{Authoritative: true}, nil
}
