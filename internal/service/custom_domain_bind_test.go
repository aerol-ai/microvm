package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// bindCluster is a server's cluster client for the custom-domain binds: it
// knows some placements, which names are the cluster's own, and records
// each bind and release.
type bindCluster struct {
	*cluster.Noop
	placements map[string]cluster.Placement
	ours       map[string]bool
	bound      []string
	removed    []string
	bindErr    error
	addErr     error
}

func (c *bindCluster) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.placements[id]
	return p, ok
}

func (c *bindCluster) IsClusterHostname(host string) bool { return c.ours[host] }

func (c *bindCluster) AddCustomDomainForIncarnation(_ context.Context, sandboxID, incarnationID, hostname string) error {
	if c.bindErr != nil {
		return c.bindErr
	}
	c.bound = append(c.bound, sandboxID+"/"+incarnationID+"/"+hostname)
	if p, ok := c.placements[sandboxID]; ok {
		p.CustomHostnames = append(p.CustomHostnames, hostname)
		c.placements[sandboxID] = p
	}
	return nil
}

// AddCustomDomain is the owner's re-add (recordClusterCustomDomain).
func (c *bindCluster) AddCustomDomain(context.Context, string, string) error { return c.addErr }

func (c *bindCluster) RemoveCustomDomain(_ context.Context, sandboxID, hostname string) error {
	c.removed = append(c.removed, sandboxID+"/"+hostname)
	return nil
}

const bindOwner = "team:payments"

// bindServer is a cluster server that knows sb-pay (team payments, holding
// held.customer.com) and sb-ops (the operator's), with DNS records for
// payments' and the operator's names.
func bindServer(t *testing.T) (*Service, *bindCluster) {
	t.Helper()
	svc := &Service{cfg: config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer,
		CustomDomainVerifyPrefix: "_aerolvm", CustomDomainVerifyValuePrefix: "aerolvm="}}
	c := &bindCluster{
		Noop: cluster.NewNoop("srv-1", "http://srv-1", ""),
		placements: map[string]cluster.Placement{
			"sb-pay": {SandboxID: "sb-pay", IncarnationID: "inc-pay", OwnerRef: bindOwner, CustomHostnames: []string{"held.customer.com"}},
			"sb-ops": {SandboxID: "sb-ops", IncarnationID: "inc-ops"},
		},
		ours: map[string]bool{"edge.example.net": true},
	}
	svc.AttachCluster(c)
	svc.SetDNSResolver(txtRecords{
		"_aerolvm.app.customer.com":  {models.CustomDomainTXTValue("aerolvm=", customDomainOwnerToken(bindOwner), "app.customer.com")},
		"_aerolvm.ops.customer.com":  {models.CustomDomainTXTValue("aerolvm=", "", "ops.customer.com")},
		"_aerolvm.shop.customer.com": {models.CustomDomainTXTValue("aerolvm=", customDomainOwnerToken(bindOwner), "shop.customer.com")},
	})
	return svc, c
}

// The server checks the caller's DNS proof and binds the name itself; the
// owner's word on whose sandbox it is plays no part.
func TestBindCustomDomain(t *testing.T) {
	payments := teamCtx("payments")
	other := teamCtx("other")
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		sandbox   string
		host      string
		wantErr   error
		wantBound string
		wantMark  bool
	}{
		{name: "payments' proof, payments' sandbox", ctx: payments, sandbox: "sb-pay", host: "App.Customer.com.", wantBound: "sb-pay/inc-pay/app.customer.com", wantMark: true},
		{name: "a name the sandbox holds: no lookup, no bind", ctx: payments, sandbox: "sb-pay", host: "held.customer.com", wantMark: true},
		{name: "no TXT record for the caller", ctx: payments, sandbox: "sb-pay", host: "none.customer.com", wantErr: models.ErrCustomDomainVerificationFailed},
		{name: "the operator's record does not prove a team's name", ctx: payments, sandbox: "sb-pay", host: "ops.customer.com", wantErr: models.ErrCustomDomainVerificationFailed},
		{name: "a cluster name", ctx: payments, sandbox: "sb-pay", host: "edge.example.net", wantErr: models.ErrCustomDomainInvalid},
		{name: "another team's sandbox goes on unbound", ctx: other, sandbox: "sb-pay", host: "app.customer.com"},
		{name: "an unknown sandbox goes on unbound", ctx: payments, sandbox: "sb-gone", host: "app.customer.com"},
		{name: "a malformed name goes on unbound", ctx: payments, sandbox: "sb-pay", host: "bad host"},
		{name: "the operator proves with its own record", ctx: adminCtx(), sandbox: "sb-ops", host: "ops.customer.com", wantBound: "sb-ops/inc-ops/ops.customer.com", wantMark: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, c := bindServer(t)
			ctx, release, err := svc.BindCustomDomain(tc.ctx, tc.sandbox, tc.host)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantBound == "" && len(c.bound) != 0 || tc.wantBound != "" && (len(c.bound) != 1 || c.bound[0] != tc.wantBound) {
				t.Fatalf("bound %v, want %q", c.bound, tc.wantBound)
			}
			if (release != nil) != (tc.wantBound != "") {
				t.Fatalf("release = %v for bound %v", release != nil, c.bound)
			}
			_, marked := cluster.CustomDomainsBoundFromContext(ctx)
			if marked != tc.wantMark {
				t.Fatalf("marked = %v", marked)
			}
			if release != nil {
				release()
				if len(c.removed) != 1 {
					t.Fatalf("release removed %v", c.removed)
				}
			}
		})
	}
}

// A worker or gateway, or a single node, binds nothing for a caller.
func TestBindCustomDomainOnlyOnAServer(t *testing.T) {
	for name, mutate := range map[string]func(*Service){
		"a worker":      func(s *Service) { s.cfg.NodeRole = config.NodeRoleWorker },
		"a single node": func(s *Service) { s.cfg.EnableCluster = false },
		"no binder":     func(s *Service) { s.AttachCluster(cluster.NewNoop("srv-1", "http://srv-1", "")) },
	} {
		t.Run(name, func(t *testing.T) {
			svc, c := bindServer(t)
			mutate(svc)
			ctx, release, err := svc.BindCustomDomain(teamCtx("payments"), "sb-pay", "app.customer.com")
			if err != nil || release != nil || len(c.bound) != 0 {
				t.Fatalf("err %v, release %v, bound %v", err, release != nil, c.bound)
			}
			if _, marked := cluster.CustomDomainsBoundFromContext(ctx); marked {
				t.Fatal("marked")
			}
			ctx, err = svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", []string{"app.customer.com"})
			if err != nil || len(c.bound) != 0 {
				t.Fatalf("create: err %v, bound %v", err, c.bound)
			}
			if _, marked := cluster.CustomDomainsBoundFromContext(ctx); marked {
				t.Fatal("create marked")
			}
		})
	}
}

// A create's names: the caller's own team's proof, none for an operator or
// admin, and every name or none.
func TestBindCreateCustomDomains(t *testing.T) {
	svc, c := bindServer(t)
	ctx, err := svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", []string{"app.customer.com", "SHOP.customer.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.bound) != 2 || c.bound[1] != "sb-new/inc-new/shop.customer.com" {
		t.Fatalf("bound %v", c.bound)
	}
	if b, ok := cluster.CustomDomainsBoundFromContext(ctx); !ok || !b.Covers("sb-new", "shop.customer.com") {
		t.Fatalf("marker %+v %v", b, ok)
	}

	svc, c = bindServer(t)
	if _, err := svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", []string{"app.customer.com", "none.customer.com"}); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("one name without a proof = %v", err)
	}
	if len(c.bound) != 0 {
		t.Fatalf("bound before every proof passed: %v", c.bound)
	}
	if _, err := svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", []string{"edge.example.net"}); !errors.Is(err, models.ErrCustomDomainInvalid) {
		t.Fatalf("a cluster name = %v", err)
	}
	if _, err := svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", []string{"localhost"}); !errors.Is(err, models.ErrCustomDomainInvalid) {
		t.Fatalf("an invalid name = %v", err)
	}
	// An operator or admin create takes no proof, as on the owner.
	if _, err := svc.BindCreateCustomDomains(adminCtx(), "sb-new", "inc-new", []string{"none.customer.com"}); err != nil {
		t.Fatalf("admin: %v", err)
	}
	// A conflict is the store's 409.
	svc, c = bindServer(t)
	c.bindErr = cluster.ErrCustomHostnameConflict
	if _, err := svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", []string{"app.customer.com"}); !errors.Is(err, storepkg.ErrCustomDomainConflict) {
		t.Fatalf("conflict = %v", err)
	}
	c.bindErr = errors.New("leader gone")
	if _, _, err := svc.BindCustomDomain(teamCtx("payments"), "sb-pay", "app.customer.com"); err == nil || errors.Is(err, storepkg.ErrCustomDomainConflict) {
		t.Fatalf("bind failure = %v", err)
	}
	if ctx, err := svc.BindCreateCustomDomains(teamCtx("payments"), "sb-new", "inc-new", nil); err != nil || ctx == nil {
		t.Fatalf("no names: %v", err)
	}
}

// slowDNS never answers before the lookup's deadline.
type slowDNS struct{}

func (slowDNS) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A lookup that gets no answer is "try again" (503), never a refusal.
func TestCustomDomainProofUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := verifyCustomDomainOwnership(ctx, slowDNS{}, "app.customer.com", "_aerolvm", "aerolvm=", "")
	if !errors.Is(err, models.ErrCustomDomainProofUnavailable) || errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("timeout = %v", err)
	}
	for _, dnsErr := range []*net.DNSError{{Err: "i/o timeout", IsTimeout: true}, {Err: "server misbehaving", IsTemporary: true}} {
		err := verifyCustomDomainOwnership(context.Background(), &mockDNSResolver{err: dnsErr}, "app.customer.com", "_aerolvm", "aerolvm=", "")
		if !errors.Is(err, models.ErrCustomDomainProofUnavailable) {
			t.Errorf("%v = %v", dnsErr, err)
		}
	}
	err = verifyCustomDomainOwnership(context.Background(), &mockDNSResolver{err: errors.New("refused")}, "app.customer.com", "_aerolvm", "aerolvm=", "")
	if !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("a final failure = %v", err)
	}
	// The server's own lookup is bounded.
	prev := customDomainProofTimeout
	customDomainProofTimeout = 50 * time.Millisecond
	t.Cleanup(func() { customDomainProofTimeout = prev })
	svc, _ := bindServer(t)
	svc.SetDNSResolver(slowDNS{})
	if _, _, err := svc.BindCustomDomain(teamCtx("payments"), "sb-pay", "app.customer.com"); !errors.Is(err, models.ErrCustomDomainProofUnavailable) {
		t.Fatalf("server lookup = %v", err)
	}
}

// The owner takes a server's binding for the call: no second lookup for
// the names the server bound to this sandbox, and only those.
func TestOwnerTakesTheServersBinding(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	bound := func(id string, hosts ...string) context.Context {
		return cluster.ContextWithCustomDomainsBound(context.Background(), cluster.CustomDomainsBound{SandboxID: id, Hostnames: hosts})
	}
	if err := svc.AddCustomDomain(context.Background(), "sb-1", "fresh.acme.com", 0); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("no record, no binding = %v", err)
	}
	if err := svc.AddCustomDomain(bound("sb-2", "fresh.acme.com"), "sb-1", "fresh.acme.com", 0); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("a binding for another sandbox = %v", err)
	}
	if err := svc.AddCustomDomain(bound("sb-1", "fresh.acme.com"), "sb-1", "fresh.acme.com", 0); err != nil {
		t.Fatalf("a server's binding: %v", err)
	}

	tenant := controlplane.ContextWithAccess(context.Background(),
		controlplane.TokenAccess("tok_x", "x", controlplane.RoleRunner, "payments", time.Time{}))
	if err := svc.persistCustomDomainsOnCreate(tenant, "sb-1", []string{"other.acme.com"}); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("create, no binding = %v", err)
	}
	both := cluster.ContextWithCustomDomainsBound(tenant, cluster.CustomDomainsBound{SandboxID: "sb-1", Hostnames: []string{"other.acme.com"}})
	if err := svc.persistCustomDomainsOnCreate(both, "sb-1", []string{"other.acme.com"}); err != nil {
		t.Fatalf("create, a server's binding: %v", err)
	}
}

// A name the cluster binds to a sandbox with no row on its owner (a server
// bound it and never learned the attach's outcome) is released by a
// detach; a name bound to nothing stays a 404.
func TestRemoveReleasesAClusterOnlyBinding(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	c := &bindCluster{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""),
		placements: map[string]cluster.Placement{"sb-1": {SandboxID: "sb-1", CustomHostnames: []string{"stale.acme.com"}}}}
	svc.AttachCluster(c)
	if err := svc.RemoveCustomDomain(context.Background(), "sb-1", "Stale.Acme.com"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(c.removed) != 1 || c.removed[0] != "sb-1/stale.acme.com" {
		t.Fatalf("removed %v", c.removed)
	}
	if err := svc.RemoveCustomDomain(context.Background(), "sb-1", "never.acme.com"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("a name bound to nothing = %v", err)
	}
}

// The leader's refusal of a worker's new name reaches the caller as a
// failed proof that says where to send the call, not as an internal error.
func TestRecordRefusalSaysWhereToSendTheCall(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	c := &bindCluster{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""), addErr: fmt.Errorf("relay: %w", cluster.ErrPeerProposalRefused)}
	svc.AttachCluster(c)
	err := svc.recordClusterCustomDomain(context.Background(), "sb-1", "api.acme.com")
	if !errors.Is(err, models.ErrCustomDomainVerificationFailed) || !strings.Contains(err.Error(), "through a server") {
		t.Fatalf("refusal = %v", err)
	}
	c.addErr = errors.New("leader gone")
	if err := svc.recordClusterCustomDomain(context.Background(), "sb-1", "api.acme.com"); errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("another failure read as a refusal: %v", err)
	}
}
