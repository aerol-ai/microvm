package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ownerBoundDNSResolver returns the owner-bound verification TXT value for the
// given owner (harness prefixes are empty), so only a caller scoped to that
// same owner passes verification for the hostname.
type ownerBoundDNSResolver struct{ owner string }

func (r ownerBoundDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	host := strings.TrimPrefix(name, ".")
	return []string{models.CustomDomainTXTValue("", customDomainOwnerToken(r.owner), host)}, nil
}

// A create with custom_domains must prove DNS control (TXT) for an owner-scoped
// caller (#5), and the proof is bound to the caller's tenant (#10): B cannot
// pass verification using a record published for tenant A.
func TestPersistCustomDomainsOnCreate_OwnerScopedRequiresTXT(t *testing.T) {
	newSvc := func() *Service {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.test"))
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		return svc
	}
	allow := true
	req := models.CreateSandboxRequest{
		Image:              "alpine:3.20",
		CustomDomains:      []string{"login.victim.example"},
		AllowPublicTraffic: &allow,
	}

	// No matching TXT record at all: refused.
	svc := newSvc()
	svc.SetDNSResolver(&mockDNSResolver{})
	if _, err := svc.CreateSandboxWithID(ownerScopedCtx("tenant-b"), req, "sb-squat"); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("owner-scoped create without TXT: err = %v, want ErrCustomDomainVerificationFailed", err)
	}

	// A record bound to tenant-a does NOT let tenant-b verify (owner binding, #10).
	svc = newSvc()
	svc.SetDNSResolver(ownerBoundDNSResolver{owner: "tenant-a"})
	if _, err := svc.CreateSandboxWithID(ownerScopedCtx("tenant-b"), req, "sb-crosstenant"); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("tenant-b verifying with tenant-a's record: err = %v, want ErrCustomDomainVerificationFailed", err)
	}

	// The owning tenant with its own bound record: allowed.
	svc = newSvc()
	svc.SetDNSResolver(ownerBoundDNSResolver{owner: "tenant-b"})
	if _, err := svc.CreateSandboxWithID(ownerScopedCtx("tenant-b"), req, "sb-ok"); err != nil {
		t.Fatalf("owner-scoped create with its own bound TXT rejected: %v", err)
	}

	// Operator (unscoped) is trusted and needs no TXT record.
	svc = newSvc()
	svc.SetDNSResolver(&mockDNSResolver{})
	if _, err := svc.CreateSandboxWithID(operatorCtx(), req, "sb-op"); err != nil {
		t.Fatalf("operator create without TXT rejected: %v", err)
	}
}
