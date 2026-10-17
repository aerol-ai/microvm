package service

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A create with custom_domains must prove DNS control (TXT) for an owner-scoped
// caller, exactly as AddCustomDomain does. Without this an untrusted tenant
// could claim another tenant's hostname at create time (no TXT), and once the
// real owner pointed DNS at the ingress the squatter served their domain.
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

	// Owner-scoped caller with NO matching TXT record: refused.
	svc := newSvc()
	svc.SetDNSResolver(&mockDNSResolver{}) // every lookup returns not-found
	_, err := svc.CreateSandboxWithID(ownerScopedCtx("tenant-b"), req, "sb-squat")
	if !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("owner-scoped create without TXT: err = %v, want ErrCustomDomainVerificationFailed", err)
	}

	// Owner-scoped caller WITH a matching TXT record: allowed.
	svc = newSvc()
	svc.SetDNSResolver(matchingDNSResolver{})
	if _, err := svc.CreateSandboxWithID(ownerScopedCtx("tenant-b"), req, "sb-ok"); err != nil {
		t.Fatalf("owner-scoped create with valid TXT rejected: %v", err)
	}

	// Operator (unscoped) is trusted and does not need a TXT record.
	svc = newSvc()
	svc.SetDNSResolver(&mockDNSResolver{})
	if _, err := svc.CreateSandboxWithID(operatorCtx(), req, "sb-op"); err != nil {
		t.Fatalf("operator create without TXT rejected: %v", err)
	}
}
