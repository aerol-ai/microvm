package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// matchingDNSResolver returns a TXT value that always satisfies
// verifyCustomDomainOwnership for the empty verify-value prefix used in the
// test config: the looked-up name is "<prefix>.<hostname>", and with an empty
// prefix the expected value is exactly the hostname, which is the looked-up
// name minus the leading dot.
type matchingDNSResolver struct{}

func (matchingDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return []string{strings.TrimPrefix(name, ".")}, nil
}

func TestCustomDomainLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.example.com"))
	svc.SetDNSResolver(matchingDNSResolver{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.CustomDomainsMaxPerSandbox = 5

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-cd",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerIP:  "10.0.0.50",
		CPU:          1,
		MemoryMB:     512,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	// Add a custom domain.
	if err := svc.AddCustomDomain(ctx, "sb-cd", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	// Idempotent re-add.
	if err := svc.AddCustomDomain(ctx, "sb-cd", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain (re-add): %v", err)
	}

	// List should reflect the attached hostname.
	domains, err := svc.ListCustomDomains(ctx, "sb-cd")
	if err != nil {
		t.Fatalf("ListCustomDomains: %v", err)
	}
	if len(domains) != 1 || domains[0].Hostname != "api.acme.com" {
		t.Fatalf("ListCustomDomains = %+v", domains)
	}

	// Remove it.
	if err := svc.RemoveCustomDomain(ctx, "sb-cd", "API.acme.com"); err != nil {
		t.Fatalf("RemoveCustomDomain: %v", err)
	}
	domains, err = svc.ListCustomDomains(ctx, "sb-cd")
	if err != nil {
		t.Fatalf("ListCustomDomains after remove: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("expected no domains after remove, got %+v", domains)
	}
}

func TestCustomDomainDisabledAndValidation(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", ""))

	// Feature disabled in this config → ErrCustomDomainNotSupported.
	if err := svc.AddCustomDomain(ctx, "sb-x", "api.acme.com", 0); !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("AddCustomDomain(disabled) = %v, want ErrCustomDomainNotSupported", err)
	}
	if _, err := svc.ListCustomDomains(ctx, "sb-x"); !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("ListCustomDomains(disabled) = %v, want ErrCustomDomainNotSupported", err)
	}

	// Enable but feed a bad target port to hit the validation branch.
	svc.SetDNSResolver(matchingDNSResolver{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-y", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.AddCustomDomain(ctx, "sb-y", "api.acme.com", -1); err == nil {
		t.Fatal("expected validation error for negative target port")
	}
}
