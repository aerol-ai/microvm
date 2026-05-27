package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVerifyCustomDomainOwnership_Success(t *testing.T) {
	resolver := &mockDNSResolver{
		records: map[string][]string{
			"_aerol-verify.api.acme.com": {"aerol-verify=sb-1"},
		},
	}

	err := verifyCustomDomainOwnership(context.Background(), resolver, "api.acme.com", "sb-1", "_aerol-verify", "aerol-verify=")
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestVerifyCustomDomainOwnership_NotFound(t *testing.T) {
	resolver := &mockDNSResolver{
		records: map[string][]string{},
	}

	err := verifyCustomDomainOwnership(context.Background(), resolver, "api.acme.com", "sb-1", "_aerol-verify", "aerol-verify=")
	if !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("expected ErrCustomDomainVerificationFailed, got %v", err)
	}
}

func TestVerifyCustomDomainOwnership_Mismatch(t *testing.T) {
	resolver := &mockDNSResolver{
		records: map[string][]string{
			"_aerol-verify.api.acme.com": {"aerol-verify=different"},
		},
	}

	err := verifyCustomDomainOwnership(context.Background(), resolver, "api.acme.com", "sb-1", "_aerol-verify", "aerol-verify=")
	if !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("expected ErrCustomDomainVerificationFailed, got %v", err)
	}
}

func TestVerifyCustomDomainOwnership_MultipleRecords(t *testing.T) {
	resolver := &mockDNSResolver{
		records: map[string][]string{
			"_aerol-verify.api.acme.com": {"other=123", "aerol-verify=sb-1", "foo=bar"},
		},
	}

	err := verifyCustomDomainOwnership(context.Background(), resolver, "api.acme.com", "sb-1", "_aerol-verify", "aerol-verify=")
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}
