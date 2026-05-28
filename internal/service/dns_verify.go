package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// DNSResolver is an interface to allow mocking of net.Resolver in tests.
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DefaultDNSResolver is the default implementation using net.DefaultResolver.
type DefaultDNSResolver struct{}

// LookupTXT implements DNSResolver using the system's default resolver.
func (d *DefaultDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// SetDNSResolver sets the DNS resolver for the service (used for testing from other packages).
func (s *Service) SetDNSResolver(resolver DNSResolver) {
	s.dnsResolver = resolver
}

// verifyCustomDomainOwnership checks if the operator has proven ownership of
// the custom domain by placing a specific TXT record. The expected value is
// derived from the hostname itself (not a sandbox ID), so the TXT can be
// provisioned once per zone and reused across sandbox recreates. Cross-
// sandbox hijack of an already-attached hostname is prevented by the
// cluster-wide uniqueness gate on insert, not by this check.
func verifyCustomDomainOwnership(ctx context.Context, resolver DNSResolver, hostname, txtNamePrefix, txtValuePrefix string) error {
	verifyDomain := fmt.Sprintf("%s.%s", txtNamePrefix, hostname)
	expectedValue := fmt.Sprintf("%s%s", txtValuePrefix, hostname)

	txts, err := resolver.LookupTXT(ctx, verifyDomain)
	if err != nil {
		if isDNSNotFound(err) {
			return fmt.Errorf("%w: TXT record not found at %s", models.ErrCustomDomainVerificationFailed, verifyDomain)
		}
		return fmt.Errorf("%w: failed to lookup TXT record at %s: %v", models.ErrCustomDomainVerificationFailed, verifyDomain, err)
	}

	for _, txt := range txts {
		if strings.TrimSpace(txt) == expectedValue {
			return nil
		}
	}

	return fmt.Errorf("%w: found TXT records but none matched %q at %s", models.ErrCustomDomainVerificationFailed, expectedValue, verifyDomain)
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	// Check string since IsNotFound might not be perfectly reliable across platforms in old Go, though usually it is.
	return strings.Contains(err.Error(), "no such host")
}
