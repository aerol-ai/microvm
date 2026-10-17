package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// customDomainOwnerTokenLen is the hex length of the owner token embedded in
// the verification TXT value — long enough that it cannot be guessed, short
// enough for a readable DNS record.
const customDomainOwnerTokenLen = 16

// customDomainOwnerToken is the opaque, stable token for an owner used in the
// verification TXT value. "" (operator/no owner) yields "", keeping the legacy
// hostname-only record. A tenant gets a hash of its owner_ref, so its required
// TXT value differs from every other tenant's for the same hostname.
func customDomainOwnerToken(owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("custom-domain-owner\x00" + owner))
	return hex.EncodeToString(sum[:])[:customDomainOwnerTokenLen]
}

// customDomainOwnerTokenFromContext derives the verification token for the
// current caller: "" for operator/internal (unscoped) callers, a per-tenant
// token for a validated user token.
func customDomainOwnerTokenFromContext(ctx context.Context) string {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return ""
	}
	return customDomainOwnerToken(owner)
}

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
func verifyCustomDomainOwnership(ctx context.Context, resolver DNSResolver, hostname, txtNamePrefix, txtValuePrefix, ownerToken string) error {
	verifyDomain := fmt.Sprintf("%s.%s", txtNamePrefix, hostname)
	expectedValue := models.CustomDomainTXTValue(txtValuePrefix, ownerToken, hostname)

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
