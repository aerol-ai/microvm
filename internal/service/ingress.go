package service

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

// IngressDNSTarget returns the cluster's public ingress address as the SDK
// would render it to a user (CNAME target hostname, raw A/AAAA IP list, or
// both). Delegates to cluster.Client so single-node, cluster, and agent
// deployments all answer through the same aggregator. This call does NOT
// gate on EnableCustomDomains: knowing the target is useful BEFORE attaching
// any domain (e.g. an SDK consumer rendering "point your DNS here first"),
// and the operator information returned (a hostname or IP they already
// chose to advertise on memberlist) is the same data anyone running
// `dig <sandbox-url>` could discover.
func (s *Service) IngressDNSTarget() models.IngressTarget {
	return s.cluster.IngressTargets()
}

// CustomDomainDNS expands a sandbox's attached custom domains into the
// ready-to-paste DNS record set users must create at their provider.
// Returns ErrCustomDomainNotSupported (412) when the deployment can't
// accept custom domains at all — symmetric with ListCustomDomains so
// callers handle both endpoints the same way. Empty Records is returned
// (with the resolved Target attached) when the sandbox exists but has no
// custom domains; that lets the SDK still surface the cluster target
// without separately calling IngressDNSTarget.
func (s *Service) CustomDomainDNS(ctx context.Context, sandboxID string) (models.CustomDomainDNSRecords, error) {
	if !s.cfg.EnableCustomDomains || s.cfg.Domain == "" {
		return models.CustomDomainDNSRecords{}, ErrCustomDomainNotSupported
	}
	if _, err := s.store.Get(ctx, sandboxID); err != nil {
		return models.CustomDomainDNSRecords{}, err
	}
	domains, err := s.store.ListCustomDomains(ctx, sandboxID)
	if err != nil {
		return models.CustomDomainDNSRecords{}, err
	}
	target := s.cluster.IngressTargets()
	hostnames := make([]string, 0, len(domains))
	for _, d := range domains {
		hostnames = append(hostnames, d.Hostname)
	}
	// ComposeDNSRecords returns nil when there are no hostnames or no
	// usable target. Normalise to an empty slice so the JSON shape is a
	// stable `[]` — SDKs that type Records as `DNSRecord[]` would choke
	// on `null` (TypeScript .map, Rust serde Vec, etc.).
	records := models.ComposeDNSRecords(hostnames, target)
	if records == nil {
		records = []models.DNSRecord{}
	}
	return models.CustomDomainDNSRecords{
		Records: records,
		Target:  target,
	}, nil
}
