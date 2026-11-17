package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Custom hostnames in a cluster are bound by a server. The leader takes a
// custom hostname from a worker or gateway only when the sandbox already
// holds it (internal/cluster peerMayPropose): the owner writes the
// sandbox, so its word on whose name a hostname is proves nothing. A
// worker or gateway sends a domain attach, and a create with
// custom_domains, to a server with the caller's own credential (pkg/api/v1
// server_tier.go). The server checks the caller's DNS proof, binds the
// name itself, and sends the call on to the owner, which then does its own
// checks and writes its row without looking the proof up again
// (cluster.CustomDomainsBound).
//
// The proof is the one the owner checked before: on an attach, the record
// bound to the sandbox's owner, or the operator's owner-less record for a
// host-capable caller (customDomainProofToken); on a create, none for a
// host-capable caller and otherwise the record bound to the caller's own
// team (persistCustomDomainsOnCreate).
//
// Rollback: the server binds before the owner runs. If the owner refuses
// the attach (a 4xx), the server releases a name this call bound. If the
// outcome is unknown (the owner did not answer, or the server stopped),
// the name stays bound to the caller's own sandbox, proven for that
// caller: it routes nowhere until the owner holds a row for it, a retry
// finds it bound and goes on, and a detach or the sandbox's delete
// releases it. A create's names are bound to its reservation, so a failed
// or abandoned create releases them with the reservation.

// customDomainProofTimeout bounds one DNS lookup a server makes for a
// caller's proof. A lookup that runs out is an answer of "try again"
// (models.ErrCustomDomainProofUnavailable, 503), never a refusal. A var so
// a test can shorten it.
var customDomainProofTimeout = 5 * time.Second

// customDomainBinder is the part of the server's cluster client the binds
// use (cluster.Cluster). A worker or gateway has none: it binds nothing.
type customDomainBinder interface {
	IsClusterHostname(host string) bool
	AddCustomDomainForIncarnation(ctx context.Context, sandboxID, incarnationID, hostname string) error
}

// BindsCustomDomainsForCallers reports whether this node binds a custom
// hostname for a caller before the attach or create goes on to the
// sandbox's owner: a cluster server. On a single node the owner checks and
// binds, as it always did.
func (s *Service) BindsCustomDomainsForCallers() bool {
	if !s.cfg.EnableCluster || !s.cfg.IsServer() {
		return false
	}
	_, ok := s.Cluster().(customDomainBinder)
	return ok
}

// BindCustomDomain is a server's half of a custom-domain attach. It returns
// the context to serve the call with, which names the hostname as bound
// when the sandbox holds it now, and release, which is non-nil only when
// this call bound it: the caller runs release if the owner refuses the
// attach. A call it cannot judge here (no such sandbox in this server's
// view, another team's sandbox for a scoped caller, a malformed hostname)
// goes on unchanged, and the owner or the route answers it as before.
func (s *Service) BindCustomDomain(ctx context.Context, sandboxID, hostname string) (context.Context, func(), error) {
	binder, ok := s.Cluster().(customDomainBinder)
	if !ok || !s.BindsCustomDomainsForCallers() {
		return ctx, nil, nil
	}
	canonical, err := models.NormalizeCustomDomain(hostname, s.cfg.Domain)
	if err != nil {
		return ctx, nil, nil
	}
	p, ok := s.Cluster().PlacementOf(sandboxID)
	if !ok {
		return ctx, nil, nil
	}
	// A scoped caller sees only its own team's sandboxes: the route
	// answers 404 for another team's, as for one that does not exist.
	if owner, scoped := ownerScope(ctx); scoped && strings.TrimSpace(p.OwnerRef) != owner {
		return ctx, nil, nil
	}
	if binder.IsClusterHostname(canonical) {
		return ctx, nil, fmt.Errorf("%w: %q is one of the cluster's own names", models.ErrCustomDomainInvalid, canonical)
	}
	bound := cluster.ContextWithCustomDomainsBound(ctx, cluster.CustomDomainsBound{SandboxID: p.SandboxID, Hostnames: []string{canonical}})
	if placementHoldsHostname(p, canonical) {
		return bound, nil, nil
	}
	if err := s.proveCustomDomainForCaller(ctx, canonical, customDomainProofToken(ctx, p.OwnerRef)); err != nil {
		return ctx, nil, err
	}
	if err := s.bindCustomDomain(ctx, binder, p.SandboxID, p.IncarnationID, canonical); err != nil {
		return ctx, nil, err
	}
	release := func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.removeClusterCustomDomain(rctx, p.SandboxID, canonical); err != nil && s.logger != nil {
			s.logger.Warn("custom domain: could not release a name the owner refused; a detach or the sandbox's delete releases it",
				"sandbox_id", p.SandboxID, "hostname", canonical, "error", err)
		}
	}
	return bound, release, nil
}

// BindCreateCustomDomains is a server's half of a create with
// custom_domains: it binds each hostname to the create's reservation
// (sandboxID at incarnationID) and returns the context the create goes on
// with. A failure leaves the names bound so far on the reservation, which
// the caller cancels.
func (s *Service) BindCreateCustomDomains(ctx context.Context, sandboxID, incarnationID string, hostnames []string) (context.Context, error) {
	binder, ok := s.Cluster().(customDomainBinder)
	if len(hostnames) == 0 || !ok || !s.BindsCustomDomainsForCallers() {
		return ctx, nil
	}
	canonical, err := models.ValidateCustomDomainList(hostnames, s.cfg.Domain)
	if err != nil {
		return ctx, err
	}
	for _, h := range canonical {
		if binder.IsClusterHostname(h) {
			return ctx, fmt.Errorf("%w: %q is one of the cluster's own names", models.ErrCustomDomainInvalid, h)
		}
	}
	if !hostCapable(ctx) {
		ownerToken := customDomainProofToken(ctx, ownerRefForCreate(ctx))
		for _, h := range canonical {
			if err := s.proveCustomDomainForCaller(ctx, h, ownerToken); err != nil {
				return ctx, err
			}
		}
	}
	for _, h := range canonical {
		if err := s.bindCustomDomain(ctx, binder, sandboxID, incarnationID, h); err != nil {
			return ctx, err
		}
	}
	return cluster.ContextWithCustomDomainsBound(ctx, cluster.CustomDomainsBound{SandboxID: sandboxID, Hostnames: canonical}), nil
}

// proveCustomDomainForCaller looks up the TXT proof a server checks for a
// caller, bounded by customDomainProofTimeout.
func (s *Service) proveCustomDomainForCaller(ctx context.Context, hostname, ownerToken string) error {
	resolver := s.dnsResolver
	if resolver == nil {
		resolver = &DefaultDNSResolver{}
	}
	lctx, cancel := context.WithTimeout(ctx, customDomainProofTimeout)
	defer cancel()
	return verifyCustomDomainOwnership(lctx, resolver, hostname, s.cfg.CustomDomainVerifyPrefix, s.cfg.CustomDomainVerifyValuePrefix, ownerToken)
}

// bindCustomDomain proposes the binding as this server.
func (s *Service) bindCustomDomain(ctx context.Context, binder customDomainBinder, sandboxID, incarnationID, hostname string) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := binder.AddCustomDomainForIncarnation(cctx, sandboxID, incarnationID, hostname); err != nil {
		if errors.Is(err, cluster.ErrCustomHostnameConflict) {
			return store.ErrCustomDomainConflict
		}
		return fmt.Errorf("cluster: bind custom domain: %w", err)
	}
	return nil
}

// customDomainBoundForCall reports whether a server bound hostname to
// sandboxID for this call (BindCustomDomain, BindCreateCustomDomains): the
// owner then does not look the proof up again.
func customDomainBoundForCall(ctx context.Context, sandboxID, hostname string) bool {
	b, ok := cluster.CustomDomainsBoundFromContext(ctx)
	return ok && b.Covers(sandboxID, hostname)
}

func placementHoldsHostname(p cluster.Placement, hostname string) bool {
	for _, h := range p.CustomHostnames {
		if h == hostname {
			return true
		}
	}
	return false
}
