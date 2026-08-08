package service

import (
	"context"
	"errors"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
)

// AuthorizeSandboxAuditAccess checks tenant/operator scope for GET …/audit
// without requiring a local sandbox row. Ingress and non-owner workers resolve
// OwnerRef from the placement owner (secure peer meta) so fan-out can stay on
// the entry node (plans/secrets-hardening E1b + P1 ingress fix).
func (s *Service) AuthorizeSandboxAuditAccess(ctx context.Context, sandboxID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	if s == nil || sandboxID == "" {
		return store.ErrNotFound
	}
	if s.store != nil {
		sb, err := s.store.Get(ctx, sandboxID)
		if err == nil {
			return enforceOwner(ctx, sb)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	owner, scoped := ownerScope(ctx)
	c := s.Cluster()
	if c == nil {
		return store.ErrNotFound
	}
	p, ok := c.PlacementOf(sandboxID)
	if !ok || strings.TrimSpace(p.OwnerNodeID) == "" {
		return store.ErrNotFound
	}
	if !scoped {
		// Operator/PAT: placement existence is enough.
		return nil
	}

	// Tenant on a non-owner node: fetch OwnerRef from the placement owner.
	ownerRef, err := s.fetchSandboxOwnerRef(ctx, p)
	if err != nil {
		return err
	}
	if ownerRef != owner {
		return store.ErrNotFound
	}
	return nil
}

func (s *Service) fetchSandboxOwnerRef(ctx context.Context, p cluster.Placement) (string, error) {
	fetcher := s.sandboxMetaFetcher()
	if fetcher == nil {
		return "", store.ErrNotFound
	}
	apiURL := strings.TrimSpace(p.OwnerAPIURL)
	if apiURL == "" {
		return "", store.ErrNotFound
	}
	ref, ok, err := fetcher.FetchSandboxOwnerRef(ctx, apiURL, p.SandboxID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", store.ErrNotFound
	}
	return strings.TrimSpace(ref), nil
}

func (s *Service) sandboxMetaFetcher() cluster.SandboxMetaFetcher {
	if s == nil {
		return nil
	}
	if s.testSandboxMetaFetcher != nil {
		return s.testSandboxMetaFetcher
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	if f, ok := c.(cluster.SandboxMetaFetcher); ok {
		return f
	}
	return nil
}

// SandboxOwnerRefLocal returns the local OwnerRef for an operator peer probe.
// Does not apply tenant scope — callers must be operator-gated.
func (s *Service) SandboxOwnerRefLocal(ctx context.Context, sandboxID string) (ownerRef string, ok bool, err error) {
	if s == nil || s.store == nil {
		return "", false, nil
	}
	sb, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	return sb.OwnerRef, true, nil
}
