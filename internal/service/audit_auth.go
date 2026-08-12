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
// OwnerRef from Placement.OwnerRef / the placement owner (secure peer meta) so
// fan-out can stay on the entry node (plans/secrets-hardening E1b + P1 ingress).
//
// After sandbox deletion, retained history stays readable via sandbox_audit_acl
// (and Placement.OwnerRef while placement remains). ACL rows are incarnation-
// scoped; authorize requires an incarnation match (from query, else live
// placement). There is no legacy any-incarnation fallback.
func (s *Service) AuthorizeSandboxAuditAccess(ctx context.Context, sandboxID, incarnationID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if s == nil || sandboxID == "" {
		return store.ErrNotFound
	}
	if incarnationID == "" {
		if c := s.Cluster(); c != nil {
			if p, ok := c.PlacementOf(sandboxID); ok {
				incarnationID = strings.TrimSpace(p.IncarnationID)
			}
		}
	}
	if s.store != nil {
		sb, err := s.store.Get(ctx, sandboxID)
		if err == nil {
			if ref := strings.TrimSpace(sb.OwnerRef); ref != "" {
				_ = s.store.UpsertSandboxAuditACL(ctx, sandboxID, ref, incarnationID)
			}
			return enforceOwner(ctx, sb)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	owner, scoped := ownerScope(ctx)
	c := s.Cluster()

	if !scoped {
		// Operator/PAT and internal callers are fleet-wide. Do not require a
		// live placement or a node-local ACL: after deletion, an arbitrary
		// ingress must still be able to fan out and discover retained evidence.
		// Tenant callers remain fenced by the owner checks below.
		return nil
	}

	if c != nil {
		if p, ok := c.PlacementOf(sandboxID); ok {
			// Live placement: incarnation must match when both sides are set.
			placeInc := strings.TrimSpace(p.IncarnationID)
			if incarnationID != "" && placeInc != "" && incarnationID != placeInc {
				return store.ErrNotFound
			}
			if ref := strings.TrimSpace(p.OwnerRef); ref != "" {
				if ref == owner {
					return nil
				}
				return store.ErrNotFound
			}
			if strings.TrimSpace(p.OwnerNodeID) != "" {
				ownerRef, err := s.fetchSandboxOwnerRef(ctx, p)
				if err != nil {
					return err
				}
				if ownerRef == owner {
					return nil
				}
				return store.ErrNotFound
			}
		}
	}
	if s.store != nil {
		ref, err := s.store.GetSandboxAuditACLOwnerRef(ctx, sandboxID, incarnationID)
		if err != nil {
			return err
		}
		if ref != "" {
			if ref == owner {
				return nil
			}
			return store.ErrNotFound
		}
	}
	if c != nil {
		ref, ok, err := c.AuditOwnerRef(ctx, sandboxID)
		if err != nil {
			return err
		}
		if ok {
			if strings.TrimSpace(ref) == owner {
				return nil
			}
			return store.ErrNotFound
		}
	}
	return store.ErrNotFound
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
