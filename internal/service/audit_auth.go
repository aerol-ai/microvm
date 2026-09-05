package service

import (
	"context"
	"errors"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) retainSandboxAuditACL(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || s.store == nil || sandbox == nil {
		return nil
	}
	return s.store.UpsertSandboxAuditACL(ctx, sandbox.ID, strings.TrimSpace(sandbox.OwnerRef), s.secretIncarnationForSeal(sandbox.ID))
}

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
		if incarnationID == "" && s.store != nil {
			var err error
			incarnationID, err = s.store.CurrentSandboxAuditIncarnation(ctx, sandboxID)
			if err != nil {
				return err
			}
		}
	}
	if s.store != nil {
		sb, err := s.store.Get(ctx, sandboxID)
		if err == nil {
			currentIncarnation := s.secretIncarnationForSeal(sandboxID)
			if incarnationID != "" && (currentIncarnation == "" || incarnationID != currentIncarnation) {
				return store.ErrNotFound
			}
			if incarnationID == "" {
				incarnationID = currentIncarnation
			}
			_ = s.store.UpsertSandboxAuditACL(ctx, sandboxID, strings.TrimSpace(sb.OwnerRef), currentIncarnation)
			return enforceOwner(ctx, sb)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	owner, scoped := ownerScope(ctx)
	c := s.Cluster()

	if !scoped {
		// Operators are fleet-wide but still require an existence proof. Allowing
		// arbitrary IDs here turns every request into a cluster fan-out oracle.
		if c != nil {
			if p, ok := c.PlacementOf(sandboxID); ok {
				placeInc := strings.TrimSpace(p.IncarnationID)
				if incarnationID == "" || placeInc == "" || incarnationID == placeInc {
					return nil
				}
				return store.ErrNotFound
			}
		}
		if s.store != nil {
			exists, err := s.store.HasSandboxAuditACL(ctx, sandboxID, incarnationID)
			if err != nil {
				return err
			}
			if exists {
				return nil
			}
		}
		if c != nil {
			acl, exists, err := c.AuditACLForSandbox(ctx, sandboxID)
			if err != nil {
				return err
			}
			if exists && (incarnationID == "" || strings.TrimSpace(acl.IncarnationID) == incarnationID) {
				return nil
			}
		}
		return store.ErrNotFound
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
		acl, ok, err := c.AuditACLForSandbox(ctx, sandboxID)
		if err != nil {
			return err
		}
		if ok && (incarnationID == "" || strings.TrimSpace(acl.IncarnationID) == incarnationID) {
			if strings.TrimSpace(acl.OwnerRef) == owner {
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
	nodeID := strings.TrimSpace(p.OwnerNodeID)
	if nodeID == "" {
		return "", store.ErrNotFound
	}
	ref, ok, err := fetcher.FetchSandboxOwnerRef(ctx, nodeID, p.SandboxID)
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
