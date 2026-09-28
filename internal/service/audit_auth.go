package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) retainSandboxAuditACL(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || s.store == nil || sandbox == nil {
		return nil
	}
	incarnationID, err := s.localSandboxAuditIncarnation(ctx, sandbox)
	if err != nil {
		return fmt.Errorf("retain sandbox audit ACL: %w", err)
	}
	if incarnationID == "" {
		return errors.New("retain sandbox audit ACL: incarnation id required")
	}
	sandbox.AuditIncarnationID = incarnationID
	return s.store.UpsertSandboxAuditACL(ctx, sandbox.ID, strings.TrimSpace(sandbox.OwnerRef), incarnationID)
}

// localSandboxAuditIncarnation resolves only from local durable identity.
// Cluster placement is intentionally excluded: a stale local row can share an
// ID with a newer remote lifecycle and must never acquire that lifecycle's ACL.
// The ACL written atomically with the sandbox is authoritative after reload;
// deriving another ID from the toolbox token would split one live lifecycle.
func (s *Service) localSandboxAuditIncarnation(ctx context.Context, sandbox *models.Sandbox) (string, error) {
	if s == nil || sandbox == nil || strings.TrimSpace(sandbox.ID) == "" {
		return "", nil
	}
	if incarnationID := strings.TrimSpace(sandbox.AuditIncarnationID); incarnationID != "" {
		return incarnationID, nil
	}
	if s.store == nil {
		return "", nil
	}
	incarnationID, err := s.store.CurrentSandboxAuditIncarnation(ctx, sandbox.ID)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(incarnationID), nil
}

// AuthorizeSandboxAuditAccess checks tenant/operator scope for GET …/audit
// without requiring a local sandbox row. Ingress and non-owner workers resolve
// OwnerRef from Placement.OwnerRef / the placement owner (secure peer meta) so
// fan-out can stay on the entry node (plans/secrets-hardening E1b + P1 ingress).
//
// After sandbox deletion, retained history stays readable via sandbox_audit_acl
// (and the Raft-replicated Placement.OwnerRef while placement remains). Missing
// placement ownership metadata fails closed; no ID-only peer lookup can cross
// an ID-reuse boundary. ACL rows are incarnation-
// scoped; authorize requires an incarnation match (from query, else live
// placement). There is no legacy any-incarnation fallback.
func (s *Service) AuthorizeSandboxAuditAccess(ctx context.Context, sandboxID, incarnationID string) (string, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if s == nil || sandboxID == "" {
		return "", store.ErrNotFound
	}
	c := s.Cluster()
	var (
		cachedACL       cluster.AuditACL
		cachedACLExists bool
		cachedACLQuery  string
		cachedACLLoaded bool
	)
	loadClusterACL := func(requestedIncarnation string) (cluster.AuditACL, bool, error) {
		requestedIncarnation = strings.TrimSpace(requestedIncarnation)
		if c == nil {
			return cluster.AuditACL{}, false, nil
		}
		if cachedACLLoaded && (cachedACLQuery == requestedIncarnation ||
			(cachedACLQuery == "" && strings.TrimSpace(cachedACL.IncarnationID) == requestedIncarnation)) {
			return cachedACL, cachedACLExists, nil
		}
		acl, exists, err := c.AuditACLForSandbox(ctx, sandboxID, requestedIncarnation)
		if err != nil {
			return cluster.AuditACL{}, false, err
		}
		cachedACL, cachedACLExists, cachedACLQuery, cachedACLLoaded = acl, exists, requestedIncarnation, true
		return acl, exists, nil
	}

	// A live local row is authoritative for its current lifecycle. Explicit
	// older-incarnation queries may continue into the retained ACL indexes.
	if s.store != nil {
		sb, err := s.store.Get(ctx, sandboxID)
		if err == nil {
			currentIncarnation, incErr := s.localSandboxAuditIncarnation(ctx, sb)
			if incErr != nil {
				return "", incErr
			}
			if currentIncarnation == "" {
				return "", store.ErrNotFound
			}
			if incarnationID == "" {
				incarnationID = currentIncarnation
			}
			if incarnationID == currentIncarnation {
				if err := enforceOwner(ctx, sb); err != nil {
					return "", err
				}
				return incarnationID, nil
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
	}
	if incarnationID == "" {
		if c != nil {
			if p, ok := c.PlacementOf(sandboxID); ok {
				incarnationID = strings.TrimSpace(p.IncarnationID)
			}
		}
		if incarnationID == "" && s.store != nil {
			var err error
			incarnationID, err = s.store.LatestRetainedSandboxAuditIncarnation(ctx, sandboxID)
			if err != nil {
				return "", err
			}
		}
		if incarnationID == "" {
			acl, exists, err := loadClusterACL("")
			if err != nil {
				return "", err
			}
			if exists {
				incarnationID = strings.TrimSpace(acl.IncarnationID)
			}
		}
	}
	if incarnationID == "" {
		return "", store.ErrNotFound
	}

	owner, scoped := ownerScope(ctx)

	if !scoped {
		// Operators are fleet-wide but still require an existence proof. Allowing
		// arbitrary IDs here turns every request into a cluster fan-out oracle.
		if c != nil {
			if p, ok := c.PlacementOf(sandboxID); ok {
				placeInc := strings.TrimSpace(p.IncarnationID)
				if placeInc != "" && incarnationID == placeInc {
					return incarnationID, nil
				}
			}
		}
		if s.store != nil {
			exists, err := s.store.HasSandboxAuditACL(ctx, sandboxID, incarnationID)
			if err != nil {
				return "", err
			}
			if exists {
				return incarnationID, nil
			}
		}
		if c != nil {
			acl, exists, err := loadClusterACL(incarnationID)
			if err != nil {
				return "", err
			}
			if exists && strings.TrimSpace(acl.IncarnationID) == incarnationID {
				return incarnationID, nil
			}
		}
		return "", store.ErrNotFound
	}

	if c != nil {
		if p, ok := c.PlacementOf(sandboxID); ok {
			placeInc := strings.TrimSpace(p.IncarnationID)
			if placeInc != "" && incarnationID == placeInc {
				if ref := strings.TrimSpace(p.OwnerRef); ref != "" {
					if ref == owner {
						return incarnationID, nil
					}
					return "", store.ErrNotFound
				}
			}
		}
	}
	if s.store != nil {
		ref, err := s.store.GetSandboxAuditACLOwnerRef(ctx, sandboxID, incarnationID)
		if err != nil {
			return "", err
		}
		if ref != "" {
			if ref == owner {
				return incarnationID, nil
			}
			return "", store.ErrNotFound
		}
	}
	if c != nil {
		acl, ok, err := loadClusterACL(incarnationID)
		if err != nil {
			return "", err
		}
		if ok && strings.TrimSpace(acl.IncarnationID) == incarnationID {
			if strings.TrimSpace(acl.OwnerRef) == owner {
				return incarnationID, nil
			}
			return "", store.ErrNotFound
		}
	}
	return "", store.ErrNotFound
}
