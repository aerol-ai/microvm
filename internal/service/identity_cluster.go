package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// identityCluster is the replicated identity store: the Raft FSM on a
// server (cluster.Cluster), the server tier on a dedicated worker
// (cluster.Agent). The single-node Noop doesn't implement it.
type identityCluster interface {
	WriteIdentity(context.Context, cluster.IdentityWriteRequest) (cluster.IdentityWriteResponse, error)
	ReadIdentity(context.Context, cluster.IdentityReadRequest) (cluster.IdentityReadResponse, error)
}

// clusterIdentity adapts the replicated store to identityBackend.
type clusterIdentity struct{ c identityCluster }

func (b clusterIdentity) ReadIdentityKeys(ctx context.Context) (cloudidentity.KeySet, error) {
	resp, err := b.c.ReadIdentity(ctx, cluster.IdentityReadRequest{Keys: true})
	if err != nil {
		return cloudidentity.KeySet{}, fmt.Errorf("%w: %v", ErrIdentityUnavailable, err)
	}
	if resp.Keys == nil {
		return cloudidentity.KeySet{}, nil
	}
	return *resp.Keys, nil
}

func (b clusterIdentity) WriteIdentityKeys(ctx context.Context, expected int64, keys []cloudidentity.KeyRecord) (cloudidentity.KeySet, error) {
	resp, err := b.c.WriteIdentity(ctx, cluster.IdentityWriteRequest{Keys: &cluster.IdentityKeysWrite{ExpectedGeneration: expected, Keys: keys}})
	if err != nil {
		return cloudidentity.KeySet{}, clusterIdentityError(err)
	}
	if resp.Keys == nil {
		return cloudidentity.KeySet{}, fmt.Errorf("%w: the leader returned no key set", ErrIdentityUnavailable)
	}
	return *resp.Keys, nil
}

func (b clusterIdentity) PutIdentityRole(ctx context.Context, owner, tag, minRole string, _ time.Time) (models.IdentityRole, bool, error) {
	resp, err := b.c.WriteIdentity(ctx, cluster.IdentityWriteRequest{Role: &cluster.IdentityRoleRecord{Owner: owner, Tag: tag, MinRole: minRole}})
	if err != nil {
		return models.IdentityRole{}, false, clusterIdentityError(err)
	}
	if resp.Role == nil {
		return models.IdentityRole{}, false, fmt.Errorf("%w: the leader returned no role", ErrIdentityUnavailable)
	}
	return roleFromRecord(*resp.Role), resp.Changed, nil
}

func (b clusterIdentity) GetIdentityRole(ctx context.Context, owner, tag string) (models.IdentityRole, error) {
	resp, err := b.c.ReadIdentity(ctx, cluster.IdentityReadRequest{Owner: owner, Tags: []string{tag}})
	if err != nil {
		return models.IdentityRole{}, fmt.Errorf("%w: %v", ErrIdentityUnavailable, err)
	}
	for _, rec := range resp.Roles {
		if rec.Tag == tag {
			return roleFromRecord(rec), nil
		}
	}
	return models.IdentityRole{}, ErrIdentityRoleNotFound
}

func (b clusterIdentity) ListIdentityRoles(ctx context.Context, owner, after string, limit int) ([]models.IdentityRole, error) {
	resp, err := b.c.ReadIdentity(ctx, cluster.IdentityReadRequest{Owner: owner, RolePage: true, After: after, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityUnavailable, err)
	}
	out := make([]models.IdentityRole, 0, len(resp.Roles))
	for _, rec := range resp.Roles {
		out = append(out, roleFromRecord(rec))
	}
	return out, nil
}

func (b clusterIdentity) DeleteIdentityRole(ctx context.Context, owner, tag string) error {
	if _, err := b.c.WriteIdentity(ctx, cluster.IdentityWriteRequest{Role: &cluster.IdentityRoleRecord{Owner: owner, Tag: tag}, DeleteRole: true}); err != nil {
		return clusterIdentityError(err)
	}
	return nil
}

// clusterIdentityError maps the cluster's verdicts onto the service's: a
// lost key CAS stays a conflict the caller re-reads on, an FSM refusal is a
// bad request, and everything else (no leader, an unfinished rolling
// upgrade, an unreachable server tier) is a retryable 503.
func clusterIdentityError(err error) error {
	switch {
	case errors.Is(err, cluster.ErrIdentityKeysConflict):
		return fmt.Errorf("%w: %v", ErrIdentityKeysConflict, err)
	case errors.Is(err, cluster.ErrIdentityInvalid):
		return fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	return fmt.Errorf("%w: %v", ErrIdentityUnavailable, err)
}

func roleFromRecord(r cluster.IdentityRoleRecord) models.IdentityRole {
	return models.IdentityRole{
		Tag:       r.Tag,
		MinRole:   r.MinRole,
		CreatedAt: time.Unix(0, r.CreatedUnixNano).UTC(),
		UpdatedAt: time.Unix(0, r.UpdatedUnixNano).UTC(),
	}
}

// noClusterIdentity answers every identity call on a cluster that has no
// replicated store wired.
type noClusterIdentity struct{}

var errNoClusterIdentity = fmt.Errorf("%w: this cluster has no replicated identity store", ErrIdentityUnavailable)

func (noClusterIdentity) ReadIdentityKeys(context.Context) (cloudidentity.KeySet, error) {
	return cloudidentity.KeySet{}, errNoClusterIdentity
}

func (noClusterIdentity) WriteIdentityKeys(context.Context, int64, []cloudidentity.KeyRecord) (cloudidentity.KeySet, error) {
	return cloudidentity.KeySet{}, errNoClusterIdentity
}

func (noClusterIdentity) PutIdentityRole(context.Context, string, string, string, time.Time) (models.IdentityRole, bool, error) {
	return models.IdentityRole{}, false, errNoClusterIdentity
}

func (noClusterIdentity) GetIdentityRole(context.Context, string, string) (models.IdentityRole, error) {
	return models.IdentityRole{}, errNoClusterIdentity
}

func (noClusterIdentity) ListIdentityRoles(context.Context, string, string, int) ([]models.IdentityRole, error) {
	return nil, errNoClusterIdentity
}

func (noClusterIdentity) DeleteIdentityRole(context.Context, string, string) error {
	return errNoClusterIdentity
}
