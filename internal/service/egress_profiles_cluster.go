package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// egressProfileCluster is the replicated profile store: the Raft FSM on a
// server (cluster.Cluster), the server tier through a cache on a dedicated
// worker (cluster.Agent). The single-node Noop doesn't implement it.
type egressProfileCluster interface {
	WriteEgressProfile(context.Context, cluster.EgressProfileWriteRequest) (cluster.EgressProfileWriteResponse, error)
	ReadEgressProfiles(context.Context, cluster.EgressProfileReadRequest) (cluster.EgressProfileReadResponse, error)
}

// clusterProfiles adapts the replicated store to egressProfileBackend.
type clusterProfiles struct{ c egressProfileCluster }

func (b clusterProfiles) PutEgressProfile(ctx context.Context, owner, name string, allowOut []string, description string, _ time.Time) (models.EgressProfile, bool, error) {
	n, err := countHostnames(allowOut)
	if err != nil {
		return models.EgressProfile{}, false, err
	}
	resp, err := b.c.WriteEgressProfile(ctx, cluster.EgressProfileWriteRequest{Profile: cluster.EgressProfileRecord{
		Owner: owner, Name: name, AllowOut: allowOut, Description: description, HostnameCount: n,
	}})
	if err != nil {
		return models.EgressProfile{}, false, clusterProfileError(err)
	}
	return profileFromRecord(resp.Profile), resp.Changed, nil
}

func (b clusterProfiles) GetEgressProfile(ctx context.Context, owner, name string) (models.EgressProfile, error) {
	resp, err := b.c.ReadEgressProfiles(ctx, cluster.EgressProfileReadRequest{Owner: owner, Names: []string{name}})
	if err != nil {
		return models.EgressProfile{}, fmt.Errorf("%w: %v", ErrEgressProfileUnavailable, err)
	}
	for _, rec := range resp.Profiles {
		if rec.Name == name {
			return profileFromRecord(rec), nil
		}
	}
	return models.EgressProfile{}, ErrEgressProfileNotFound
}

func (b clusterProfiles) ListEgressProfiles(ctx context.Context, owner, after string, limit int) ([]models.EgressProfile, error) {
	resp, err := b.c.ReadEgressProfiles(ctx, cluster.EgressProfileReadRequest{Owner: owner, After: after, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgressProfileUnavailable, err)
	}
	out := make([]models.EgressProfile, 0, len(resp.Profiles))
	for _, rec := range resp.Profiles {
		out = append(out, profileFromRecord(rec))
	}
	return out, nil
}

func (b clusterProfiles) DeleteEgressProfile(ctx context.Context, owner, name string) error {
	_, err := b.c.WriteEgressProfile(ctx, cluster.EgressProfileWriteRequest{Delete: true, Profile: cluster.EgressProfileRecord{Owner: owner, Name: name}})
	if err != nil {
		return clusterProfileError(err)
	}
	return nil
}

// clusterProfileError maps the cluster's verdicts onto the service's: the
// FSM's refusals keep their 409s, and everything else (no leader, an
// unfinished rolling upgrade, an unreachable server tier) is a retryable 503.
func clusterProfileError(err error) error {
	switch {
	case errors.Is(err, cluster.ErrEgressProfileInUse):
		return fmt.Errorf("%w: %v", ErrEgressProfileInUse, err)
	case errors.Is(err, cluster.ErrEgressProfileCapExceeded):
		return fmt.Errorf("%w: %v", ErrEgressProfileCapExceeded, err)
	}
	return fmt.Errorf("%w: %v", ErrEgressProfileUnavailable, err)
}

func profileFromRecord(r cluster.EgressProfileRecord) models.EgressProfile {
	return models.EgressProfile{
		Name:        r.Name,
		AllowOut:    append([]string{}, r.AllowOut...),
		Description: r.Description,
		Generation:  r.Generation,
		CreatedAt:   time.Unix(0, r.CreatedUnixNano).UTC(),
		UpdatedAt:   time.Unix(0, r.UpdatedUnixNano).UTC(),
	}
}
