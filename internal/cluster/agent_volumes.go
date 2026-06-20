package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Agent-role nodes are not raft voters, so they have no local FSM replica.
// Volume writes forward to a server peer via applyCommand (the generic raft
// apply channel); volume reads forward to the consolidated internal volume
// endpoint, which the server node answers from its own replicated FSM.

// VolumeQueryResponse is the wire shape of the internal volume read endpoint.
// Exactly one of Volume / Volumes / Exists is meaningful per request kind.
type VolumeQueryResponse struct {
	Volume  *models.Volume  `json:"volume,omitempty"`
	Volumes []models.Volume `json:"volumes,omitempty"`
	Exists  bool            `json:"exists,omitempty"`
}

func (a *Agent) VolumeUpsert(ctx context.Context, v models.Volume, maxPerTenant int) (models.Volume, bool, error) {
	tenant := strings.TrimSpace(v.Tenant)
	name := strings.TrimSpace(v.Name)
	if tenant == "" || name == "" || strings.TrimSpace(v.ID) == "" || strings.TrimSpace(v.Backend) == "" {
		return models.Volume{}, false, fmt.Errorf("cluster agent: VolumeUpsert requires tenant, name, id, backend")
	}
	if existing, err := a.VolumeByName(ctx, tenant, name); err == nil {
		return existing, false, nil
	}
	if err := a.applyCommand(ctx, command{Op: opUpsertVolume, Volume: &v, MaxPerTenant: maxPerTenant}); err != nil {
		if errors.Is(err, ErrVolumeQuotaExceeded) {
			return models.Volume{}, false, ErrVolumeQuotaExceeded
		}
		return models.Volume{}, false, err
	}
	row, err := a.readbackVolume(ctx, tenant, name)
	if err != nil {
		return models.Volume{}, false, err
	}
	return row, row.ID == v.ID, nil
}

func (a *Agent) readbackVolume(ctx context.Context, tenant, name string) (models.Volume, error) {
	deadline := time.Now().Add(volumeReadbackTimeout)
	for {
		if row, err := a.VolumeByName(ctx, tenant, name); err == nil {
			return row, nil
		}
		if time.Now().After(deadline) {
			return models.Volume{}, fmt.Errorf("cluster agent: volume %q/%q not visible after apply: %w", tenant, name, ErrUnknownVolume)
		}
		select {
		case <-ctx.Done():
			return models.Volume{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (a *Agent) VolumeDelete(ctx context.Context, tenant, id string) error {
	tenant = strings.TrimSpace(tenant)
	id = strings.TrimSpace(id)
	if tenant == "" || id == "" {
		return fmt.Errorf("cluster agent: VolumeDelete requires tenant and id")
	}
	err := a.applyCommand(ctx, command{Op: opDeleteVolume, VolumeTenant: tenant, VolumeID: id})
	if errors.Is(err, ErrUnknownVolume) {
		return ErrUnknownVolume
	}
	return err
}

func (a *Agent) VolumeByID(ctx context.Context, tenant, id string) (models.Volume, error) {
	q := url.Values{"kind": {"id"}, "tenant": {tenant}, "id": {id}}
	resp, err := a.queryVolumes(ctx, q)
	if err != nil {
		return models.Volume{}, err
	}
	if resp.Volume == nil {
		return models.Volume{}, ErrUnknownVolume
	}
	return *resp.Volume, nil
}

func (a *Agent) VolumeByName(ctx context.Context, tenant, name string) (models.Volume, error) {
	q := url.Values{"kind": {"name"}, "tenant": {tenant}, "name": {name}}
	resp, err := a.queryVolumes(ctx, q)
	if err != nil {
		return models.Volume{}, err
	}
	if resp.Volume == nil {
		return models.Volume{}, ErrUnknownVolume
	}
	return *resp.Volume, nil
}

func (a *Agent) VolumesForTenant(ctx context.Context, tenant string) ([]models.Volume, error) {
	q := url.Values{"kind": {"list"}, "tenant": {tenant}}
	resp, err := a.queryVolumes(ctx, q)
	if err != nil {
		return nil, err
	}
	if resp.Volumes == nil {
		return []models.Volume{}, nil
	}
	return resp.Volumes, nil
}

func (a *Agent) VolumeExistsForSource(ctx context.Context, source string) (bool, error) {
	q := url.Values{"kind": {"source"}, "source": {source}}
	resp, err := a.queryVolumes(ctx, q)
	if err != nil {
		return false, err
	}
	return resp.Exists, nil
}

func (a *Agent) queryVolumes(ctx context.Context, q url.Values) (VolumeQueryResponse, error) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	path := PublicInternalVolumePath + "?" + q.Encode()
	var resp VolumeQueryResponse
	if err := a.doControlPlaneJSON(reqCtx, "GET", path, path, nil, &resp); err != nil {
		// A 404 from the server means "no such volume", which the typed reads
		// above translate into ErrUnknownVolume via a nil Volume.
		if isStatus(err, 404) {
			return VolumeQueryResponse{}, nil
		}
		return VolumeQueryResponse{}, err
	}
	return resp, nil
}
