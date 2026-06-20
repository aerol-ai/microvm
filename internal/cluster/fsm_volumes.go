package cluster

import (
	"errors"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Platform-volume metadata is replicated through the placement FSM so a Daytona
// volume's id/name/source survive the tenant's API ownership moving between
// nodes (membership changes, failover). Only the small metadata row is in raft;
// the backing bytes live in S3/NFS at a deterministic, tenant-scoped path. The
// apply cases live in fsm.go's switch; the read helpers and errors live here.

var (
	// ErrVolumeQuotaExceeded is returned by opUpsertVolume when inserting a new
	// row would exceed the tenant's configured volume-count cap.
	ErrVolumeQuotaExceeded = errors.New("cluster: tenant volume quota exceeded")
	// ErrUnknownVolume is returned by volume reads/deletes when no replicated row
	// exists for the (tenant, id).
	ErrUnknownVolume = errors.New("cluster: unknown volume")
)

// VolumeByID returns the replicated row for (tenant, id) or ErrUnknownVolume.
func (f *placementFSM) VolumeByID(tenant, id string) (models.Volume, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.volumes[volumeKey(strings.TrimSpace(tenant), strings.TrimSpace(id))]
	if !ok {
		return models.Volume{}, ErrUnknownVolume
	}
	return v, nil
}

// VolumeByName resolves (tenant, name) → row via the name index, or
// ErrUnknownVolume.
func (f *placementFSM) VolumeByName(tenant, name string) (models.Volume, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	tenant = strings.TrimSpace(tenant)
	id, ok := f.volumeNameIndex[volumeNameKey(tenant, strings.TrimSpace(name))]
	if !ok {
		return models.Volume{}, ErrUnknownVolume
	}
	v, ok := f.volumes[volumeKey(tenant, id)]
	if !ok {
		return models.Volume{}, ErrUnknownVolume
	}
	return v, nil
}

// VolumesForTenant returns all of the tenant's replicated rows, newest first
// (matching the SQLite ListVolumes ordering). Never nil.
func (f *placementFSM) VolumesForTenant(tenant string) []models.Volume {
	f.mu.RLock()
	defer f.mu.RUnlock()
	prefix := strings.TrimSpace(tenant) + "\x00"
	out := []models.Volume{}
	for k, v := range f.volumes {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// VolumeCountForTenant counts the tenant's replicated rows (quota reads).
func (f *placementFSM) VolumeCountForTenant(tenant string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	prefix := strings.TrimSpace(tenant) + "\x00"
	n := 0
	for k := range f.volumes {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// LiveVolumeExistsForSource reports whether any replicated row resolves to
// source. The reclaim worker uses it cluster-wide instead of a single node's
// SQLite so it never deletes bytes a recreated volume still owns.
func (f *placementFSM) LiveVolumeExistsForSource(source string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	source = strings.TrimSpace(source)
	for _, v := range f.volumes {
		if v.Source == source {
			return true
		}
	}
	return false
}

// volumesSnapshot returns a copy of all replicated volume rows for the raft
// snapshot. Caller holds f.mu.
func (f *placementFSM) volumesSnapshotLocked() []models.Volume {
	out := make([]models.Volume, 0, len(f.volumes))
	for _, v := range f.volumes {
		out = append(out, v)
	}
	return out
}
