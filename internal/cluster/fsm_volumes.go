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
	// ErrVolumeInUse is returned when a delete races with or follows a sandbox
	// attachment that still points at the volume.
	ErrVolumeInUse = errors.New("cluster: volume is still attached")
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

// VolumeAttachmentCount returns the number of live replicated sandbox
// attachments for (tenant, volumeID).
func (f *placementFSM) VolumeAttachmentCount(tenant, volumeID string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.volumeAttachmentCountLocked(strings.TrimSpace(tenant), strings.TrimSpace(volumeID))
}

func (f *placementFSM) volumeAttachmentCountLocked(tenant, volumeID string) int {
	if tenant == "" || volumeID == "" {
		return 0
	}
	return len(f.volumeAttachmentsByVolume[volumeKey(tenant, volumeID)])
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

func (f *placementFSM) volumeAttachmentsSnapshotLocked() []models.VolumeAttachment {
	out := make([]models.VolumeAttachment, 0, len(f.volumeAttachments))
	for _, a := range f.volumeAttachments {
		out = append(out, a)
	}
	return out
}

func (f *placementFSM) putVolumeAttachmentLocked(a models.VolumeAttachment) {
	key := volumeAttachmentKey(a.Tenant, a.VolumeID, a.SandboxID, a.Target)
	if existing, ok := f.volumeAttachments[key]; ok {
		f.releaseVolumeAttachmentKeyLocked(key, existing)
	}
	f.volumeAttachments[key] = a
	vKey := volumeKey(a.Tenant, a.VolumeID)
	if f.volumeAttachmentsByVolume[vKey] == nil {
		f.volumeAttachmentsByVolume[vKey] = make(map[string]struct{})
	}
	f.volumeAttachmentsByVolume[vKey][key] = struct{}{}
	if f.volumeAttachmentsBySandbox[a.SandboxID] == nil {
		f.volumeAttachmentsBySandbox[a.SandboxID] = make(map[string]struct{})
	}
	f.volumeAttachmentsBySandbox[a.SandboxID][key] = struct{}{}
}

func (f *placementFSM) releaseVolumeAttachmentKeyLocked(key string, a models.VolumeAttachment) {
	delete(f.volumeAttachments, key)
	vKey := volumeKey(a.Tenant, a.VolumeID)
	if refs := f.volumeAttachmentsByVolume[vKey]; refs != nil {
		delete(refs, key)
		if len(refs) == 0 {
			delete(f.volumeAttachmentsByVolume, vKey)
		}
	}
	if refs := f.volumeAttachmentsBySandbox[a.SandboxID]; refs != nil {
		delete(refs, key)
		if len(refs) == 0 {
			delete(f.volumeAttachmentsBySandbox, a.SandboxID)
		}
	}
}

func (f *placementFSM) releaseVolumeAttachmentsForSandboxLocked(sandboxID string) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return
	}
	refs := f.volumeAttachmentsBySandbox[sandboxID]
	for key := range refs {
		if a, ok := f.volumeAttachments[key]; ok {
			f.releaseVolumeAttachmentKeyLocked(key, a)
		}
	}
}
