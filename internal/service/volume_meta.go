package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// volumeMetaStore is the platform-volume metadata source of truth. There are two
// implementations: the per-node SQLite store (single-node / clustering off) and
// a cluster-FSM-backed adapter (clustering on) that replicates the rows through
// raft so a volume's id/name/source survive the tenant's API ownership moving
// between nodes. The service selects between them with volumeMeta().
//
// Metadata and attachment ownership use the same abstraction: SQLite in
// single-node mode and the cluster FSM in cluster mode. The pending-deletion
// ledger remains local because each node deletes only its deterministic S3/NFS
// backing path.
type volumeMetaStore interface {
	GetOrCreate(ctx context.Context, v *models.Volume, maxPerTenant int) (*models.Volume, bool, error)
	ByID(ctx context.Context, tenant, id string) (*models.Volume, error)
	ByName(ctx context.Context, tenant, name string) (*models.Volume, error)
	List(ctx context.Context, tenant string) ([]models.Volume, error)
	DeleteRow(ctx context.Context, tenant, id string) error
	// DeleteRowOwingBytes deletes an unattached volume's row and records, in
	// the same step, that its backend bytes (at the row's source, else
	// source) are owed a delete. Refused while attached (ErrVolumeInUse).
	DeleteRowOwingBytes(ctx context.Context, vol models.Volume, source string) error
	ExistsForSource(ctx context.Context, source string) (bool, error)
	AttachmentCount(ctx context.Context, tenant, id string) (int, error)
	// AttachmentsForSandbox lists the attachments one sandbox holds; a destroy
	// reads them before they are released (delete_with_sandbox volumes).
	AttachmentsForSandbox(ctx context.Context, sandboxID string) ([]models.VolumeAttachment, error)
	PutAttachments(ctx context.Context, attachments []models.VolumeAttachment) error
	DeleteAttachmentsForSandbox(ctx context.Context, sandboxID, incarnationID string) error
}

// volumeMeta returns the cluster-FSM-backed store when clustering is enabled and
// a real cluster client is attached, else the local SQLite store. The selection
// is per-call so a node that joins/leaves a cluster picks up the right backing
// without re-wiring the service.
func (s *Service) volumeMeta() volumeMetaStore {
	if s != nil && s.testVolumeMeta != nil {
		return s.testVolumeMeta
	}
	if s.cfg.EnableCluster {
		if c := s.Cluster(); c != nil {
			return clusterVolumeMeta{c: c, store: s.store}
		}
	}
	return sqliteVolumeMeta{store: s.store}
}

// sqliteVolumeMeta is the single-node implementation backed by the SQLite store.
type sqliteVolumeMeta struct{ store *store.Store }

func (m sqliteVolumeMeta) GetOrCreate(ctx context.Context, v *models.Volume, maxPerTenant int) (*models.Volume, bool, error) {
	return m.store.GetOrCreateVolume(ctx, v, maxPerTenant)
}
func (m sqliteVolumeMeta) ByID(ctx context.Context, tenant, id string) (*models.Volume, error) {
	return m.store.GetVolumeByID(ctx, tenant, id)
}
func (m sqliteVolumeMeta) ByName(ctx context.Context, tenant, name string) (*models.Volume, error) {
	return m.store.GetVolume(ctx, tenant, name)
}
func (m sqliteVolumeMeta) List(ctx context.Context, tenant string) ([]models.Volume, error) {
	return m.store.ListVolumes(ctx, tenant)
}
func (m sqliteVolumeMeta) DeleteRow(ctx context.Context, tenant, id string) error {
	// Refused while attached, like the FSM's opDeleteVolume: a sandbox that
	// attached since the caller's count must keep its volume.
	return m.store.DeleteVolumeIfNoAttachments(ctx, tenant, id)
}
func (m sqliteVolumeMeta) DeleteRowOwingBytes(ctx context.Context, vol models.Volume, source string) error {
	// One transaction: the ledger row is written before the volume row goes.
	return m.store.DeleteVolumeIfUnattached(ctx, vol.Tenant, vol.ID, source)
}
func (m sqliteVolumeMeta) ExistsForSource(ctx context.Context, source string) (bool, error) {
	return m.store.LiveVolumeExistsForSource(ctx, source)
}
func (m sqliteVolumeMeta) AttachmentCount(ctx context.Context, tenant, id string) (int, error) {
	return m.store.CountVolumeAttachments(ctx, tenant, id)
}
func (m sqliteVolumeMeta) AttachmentsForSandbox(ctx context.Context, sandboxID string) ([]models.VolumeAttachment, error) {
	return m.store.ListVolumeAttachmentsForSandbox(ctx, sandboxID)
}
func (m sqliteVolumeMeta) PutAttachments(ctx context.Context, attachments []models.VolumeAttachment) error {
	return m.store.PutVolumeAttachments(ctx, attachments)
}
func (m sqliteVolumeMeta) DeleteAttachmentsForSandbox(ctx context.Context, sandboxID, incarnationID string) error {
	return m.store.DeleteVolumeAttachmentsForSandbox(ctx, sandboxID, incarnationID)
}

// clusterVolumeMeta adapts the replicated cluster volume API to the service
// interface, translating cluster.ErrUnknownVolume / ErrVolumeQuotaExceeded into
// the store-level sentinels the service already branches on. store is this
// node's ledger, the fallback while a server predates the replicated one.
type clusterVolumeMeta struct {
	c     cluster.Client
	store *store.Store
}

func (m clusterVolumeMeta) GetOrCreate(ctx context.Context, v *models.Volume, maxPerTenant int) (*models.Volume, bool, error) {
	row, created, err := m.c.VolumeUpsert(ctx, *v, maxPerTenant)
	if err != nil {
		if errors.Is(err, cluster.ErrVolumeQuotaExceeded) {
			return nil, false, store.ErrVolumeQuotaExceeded
		}
		return nil, false, err
	}
	return &row, created, nil
}
func (m clusterVolumeMeta) ByID(ctx context.Context, tenant, id string) (*models.Volume, error) {
	row, err := m.c.VolumeByID(ctx, tenant, id)
	if err != nil {
		return nil, mapVolumeNotFound(err)
	}
	return &row, nil
}
func (m clusterVolumeMeta) ByName(ctx context.Context, tenant, name string) (*models.Volume, error) {
	row, err := m.c.VolumeByName(ctx, tenant, name)
	if err != nil {
		return nil, mapVolumeNotFound(err)
	}
	return &row, nil
}
func (m clusterVolumeMeta) List(ctx context.Context, tenant string) ([]models.Volume, error) {
	return m.c.VolumesForTenant(ctx, tenant)
}
func (m clusterVolumeMeta) DeleteRow(ctx context.Context, tenant, id string) error {
	return mapVolumeNotFound(m.c.VolumeDelete(ctx, tenant, id))
}
func (m clusterVolumeMeta) DeleteRowOwingBytes(ctx context.Context, vol models.Volume, source string) error {
	if rc, ok := m.c.(cluster.VolumeReclaimClient); ok && rc.VolumeReclaimsReplicated() {
		// One apply deletes the row and records the reclaim, which a worker
		// drains even when this node is an ingress or server node (no
		// reclaim sweep) or dies before its next pass.
		return mapVolumeNotFound(rc.VolumeDeleteOwingBytes(ctx, vol.Tenant, vol.ID, source))
	}
	// A server predates the replicated ledger: this node's ledger, as before.
	if err := m.store.SchedulePendingVolumeDeletion(ctx, vol, source); err != nil {
		return err
	}
	return m.DeleteRow(ctx, vol.Tenant, vol.ID)
}
func (m clusterVolumeMeta) ExistsForSource(ctx context.Context, source string) (bool, error) {
	return m.c.VolumeExistsForSource(ctx, source)
}
func (m clusterVolumeMeta) AttachmentCount(ctx context.Context, tenant, id string) (int, error) {
	return m.c.VolumeAttachmentCount(ctx, tenant, id)
}
func (m clusterVolumeMeta) AttachmentsForSandbox(ctx context.Context, sandboxID string) ([]models.VolumeAttachment, error) {
	return m.c.VolumeAttachmentsForSandbox(ctx, sandboxID)
}
func (m clusterVolumeMeta) PutAttachments(ctx context.Context, attachments []models.VolumeAttachment) error {
	if err := m.c.PutVolumeAttachments(ctx, attachments); err != nil {
		return mapVolumeNotFound(err)
	}
	return nil
}
func (m clusterVolumeMeta) DeleteAttachmentsForSandbox(ctx context.Context, sandboxID, incarnationID string) error {
	return m.c.DeleteVolumeAttachmentsForSandbox(ctx, sandboxID, incarnationID)
}

func mapVolumeNotFound(err error) error {
	if errors.Is(err, cluster.ErrUnknownVolume) {
		return store.ErrNotFound
	}
	if errors.Is(err, cluster.ErrVolumeInUse) {
		return store.ErrVolumeInUse
	}
	return err
}
