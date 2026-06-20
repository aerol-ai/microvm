package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Platform-volume metadata replication on the raft-voter Cluster. Writes go
// through the ordered log (applyCommand handles leader-forward); reads come from
// the local replicated FSM, so any node answers after ownership moves.

// volumeReadbackTimeout bounds how long VolumeUpsert waits for its just-applied
// write to become visible in the local FSM. On the leader the apply is already
// local; on a follower the commit returns before the local Apply, so we poll the
// local FSM briefly to return the canonical row.
const volumeReadbackTimeout = 2 * time.Second

func (c *Cluster) VolumeUpsert(ctx context.Context, v models.Volume, maxPerTenant int) (models.Volume, bool, error) {
	tenant := strings.TrimSpace(v.Tenant)
	name := strings.TrimSpace(v.Name)
	if tenant == "" || name == "" || strings.TrimSpace(v.ID) == "" || strings.TrimSpace(v.Backend) == "" {
		return models.Volume{}, false, fmt.Errorf("cluster: VolumeUpsert requires tenant, name, id, backend")
	}
	// Fast path: already replicated locally → return it (idempotent, no write).
	if existing, err := c.fsm.VolumeByName(tenant, name); err == nil {
		return existing, false, nil
	}
	// Propose the create. The FSM apply is idempotent and enforces quota on the
	// authoritative ordered log, so a racing create for the same name converges
	// rather than inserting a duplicate.
	cmd := command{Op: opUpsertVolume, Volume: &v, MaxPerTenant: maxPerTenant}
	if err := c.applyCommand(ctx, cmd); err != nil {
		if errors.Is(err, ErrVolumeQuotaExceeded) {
			return models.Volume{}, false, ErrVolumeQuotaExceeded
		}
		return models.Volume{}, false, err
	}
	// Read back the canonical row (may be ours, or a pre-existing one a concurrent
	// create won). Poll the local FSM since a follower applies slightly after the
	// commit returns.
	row, err := c.readbackVolume(ctx, tenant, name)
	if err != nil {
		return models.Volume{}, false, err
	}
	return row, row.ID == v.ID, nil
}

func (c *Cluster) readbackVolume(ctx context.Context, tenant, name string) (models.Volume, error) {
	deadline := time.Now().Add(volumeReadbackTimeout)
	for {
		if row, err := c.fsm.VolumeByName(tenant, name); err == nil {
			return row, nil
		}
		if time.Now().After(deadline) {
			return models.Volume{}, fmt.Errorf("cluster: volume %q/%q not visible after apply: %w", tenant, name, ErrUnknownVolume)
		}
		select {
		case <-ctx.Done():
			return models.Volume{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (c *Cluster) VolumeDelete(ctx context.Context, tenant, id string) error {
	tenant = strings.TrimSpace(tenant)
	id = strings.TrimSpace(id)
	if tenant == "" || id == "" {
		return fmt.Errorf("cluster: VolumeDelete requires tenant and id")
	}
	err := c.applyCommand(ctx, command{Op: opDeleteVolume, VolumeTenant: tenant, VolumeID: id})
	if errors.Is(err, ErrUnknownVolume) {
		return ErrUnknownVolume
	}
	return err
}

func (c *Cluster) VolumeByID(_ context.Context, tenant, id string) (models.Volume, error) {
	return c.fsm.VolumeByID(tenant, id)
}

func (c *Cluster) VolumeByName(_ context.Context, tenant, name string) (models.Volume, error) {
	return c.fsm.VolumeByName(tenant, name)
}

func (c *Cluster) VolumesForTenant(_ context.Context, tenant string) ([]models.Volume, error) {
	return c.fsm.VolumesForTenant(tenant), nil
}

func (c *Cluster) VolumeExistsForSource(_ context.Context, source string) (bool, error) {
	return c.fsm.LiveVolumeExistsForSource(source), nil
}

func (c *Cluster) VolumeAttachmentCount(_ context.Context, tenant, id string) (int, error) {
	return c.fsm.VolumeAttachmentCount(tenant, id), nil
}

func (c *Cluster) PutVolumeAttachments(ctx context.Context, attachments []models.VolumeAttachment) error {
	if len(attachments) == 0 {
		return nil
	}
	err := c.applyCommand(ctx, command{Op: opPutVolumeAttach, VolumeAttachments: attachments})
	if errors.Is(err, ErrUnknownVolume) {
		return ErrUnknownVolume
	}
	return err
}

func (c *Cluster) DeleteVolumeAttachmentsForSandbox(ctx context.Context, sandboxID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil
	}
	return c.applyCommand(ctx, command{Op: opDeleteVolumeAttach, VolumeSandboxID: sandboxID})
}
