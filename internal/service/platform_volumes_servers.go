package service

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// A platform volume's row freezes the storage location every node mounts
// and reclaims it at, so in a cluster whose servers sign only a server
// makes one, from its own platform-volume settings and for the caller's
// own account (cluster volume_proposals.go). A worker or gateway sends a
// create that names a platform volume to a server with the caller's own
// credential, as it does the settings writes; the server makes the rows
// the create's volumes need, then sends the create on to its node, which
// finds them made. A create the server runs itself makes its rows as
// before.
//
// Rollback: the rows are made before the create goes on. When the node
// answers the create with an error (a 4xx, or a 5xx such as 500 or 501),
// the server removes the rows that call made, if nothing is attached to
// them yet. When the outcome is unknown (no answer, 502 to 504), they
// stay: a retry finds them, and they are the caller's own, empty, volumes
// under the names it asked for.

// CreateVolumeRowsGoToServers reports whether this worker or gateway sends
// req to a server because it names a platform volume.
func (s *Service) CreateVolumeRowsGoToServers(req models.CreateSandboxRequest) bool {
	return len(req.PlatformVolumes) > 0 && s.SendsOperatorCallsToServers() && s.ServerSigningOn()
}

// IsClusterServer reports whether this node is a cluster server: the
// edge of a call a worker or gateway sent on to it.
func (s *Service) IsClusterServer() bool {
	return s != nil && s.cfg.EnableCluster && s.cfg.IsServer() && s.Cluster() != nil
}

// MakeCreateVolumeRows makes, on a server, the rows req's platform volumes
// need before the create goes to another node, for the caller's account.
// undo removes the rows this call made that nothing is attached to; it is
// nil when there is nothing to make or nothing to undo.
func (s *Service) MakeCreateVolumeRows(ctx context.Context, req models.CreateSandboxRequest) (undo func(), err error) {
	if len(req.PlatformVolumes) == 0 || !s.IsClusterServer() || !s.ServerSigningOn() {
		return nil, nil
	}
	pv := s.cfg.PlatformVolumes
	if !pv.Enabled {
		return nil, models.ErrPlatformVolumesDisabled
	}
	tenant, err := volumes.TenantScope(callerFromContext(ctx, s.cfg.PATToken, s.cfg.OperatorVolumeScope))
	if err != nil {
		return nil, fmt.Errorf("scope platform volume: %w", err)
	}
	var made []models.VolumeAttachment
	defer func() {
		if err != nil {
			s.cleanupCreatedPlatformVolumes(context.WithoutCancel(ctx), made)
		}
	}()
	seen := map[string]bool{}
	for _, ref := range req.PlatformVolumes {
		safeName, err := volumes.SanitizeVolumeName(ref.Name)
		if err != nil {
			return nil, fmt.Errorf("platform volume %q: %w", ref.Name, err)
		}
		if seen[safeName] {
			continue
		}
		seen[safeName] = true
		vol, created, err := s.getOrCreateVolumeRow(ctx, pv, tenant, safeName, ref)
		if err != nil {
			return nil, err
		}
		if created {
			made = append(made, models.VolumeAttachment{Tenant: tenant, VolumeID: vol.ID, CreatedVolume: true})
		}
		if err := volumeRefAgrees(vol, ref); err != nil {
			return nil, err
		}
	}
	if len(made) == 0 {
		return nil, nil
	}
	return func() { s.cleanupCreatedPlatformVolumes(context.WithoutCancel(ctx), made) }, nil
}
