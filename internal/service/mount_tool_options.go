package service

import (
	"context"
	"fmt"
	"slices"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Every path that runs a sandbox's mount tools passes the mount-tool allow
// lists (models.MountSpec.ValidateToolOptions) first:
//
//	create, WASM create, failover rebuild   validateCreateMounts
//	start, passivated WASM start            reestablishMounts
//	boot reconcile, WASM adopt              reestablishMounts
//
// A spec stored before the lists existed is refused on start or restart,
// not run once more: a refused flag is only harmless if it never runs.

// checkCallerMountTools holds the caller's mounts in specs to the allow
// lists. A platform volume's mount is not the caller's: it is built from
// this node's configuration, which daemon start checks
// (config.PlatformVolumesConfig.Validate), and a stored one may carry
// options the operator configured before that check existed, which the
// caller cannot fix. So a mount that fails the lists passes when it is one
// of the sandbox's platform volumes: one that platform (the attachments a
// create just made) or the sandbox's stored attachments name, by source and
// target. A caller cannot write an attachment, and no two mounts of one
// sandbox share a target. The stored attachments are read only then, so a
// sandbox whose mounts all pass reads nothing.
func (s *Service) checkCallerMountTools(ctx context.Context, sandboxID string, specs []models.MountSpec, platform []models.VolumeAttachment) error {
	read := false
	for i := range specs {
		err := specs[i].ValidateToolOptions()
		if err == nil {
			continue
		}
		if !read && sandboxID != "" && (s.testVolumeMeta != nil || s.store != nil) {
			stored, readErr := s.volumeMeta().AttachmentsForSandbox(ctx, sandboxID)
			if readErr != nil {
				// Not knowing whether it is a platform volume, refuse it.
				return fmt.Errorf("mount %d: %w (and the sandbox's platform volume records could not be read: %v)", i, err, readErr)
			}
			platform = append(slices.Clone(platform), stored...)
			read = true
		}
		if isPlatformMount(specs[i], platform) {
			continue
		}
		return fmt.Errorf("mount %d: %w", i, err)
	}
	return nil
}

func isPlatformMount(m models.MountSpec, platform []models.VolumeAttachment) bool {
	return slices.ContainsFunc(platform, func(a models.VolumeAttachment) bool {
		return a.Source == m.Source && a.Target == m.Target
	})
}

// reestablishMounts runs sandbox id's stored mounts again (start, boot
// reconcile, WASM adopt), after the allow lists. A refused spec mounts
// nothing, and whatever a previous sandboxd left serving it, such as a
// helper still running a flag the lists now refuse, is torn down: the
// caller gets the refusal naming the mount and the flag, and recreating
// the sandbox without the flag is the way back.
func (s *Service) reestablishMounts(ctx context.Context, id string, specs []models.MountSpec) error {
	if err := s.checkCallerMountTools(ctx, id, specs, nil); err != nil {
		s.mounts.Discard(id)
		return err
	}
	return s.mounts.Reestablish(ctx, id, specs)
}
