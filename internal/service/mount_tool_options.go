package service

import (
	"context"
	"expvar"
	"fmt"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Every path that runs a sandbox's mount tools passes the mount-tool allow
// lists (models.MountSpec.ValidateToolOptions) first:
//
//	create, WASM create, failover rebuild   validateCreateMounts
//	start, passivated WASM start            reestablishMounts
//	boot reconcile, WASM adopt              reestablishRunningMounts
//
// A spec stored before the lists existed never runs again: a refused flag
// is only harmless if it never runs. Its sandbox's next start is refused,
// naming the mount and the flag. A sandbox still running across the
// restart keeps a mount whose refused flags do no harm while the tool runs
// until then; one whose flags do is torn down (reestablishRunningMounts).

// mountsRefusedRunning counts the running sandboxes a restart found with
// stored mounts the allow lists refuse, by what was done: "kept" (they run
// on as they were until the sandbox's next start, which is refused) or
// "removed" (torn down: the running tool reached into the server). Each
// one also gets a log line and a system action record naming the sandbox
// and the refused options, so an operator can find them before they stop.
var mountsRefusedRunning = expvar.NewMap("aerolvm_mounts_refused_running_total")

// runningMountSet is what reestablishRunningMounts and the WASM adopt need
// of the mount manager. Tests stand in a fake (Service.testRunningMounts).
type runningMountSet interface {
	Reestablish(ctx context.Context, sandboxID string, specs []models.MountSpec) error
	KeepLive(ctx context.Context, sandboxID string, specs []models.MountSpec) (mounts.KeepReport, error)
	Discard(sandboxID string) bool
	HostBindsFor(sandboxID string) []mounts.ContainerBind
}

func (s *Service) runningMounts() runningMountSet {
	if s.testRunningMounts != nil {
		return s.testRunningMounts
	}
	return s.mounts
}

// checkCallerMountTools holds the caller's mounts in specs to the allow
// lists. A platform volume's mount is not the caller's: it is built from
// this node's configuration, which daemon start checks
// (config.PlatformVolumesConfig.Validate), and a stored one may carry
// options the operator configured before that check existed, which the
// caller cannot fix. So a mount that fails the lists passes when it is one
// of the sandbox's platform volumes (platformMountTest).
func (s *Service) checkCallerMountTools(ctx context.Context, sandboxID string, specs []models.MountSpec, platform []models.VolumeAttachment) error {
	isPlatform := s.platformMountTest(ctx, sandboxID, platform)
	for i := range specs {
		err := specs[i].ValidateToolOptions()
		if err == nil {
			continue
		}
		ok, readErr := isPlatform(specs[i])
		if readErr != nil {
			// Not knowing whether it is a platform volume, refuse it.
			return fmt.Errorf("mount %d: %w (and the sandbox's platform volume records could not be read: %v)", i, err, readErr)
		}
		if !ok {
			return fmt.Errorf("mount %d: %w", i, err)
		}
	}
	return nil
}

// platformMountTest returns a test for "is this mount one of sandboxID's
// platform volumes": one that platform (the attachments a create just
// made) or the sandbox's stored attachments name, by source and target. A
// caller cannot write an attachment, and no two mounts of one sandbox
// share a target. The stored attachments are read at most once, and only
// when asked, so a sandbox whose mounts all pass the lists reads nothing.
func (s *Service) platformMountTest(ctx context.Context, sandboxID string, platform []models.VolumeAttachment) func(models.MountSpec) (bool, error) {
	read := false
	return func(m models.MountSpec) (bool, error) {
		if !read && sandboxID != "" && (s.testVolumeMeta != nil || s.store != nil) {
			stored, err := s.volumeMeta().AttachmentsForSandbox(ctx, sandboxID)
			if err != nil {
				return false, err
			}
			platform = append(slices.Clone(platform), stored...)
			read = true
		}
		return isPlatformMount(m, platform), nil
	}
}

func isPlatformMount(m models.MountSpec, platform []models.VolumeAttachment) bool {
	return slices.ContainsFunc(platform, func(a models.VolumeAttachment) bool {
		return a.Source == m.Source && a.Target == m.Target
	})
}

// reestablishMounts runs sandbox id's stored mounts again on a start, after
// the allow lists. A refused spec mounts nothing, and whatever a previous
// sandboxd left serving it, such as a helper still running a flag the
// lists now refuse (kept by reestablishRunningMounts while the sandbox
// ran), is torn down: the caller gets the refusal naming the mount and the
// flag, and recreating the sandbox without the flag is the way back.
func (s *Service) reestablishMounts(ctx context.Context, id string, specs []models.MountSpec) error {
	if err := s.checkCallerMountTools(ctx, id, specs, nil); err != nil {
		s.mounts.Discard(id)
		return err
	}
	return s.mounts.Reestablish(ctx, id, specs)
}

// reestablishRunningMounts is reestablishMounts for a sandbox still running
// across a sandboxd restart: the boot reconcile (and every later pass) and
// the WASM adopt. Specs the lists accept are reestablished as before. A
// refused one is already running in the tool a previous sandboxd left:
// tearing it down breaks the sandbox's storage without notice and stops
// nothing that matters, and mounting it afresh would run the refused flag
// again. So:
//
//   - when every refused flag does no harm while the tool goes on running
//     (models.MountSpec.ValidateRunningToolOptions: an S3 cache folder or
//     log level, NFS defaults, bg or fsc), the live mounts are kept as they
//     run and nothing is started (mounts.Manager.KeepLive). The sandbox's
//     next start is refused (reestablishMounts).
//   - otherwise the running tool itself keeps reaching into the server (a
//     folder it serves or writes, a command it runs again, the server's
//     credentials), so the mounts are torn down and the sandbox runs on
//     without them. A WASM sandbox is then left to reconcile, as before,
//     rather than run with its mount paths unbacked.
//
// Either way it is logged, counted (mountsRefusedRunning) and recorded as
// a system action naming the sandbox and every refused option, once per
// sandboxd. When a refused mount may be a platform volume but the records
// that say so cannot be read, nothing is touched: the next pass decides.
func (s *Service) reestablishRunningMounts(ctx context.Context, id string, specs []models.MountSpec) error {
	refused, unsafe, err := s.runningMountRefusals(ctx, id, specs)
	if err != nil {
		return err
	}
	set := s.runningMounts()
	if len(refused) == 0 {
		return set.Reestablish(ctx, id, specs)
	}
	reason := strings.Join(refused, "; ")
	if len(unsafe) > 0 {
		if !set.Discard(id) {
			return nil // nothing left to tear down: an earlier pass did
		}
		removed := strings.Join(unsafe, "; ")
		mountsRefusedRunning.Add("removed", 1)
		s.logger.Warn("mounts: tore down a running sandbox's mounts: their stored options are refused, and the running mount tool would keep reaching into this server; the sandbox runs on without them, and its next start is refused",
			"sandbox_id", id, "refused", reason, "unsafe_while_running", removed)
		s.beginSystemActionReason(ctx, id, systemActionMountsRefusedRemoved, reason)(nil)
		return fmt.Errorf("stored mounts refused and torn down: %s", removed)
	}
	report, err := set.KeepLive(ctx, id, specs)
	if err != nil {
		return err
	}
	if report.Already {
		return nil
	}
	mountsRefusedRunning.Add("kept", 1)
	s.logger.Warn("mounts: kept a running sandbox's mounts as they run, though their stored options are now refused; nothing is mounted or restarted for them, and the sandbox's next start is refused until it is recreated without those options",
		"sandbox_id", id, "refused", reason, "kept", report.Kept, "not_running", report.Gone)
	s.beginSystemActionReason(ctx, id, systemActionMountsRefusedKept, reason)(nil)
	return nil
}

// runningMountRefusals lists the caller mounts in specs that the allow
// lists refuse (refused), and of those the ones a running mount may not
// keep either (unsafe), each naming the mount and its first such flag.
// Platform volumes' mounts are skipped as checkCallerMountTools skips
// them; err is set when one fails the lists and the sandbox's platform
// volume records cannot be read.
func (s *Service) runningMountRefusals(ctx context.Context, id string, specs []models.MountSpec) (refused, unsafe []string, err error) {
	isPlatform := s.platformMountTest(ctx, id, nil)
	for i := range specs {
		listErr := specs[i].ValidateToolOptions()
		if listErr == nil {
			continue
		}
		ok, readErr := isPlatform(specs[i])
		if readErr != nil {
			return nil, nil, fmt.Errorf("mount %d: %w (and the sandbox's platform volume records could not be read: %v)", i, listErr, readErr)
		}
		if ok {
			continue
		}
		refused = append(refused, fmt.Sprintf("mount %d: %v", i, listErr))
		if runErr := specs[i].ValidateRunningToolOptions(); runErr != nil {
			unsafe = append(unsafe, fmt.Sprintf("mount %d: %v", i, runErr))
		}
	}
	return refused, unsafe, nil
}
