package service

// template_health.go is the Phase 6 PR-A service-layer side of
// snapshot corruption recovery. Two entry points:
//
//   - MarkSnapshotCorrupt is called from two sites: the cold-load
//     intercept inline in createFirecrackerSandbox (when the driver
//     returns an ErrSnapshotCorrupt-wrapping error), and the
//     warm-spawn path via the firecracker.TemplateHealthNotifier
//     interface (which *Service satisfies). Idempotent: many
//     concurrent Creates can hit the same corrupt snapshot in a burst
//     and only the first transitions the row + kicks the rebuild.
//
//   - RebuildTemplateSnapshot reruns the snapshot phase against the
//     existing on-disk rootfs (which is presumed intact — the build
//     succeeded once and only the snapshot artifact corrupted). If
//     the rootfs is *also* corrupt the snapshotter will fail; we then
//     flip to ready_no_snapshot via the existing
//     UpdateTemplateSnapshotFailed path, preserving the cold-boot
//     fallback. Full from-scratch rebuild (rerunning the rootfs
//     phase) is deferred — it needs source-image access and is a
//     larger surface than PR-A wants.
//
// The notifier-interface contract is declared in
// internal/runtime/firecracker/health.go; we don't import that
// package here (cycle), so the method signature is matched
// structurally.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// MarkSnapshotCorrupt transitions a template from ready to unhealthy
// and, on the first such transition for a given corruption event,
// kicks an async snapshot rebuild. Subsequent concurrent calls for
// the same template return nil with no rebuild kicked — the
// idempotent UPDATE ... WHERE status='ready' is the gating primitive.
//
// reason is logged + persisted to the snapshot_error column so the
// operator-facing GET /v1/templates/{id} payload carries the
// human-readable detail.
//
// The method swallows store/rebuild errors after logging — the caller
// (driver.Create's failure path / warm-spawn notifier) is already
// returning its own user-facing error. The notification is a
// best-effort hint to the service layer; failing to honour it leaves
// the system no worse than today (next corruption observation
// retries).
func (s *Service) MarkSnapshotCorrupt(ctx context.Context, templateID, reason string) error {
	if templateID == "" {
		return errors.New("template id is required")
	}
	changed, err := s.store.MarkTemplateUnhealthy(ctx, templateID, reason)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Template was deleted between the corrupt-load and the
			// mark — nothing to rebuild. Treat as no-op success.
			return nil
		}
		s.logger.Warn("mark snapshot corrupt: store update failed",
			"template_id", templateID, "reason", reason, "error", err)
		return err
	}
	if !changed {
		// Concurrent observer already transitioned the row. The
		// rebuild kick is bound to the first observer; we stay out
		// of its way.
		return nil
	}
	s.logger.Warn("snapshot corruption detected; template marked unhealthy, rebuild kicked",
		"template_id", templateID, "reason", reason)
	s.kickSnapshotRebuild(templateID)
	return nil
}

// kickSnapshotRebuild spawns the rebuild goroutine. Detached context
// + bounded timeout match kickTemplateBuild — the rebuild outlives
// the request that triggered it (which has already returned a 500 to
// the user), and a wedged snapshotter cannot pin the goroutine
// forever. The rebuild caller is the single source of "should we
// kick" — MarkSnapshotCorrupt gates this on the row transition
// having actually happened, so concurrent corruption observations
// produce exactly one rebuild.
func (s *Service) kickSnapshotRebuild(templateID string) {
	timeout := s.cfg.FirecrackerTemplateBuildTimeout
	if timeout <= 0 {
		timeout = defaultTemplateBuildTimeout
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := s.RebuildTemplateSnapshot(ctx, templateID); err != nil {
			s.logger.Warn("snapshot rebuild failed",
				"template_id", templateID, "error", err)
		}
	}()
}

// RebuildTemplateSnapshot reruns the snapshot phase against an
// existing rootfs. Synchronous (the caller — typically
// kickSnapshotRebuild — provides its own goroutine + timeout).
// Exported because future phases (snapshot rotation in PR 6-D,
// operator-triggered repair via an API endpoint) will call it
// directly.
//
// Precondition: template must exist and be in status=unhealthy.
// (ready_no_snapshot rebuilds need a different entry point — they
// failed during build and may not have a valid rootfs path; that's
// PR 6-D territory.)
//
// State transitions on success: unhealthy → snapshotting → ready.
// On snapshotter failure: unhealthy → snapshotting → ready_no_snapshot.
// The intermediate snapshotting state is intentional — it matches the
// kickTemplateBuild semantics so operators see a uniform state
// machine on the dashboard.
func (s *Service) RebuildTemplateSnapshot(ctx context.Context, templateID string) error {
	if s.templateSnapshotter == nil || s.templateCIDAllocator == nil {
		return errors.New("snapshot rebuild requires snapshotter + cid allocator wiring")
	}
	template, err := s.store.GetTemplate(ctx, templateID)
	if err != nil {
		return fmt.Errorf("get template: %w", err)
	}
	if template.Status != models.TemplateStatusUnhealthy {
		// Either someone else already recovered the template, or the
		// state machine is in an unexpected place (operator may have
		// manually transitioned). Don't rebuild — would race with
		// whoever is driving the state.
		return fmt.Errorf("template %q is %s, expected unhealthy",
			templateID, template.Status)
	}
	if template.RootfsPath == "" {
		return fmt.Errorf("template %q has no rootfs path; full rebuild required",
			templateID)
	}

	// AllocateForTemplate is idempotent — the synthetic "template:<id>"
	// key returns the same CID that the original build reserved, so
	// the snapshot's vsock device stays consistent across the rebuild.
	cid, err := s.templateCIDAllocator.AllocateForTemplate(ctx, templateID)
	if err != nil {
		// Without a CID the snapshot phase can't run. Mirror the
		// build-time fallback: flip to ready_no_snapshot so cold-boot
		// keeps working until an operator intervenes.
		snapErrMsg := fmt.Sprintf("rebuild: cid allocate: %s", err.Error())
		_ = s.store.UpdateTemplateSnapshotFailed(ctx, templateID, snapErrMsg)
		_ = s.store.UpdateTemplateStatus(ctx, templateID,
			models.TemplateStatusReadyNoSnapshot, template.RootfsPath, "",
			template.RootfsSizeBytes)
		return fmt.Errorf("cid allocate: %w", err)
	}

	dir := filepath.Dir(template.RootfsPath)
	memOut := filepath.Join(dir, snapshotMemoryFilename)
	stateOut := filepath.Join(dir, snapshotStateFilename)

	if uerr := s.store.UpdateTemplateStatus(ctx, templateID,
		models.TemplateStatusSnapshotting, template.RootfsPath, "",
		template.RootfsSizeBytes); uerr != nil {
		s.logger.Warn("snapshot rebuild: status update to snapshotting failed",
			"template_id", templateID, "error", uerr)
	}

	snap, snapErr := s.templateSnapshotter.SnapshotTemplate(ctx, TemplateSnapshotRequest{
		TemplateID:    templateID,
		RootfsPath:    template.RootfsPath,
		OutMemoryPath: memOut,
		OutStatePath:  stateOut,
		GuestCID:      cid,
		MemoryMB:      s.cfg.FirecrackerTemplateMemoryMB,
		VCPU:          s.cfg.FirecrackerTemplateVCPU,
	})
	if snapErr != nil {
		// Snapshot phase failed but rootfs is presumed fine. Release
		// the CID so the next rebuild attempt gets a clean slot,
		// flip to ready_no_snapshot.
		if relErr := s.templateCIDAllocator.ReleaseForTemplate(ctx, templateID); relErr != nil {
			s.logger.Warn("snapshot rebuild: cid release after failure failed",
				"template_id", templateID, "error", relErr)
		}
		if uerr := s.store.UpdateTemplateSnapshotFailed(ctx, templateID, snapErr.Error()); uerr != nil {
			s.logger.Warn("snapshot rebuild: snapshot_error update failed",
				"template_id", templateID, "error", uerr)
		}
		if uerr := s.store.UpdateTemplateStatus(ctx, templateID,
			models.TemplateStatusReadyNoSnapshot, template.RootfsPath, "",
			template.RootfsSizeBytes); uerr != nil {
			s.logger.Warn("snapshot rebuild: status update to ready_no_snapshot failed",
				"template_id", templateID, "error", uerr)
		}
		s.logger.Info("audit snapshot rebuild finished",
			"template_id", templateID,
			"status", models.TemplateStatusReadyNoSnapshot,
			"snapshot_error", snapErr.Error())
		return fmt.Errorf("snapshotter: %w", snapErr)
	}

	snapshotSize := snap.MemorySizeBytes + snap.StateSizeBytes
	if uerr := s.store.UpdateTemplateSnapshotReady(ctx, templateID, memOut, stateOut,
		snapshotSize, snap.Checksum, cid, true); uerr != nil {
		s.logger.Warn("snapshot rebuild: snapshot ready update failed",
			"template_id", templateID, "error", uerr)
		return fmt.Errorf("snapshot ready update: %w", uerr)
	}
	if uerr := s.store.UpdateTemplateStatus(ctx, templateID,
		models.TemplateStatusReady, template.RootfsPath, "",
		template.RootfsSizeBytes); uerr != nil {
		s.logger.Warn("snapshot rebuild: final status update failed",
			"template_id", templateID, "error", uerr)
		return fmt.Errorf("final status update: %w", uerr)
	}
	// Operator-facing manifest is best-effort (matches kickTemplateBuild).
	if mErr := writeTemplateManifest(filepath.Join(dir, templateManifestFilename), templateManifest{
		SourceImage:      template.Image,
		SnapshotChecksum: snap.Checksum,
		VsockCID:         cid,
		CreatedAt:        time.Now().UTC(),
	}); mErr != nil {
		s.logger.Warn("snapshot rebuild: manifest write failed",
			"template_id", templateID, "error", mErr)
	}
	s.logger.Info("audit snapshot rebuild finished",
		"template_id", templateID,
		"status", models.TemplateStatusReady,
		"snapshot_size_bytes", snapshotSize,
		"vsock_cid", cid)
	return nil
}
