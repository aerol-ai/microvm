package service

import (
	"context"
	"expvar"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// diskLimitSlack lets a sandbox run a little past its DiskGB before the
// watchdog stops it, so one that sits right at its size does not flap.
const diskLimitSlack = 1.05

// diskLimitStops counts sandboxes the watchdog stopped
// (aerolvm_sandbox_disk_limit_stops_total).
var diskLimitStops = expvar.NewInt("aerolvm_sandbox_disk_limit_stops_total")

// StartDiskLimitWatch runs the disk watchdog every
// SB_DISK_LIMIT_CHECK_INTERVAL; zero leaves it off.
func (s *Service) StartDiskLimitWatch(ctx context.Context) {
	if s == nil || s.cfg.DiskLimitCheckInterval <= 0 {
		return
	}
	s.startPeriodic(withAuditSubsystem(ctx, auditSubsystemLifecycle), s.cfg.DiskLimitCheckInterval, 2*time.Minute, s.runDiskLimitWatch)
}

// runDiskLimitWatch stops every running container sandbox on this node that
// has written more than its DiskGB to its writable layer. A stop (not a
// destroy) keeps the tenant's data and stops the growth; the sandbox's
// last error says why. Firecracker disks are fixed-size images and the
// WASM and isolate runtimes have no writable layer, so they are skipped.
func (s *Service) runDiskLimitWatch(ctx context.Context) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("disk watchdog: list sandboxes", "error", err)
		return
	}
	for _, sb := range sandboxes {
		if sb.Status != models.SandboxStatusStarted || sb.DiskGB <= 0 || sb.ContainerID == "" ||
			s.isFirecrackerSandbox(sb) || s.isWasmSandbox(sb) || s.isIsolateSandbox(sb) {
			continue
		}
		rt, err := s.ociEngineForSandbox(sb)
		if err != nil {
			continue
		}
		sizer, ok := rt.(runtime.WritableLayerSizer)
		if !ok {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		used, err := sizer.WritableLayerBytes(cctx, sb.ContainerID)
		cancel()
		if err != nil {
			s.logger.Debug("disk watchdog: size not read", "sandbox_id", sb.ID, "error", err)
			continue
		}
		if used <= int64(float64(sb.DiskGB)*diskLimitSlack*float64(1<<30)) {
			continue
		}
		s.stopForDiskLimit(ctx, sb, used)
	}
}

func (s *Service) stopForDiskLimit(ctx context.Context, sb *models.Sandbox, used int64) {
	msg := fmt.Sprintf("stopped: wrote %.1f GiB to its disk, over its %d GiB", float64(used)/float64(1<<30), sb.DiskGB)
	done := s.beginSystemAction(ctx, sb.ID, systemActionDiskStop)
	// Manual: never armed for wake, so traffic does not restart a sandbox
	// that is over its disk.
	_, err := s.stopSandboxInternal(ctx, sb.ID, stopModeManual)
	done(err)
	if err != nil {
		s.logger.Warn("disk watchdog: stop failed", "sandbox_id", sb.ID, "used_bytes", used, "disk_gb", sb.DiskGB, "error", err)
		return
	}
	diskLimitStops.Add(1)
	if uerr := s.store.UpdateStatus(ctx, sb.ID, models.SandboxStatusStopped, msg); uerr != nil {
		s.logger.Warn("disk watchdog: reason not recorded", "sandbox_id", sb.ID, "error", uerr)
	}
	s.logger.Warn("disk watchdog: sandbox stopped over its disk size", "sandbox_id", sb.ID, "used_bytes", used, "disk_gb", sb.DiskGB)
}
