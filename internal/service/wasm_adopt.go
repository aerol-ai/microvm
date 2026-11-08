package service

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// wasmAdopter is the WASM driver's boot surface (internal/runtime/wasm,
// adopt.go): take over an instance whose worker outlived the previous
// sandboxd, or bring back one whose worker did not.
type wasmAdopter interface {
	AdoptSandbox(ctx context.Context, sb *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error)
	RestoreSandbox(ctx context.Context, sb *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error)
	HasWorkDir(sandboxID string) bool
	FinishAdoption() int
}

// wasmShutdownKeeper says which instances the shutdown drain must leave
// running (adopt.go, KeepOnShutdown).
type wasmShutdownKeeper interface {
	KeepOnShutdown(sandboxID string) bool
}

// wasmAdoptParallelism bounds the boot pass. Taking over a live instance is
// one local RPC; restoring one is an instantiate (a compile per module,
// usually a compile-cache hit, the first time).
const wasmAdoptParallelism = 8

// WasmAdoptReport counts what AdoptWasmSandboxes did with the started WASM
// rows at boot.
type WasmAdoptReport struct {
	Adopted  int // the instance outlived the previous sandboxd and was taken over
	Restored int // its worker was gone; a new instance runs over the kept /work
	Lost     int // nothing to take over or restore (a reboot): left stopped or passivated
}

// AdoptWasmSandboxes keeps every started WASM sandbox running across a
// sandboxd restart. Call it once at boot, after the driver adopted the
// workers' cgroup (AdoptWorkers) and before the first reconcile, which
// would otherwise mark every one of them stopped ("ephemeral wasm lost on
// daemon restart") or reap it.
//
// For each started row: take over its live instance; else, when its /work
// is still there (a restart, not a reboot), restore it over that work dir;
// else it is lost, and the row says so instead of being reaped. Mounts are
// re-established first, which adopts their helpers, so the instance sees
// the same binds it had.
func (s *Service) AdoptWasmSandboxes(ctx context.Context) WasmAdoptReport {
	var report WasmAdoptReport
	if s.wasm == nil || !s.cfg.EnableWasm {
		return report
	}
	adopter, ok := s.wasm.(wasmAdopter)
	if !ok {
		return report
	}
	defer adopter.FinishAdoption()
	known, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("wasm adopt: cannot list sandboxes; running WASM sandboxes are left to reconcile", "error", err)
		return report
	}
	var mu sync.Mutex
	jobs := make(chan *models.Sandbox)
	var wg sync.WaitGroup
	for i := 0; i < wasmAdoptParallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sb := range jobs {
				outcome := s.adoptWasmSandbox(ctx, adopter, sb)
				mu.Lock()
				switch outcome {
				case wasmAdopted:
					report.Adopted++
				case wasmRestored:
					report.Restored++
				case wasmLost:
					report.Lost++
				}
				mu.Unlock()
			}
		}()
	}
	for _, sb := range known {
		if sb == nil || !s.isWasmSandbox(sb) {
			continue
		}
		// passivate_failed is a sandbox an older sandboxd's shutdown drain
		// tried and failed to save (a resident host serves no checkpoint):
		// its /work is still there after a restart, so it is restored too.
		switch sb.Status {
		case models.SandboxStatusStarted, models.SandboxStatusCreating, models.SandboxStatusPassivateFailed:
			jobs <- sb
		}
	}
	close(jobs)
	wg.Wait()
	if report != (WasmAdoptReport{}) {
		s.logger.Info("wasm adopt: running WASM sandboxes after the restart",
			"adopted", report.Adopted, "restored", report.Restored, "lost", report.Lost)
	}
	return report
}

type wasmAdoptOutcome int

const (
	wasmSkipped wasmAdoptOutcome = iota
	wasmAdopted
	wasmRestored
	wasmLost
)

func (s *Service) adoptWasmSandbox(ctx context.Context, adopter wasmAdopter, sb *models.Sandbox) wasmAdoptOutcome {
	env, err := s.loadEnv(ctx, sb.ID, sb.AuditIncarnationID)
	if err != nil {
		// Without its env an exec would run stripped of its credentials.
		// Reconcile handles the row as before.
		s.logger.Warn("wasm adopt: env not readable; sandbox left to reconcile", "sandbox_id", sb.ID, "error", err)
		return wasmSkipped
	}
	sb.Env = env
	var binds []mounts.ContainerBind
	if specs, err := s.loadMounts(ctx, sb.ID); err != nil {
		s.logger.Warn("wasm adopt: mounts not readable; sandbox left to reconcile", "sandbox_id", sb.ID, "error", err)
		return wasmSkipped
	} else if len(specs) > 0 && s.mounts != nil {
		if err := s.mounts.Reestablish(ctx, sb.ID, specs); err != nil {
			s.logger.Warn("wasm adopt: mounts not re-established; sandbox left to reconcile", "sandbox_id", sb.ID, "error", err)
			return wasmSkipped
		}
		binds = s.mounts.HostBindsFor(sb.ID)
	}
	if _, err := adopter.AdoptSandbox(ctx, sb, binds); err == nil {
		s.markWasmRunning(ctx, sb)
		return wasmAdopted
	}
	if adopter.HasWorkDir(sb.ID) {
		if err := s.restoreWasmSandbox(ctx, adopter, sb, binds); err == nil {
			s.logger.Info("wasm adopt: sandbox restored over its kept work dir", "sandbox_id", sb.ID)
			s.markWasmRunning(ctx, sb)
			return wasmRestored
		} else {
			s.logger.Warn("wasm adopt: restore failed", "sandbox_id", sb.ID, "error", err)
		}
	}
	s.markWasmLost(ctx, sb)
	return wasmLost
}

func (s *Service) restoreWasmSandbox(ctx context.Context, adopter wasmAdopter, sb *models.Sandbox, binds []mounts.ContainerBind) error {
	// A private oci:// module may need the tenant's registry identity to
	// pull again on this node (codex C4).
	if err := s.attachWasmRegistryAuth(ctx, sb); err != nil {
		return err
	}
	_, err := adopter.RestoreSandbox(ctx, sb, binds)
	return err
}

// markWasmRunning records a sandbox brought back from passivate_failed as
// started again; a started row is already right.
func (s *Service) markWasmRunning(ctx context.Context, sb *models.Sandbox) {
	if sb.Status == models.SandboxStatusStarted {
		return
	}
	if err := s.store.UpdateWasmCheckpoint(ctx, sb.ID, sb.AuditIncarnationID,
		string(models.SandboxStatusStarted), sb.CheckpointPath, sb.CloneGeneration, ""); err != nil {
		s.logger.Warn("wasm adopt: restored sandbox not marked started", "sandbox_id", sb.ID, "error", err)
	}
}

// markWasmLost records a started sandbox nothing could keep (a reboot took
// its worker and its /work). A passivatable or durable one with a local
// checkpoint becomes passivated, so its next start restores it; anything
// else is stopped, with the reason. Never reaped: before, reconcile deleted
// a passivatable row it found this way.
func (s *Service) markWasmLost(ctx context.Context, sb *models.Sandbox) {
	if s.admitter != nil {
		s.admitter.Release(sb.ID)
	}
	if wasmShouldCheckpoint(sb.Durability) {
		if path := strings.TrimSpace(sb.CheckpointPath); path != "" {
			if st, err := os.Stat(path); err == nil && st.IsDir() {
				if err := s.store.UpdateWasmCheckpoint(ctx, sb.ID, sb.AuditIncarnationID,
					string(models.SandboxStatusPassivated), path, sb.CloneGeneration, ""); err != nil {
					s.logger.Warn("wasm adopt: lost sandbox not marked passivated", "sandbox_id", sb.ID, "error", err)
				}
				return
			}
		}
	}
	done := s.beginSystemActionReason(ctx, sb.ID, systemActionFoundStopped, models.StatusReasonReconcile)
	recordSandboxStop(models.StatusReasonReconcile)
	done(s.store.UpdateStatusWithReason(ctx, sb.ID, models.SandboxStatusStopped,
		"wasm worker and work dir gone after a sandboxd restart (host reboot?)", models.StatusReasonReconcile, nil))
}
