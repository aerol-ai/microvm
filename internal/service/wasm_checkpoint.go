package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/observability"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"go.opentelemetry.io/otel/attribute"
)

const defaultWasmCheckpointMaxParallel = 64

// DrainWasmSandboxes checkpoints passivatable/durable live WASM sandboxes during
// graceful shutdown (plans/wasm-runtime.md §4.3).
func (s *Service) DrainWasmSandboxes(ctx context.Context) error {
	if s.wasm == nil || !s.cfg.EnableWasm {
		return nil
	}
	host, ok := s.wasm.(wasmruntime.CheckpointHost)
	if !ok {
		return nil
	}

	known, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("drain wasm: list sandboxes: %w", err)
	}
	managed, err := s.wasm.ListManaged(ctx)
	if err != nil {
		return fmt.Errorf("drain wasm: list managed: %w", err)
	}

	eligible := make([]*models.Sandbox, 0, len(known))
	for _, sb := range known {
		if sb == nil || !s.isWasmSandbox(sb) {
			continue
		}
		if sb.Status != models.SandboxStatusStarted && sb.Status != models.SandboxStatusCreating {
			continue
		}
		if !wasmShouldCheckpoint(sb.Durability) {
			continue
		}
		if _, live := managed[sb.ID]; !live {
			continue
		}
		eligible = append(eligible, sb)
	}
	return s.runWasmCheckpointPool(ctx, eligible, func(sandbox *models.Sandbox) error {
		return s.checkpointWasmSandbox(ctx, host, sandbox)
	})
}

func wasmShouldCheckpoint(durability string) bool {
	switch durability {
	case models.DurabilityPassivatable, models.DurabilityDurable:
		return true
	default:
		return false
	}
}

func (s *Service) checkpointWasmSandbox(ctx context.Context, host wasmruntime.CheckpointHost, sandbox *models.Sandbox) (err error) {
	ctx, span := observability.StartSpan(ctx, "wasm.checkpoint",
		attribute.String("sandbox.id", sandbox.ID),
		attribute.String("durability", sandbox.Durability),
	)
	defer func() { observability.EndSpan(span, err) }()

	path, gen, err := host.CheckpointSandbox(ctx, sandbox)
	if err != nil {
		s.logger.Error("wasm drain checkpoint failed",
			"sandbox_id", sandbox.ID,
			"durability", sandbox.Durability,
			"error", err,
		)
		_ = s.store.UpdateWasmCheckpoint(ctx, sandbox.ID, sandbox.AuditIncarnationID,
			string(models.SandboxStatusPassivateFailed), "", sandbox.CloneGeneration, err.Error())
		if s.admitter != nil {
			s.admitter.Release(sandbox.ID)
		}
		return nil
	}
	if err := s.store.UpdateWasmCheckpoint(ctx, sandbox.ID, sandbox.AuditIncarnationID,
		string(models.SandboxStatusPassivated), path, gen, ""); err != nil {
		return err
	}
	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}
	s.logger.Info("wasm sandbox passivated",
		"sandbox_id", sandbox.ID,
		"checkpoint", path,
		slog.String("clone_generation", gen),
	)
	if sandbox.Durability == models.DurabilityDurable && s.wasmCheckpointPusher != nil {
		go s.pushWasmCheckpointBestEffort(sandbox.ID, sandbox.AuditIncarnationID, path)
	}
	return nil
}

func (s *Service) checkpointLiveWasmSandbox(ctx context.Context, host wasmruntime.LiveCheckpointHost, sandbox *models.Sandbox) (err error) {
	ctx, span := observability.StartSpan(ctx, "wasm.checkpoint.live",
		attribute.String("sandbox.id", sandbox.ID),
		attribute.String("durability", sandbox.Durability),
	)
	defer func() { observability.EndSpan(span, err) }()

	path, gen, err := host.CheckpointLiveSandbox(ctx, sandbox)
	if err != nil {
		s.logger.Warn("wasm live checkpoint failed",
			"sandbox_id", sandbox.ID,
			"durability", sandbox.Durability,
			"error", err,
		)
		return nil
	}
	if err := s.store.UpdateWasmCheckpoint(ctx, sandbox.ID, sandbox.AuditIncarnationID,
		string(models.SandboxStatusStarted), path, gen, ""); err != nil {
		return err
	}
	s.logger.Info("wasm live checkpoint written",
		"sandbox_id", sandbox.ID,
		"checkpoint", path,
		slog.String("clone_generation", gen),
	)
	if sandbox.Durability == models.DurabilityDurable && s.wasmCheckpointPusher != nil {
		go s.pushWasmCheckpointBestEffort(sandbox.ID, sandbox.AuditIncarnationID, path)
	}
	return nil
}

func (s *Service) runWasmCheckpointPool(ctx context.Context, sandboxes []*models.Sandbox, fn func(*models.Sandbox) error) error {
	if len(sandboxes) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parallelism := s.wasmCheckpointParallelism()
	if parallelism > len(sandboxes) {
		parallelism = len(sandboxes)
	}
	jobs := make(chan *models.Sandbox)
	errCh := make(chan error, len(sandboxes))
	var wg sync.WaitGroup
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sandbox := range jobs {
				if err := fn(sandbox); err != nil {
					errCh <- err
				}
			}
		}()
	}
	for _, sandbox := range sandboxes {
		select {
		case jobs <- sandbox:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	close(errCh)
	if err := ctx.Err(); err != nil {
		return err
	}
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) wasmCheckpointParallelism() int {
	if s == nil || s.cfg.WasmCheckpointMaxParallel <= 0 {
		return defaultWasmCheckpointMaxParallel
	}
	return s.cfg.WasmCheckpointMaxParallel
}

// pushWasmCheckpointBestEffort ships a checkpoint to AOCR detached from the
// request that produced it. incarnationID is the lifecycle it belongs to: the
// push holds a 5-minute budget, so the sandbox can be destroyed and its id
// re-created before the result lands, and an unfenced write would then hand a
// fresh sandbox the previous incarnation's memory image.
func (s *Service) pushWasmCheckpointBestEffort(sandboxID, incarnationID, memSnapDir string) {
	incarnationID = strings.TrimSpace(incarnationID)
	if incarnationID == "" {
		// Without a lifetime there is nothing to bind the artifact to, and an
		// unbound checkpoint could later be restored into a different lifetime
		// of this sandbox id.
		s.logger.Warn("wasm checkpoint AOCR push skipped: sandbox has no lifetime (incarnation) to bind it to",
			"sandbox_id", sandboxID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Both refs are scoped to THIS lifetime. Every push used to write the
	// id-wide :latest first, and the incarnation fence only ran afterwards on
	// SQLite — which cannot undo a registry write. A destroyed lifetime's late
	// push then re-pointed the tag a failover owner restores from, and orphan
	// GC deleting that lifetime's manifest took the live alias with it.
	dest := s.wasmCheckpointLatestRef(sandboxID, incarnationID)
	result, err := s.wasmCheckpointPusher.PushOnceTo(ctx, sandboxID, incarnationID, memSnapDir, dest)
	if err != nil {
		s.logger.Warn("wasm checkpoint AOCR push failed",
			"sandbox_id", sandboxID,
			"error", err,
		)
		return
	}
	if strings.TrimSpace(result.Digest) != "" {
		if taggedDest := s.wasmCheckpointDigestRef(sandboxID, incarnationID, result.Digest); taggedDest != "" && taggedDest != dest {
			if _, tagErr := s.wasmCheckpointPusher.PushOnceTo(ctx, sandboxID, incarnationID, memSnapDir, taggedDest); tagErr != nil {
				// The row falls back to this lifetime's rolling pointer, which
				// no other lifetime can move.
				s.logger.Warn("wasm checkpoint digest-tagged AOCR push failed",
					"sandbox_id", sandboxID,
					"ref", taggedDest,
					"error", tagErr,
				)
			} else {
				result.RegistryRef = taggedDest
			}
		}
	}
	applied, err := s.store.UpdateWasmRegistryPush(ctx, sandboxID, incarnationID, result.RegistryRef, result.Digest)
	if err != nil {
		s.logger.Warn("wasm checkpoint AOCR push metadata persist failed",
			"sandbox_id", sandboxID,
			"error", err,
		)
	}
	if !applied {
		// The lifecycle this push belonged to is gone. Recording the ref under
		// the live row would point a different sandbox at it; the ref is still
		// journalled below, under the DEAD incarnation, so the orphan sweep
		// can reclaim the pushed artifact.
		s.logger.Warn("wasm checkpoint AOCR push landed after its lifecycle ended",
			"sandbox_id", sandboxID,
			"incarnation_id", incarnationID,
			"registry_ref", result.RegistryRef,
		)
	}
	if _, err := s.store.InsertWasmCheckpointPush(ctx, sandboxID, incarnationID, result.RegistryRef, result.Digest); err != nil {
		s.logger.Warn("wasm checkpoint push history persist failed",
			"sandbox_id", sandboxID,
			"error", err,
		)
	}
	if !applied {
		// A rejected push is a cleanup obligation for the orphan sweep, not a
		// retention event: it must not spend the live lifetime's keep-last-N
		// budget, which is how late pushes from a destroyed incarnation used
		// to push the replacement's valid checkpoint out and delete it.
		return
	}
	s.pruneWasmCheckpointPushes(ctx, sandboxID, incarnationID)
}

// pruneWasmCheckpointPushes applies keep-last-N to ONE lifetime's checkpoints.
func (s *Service) pruneWasmCheckpointPushes(ctx context.Context, sandboxID, incarnationID string) {
	keep := s.cfg.WasmCheckpointKeepLastN
	if keep <= 0 {
		return
	}
	recs, err := s.store.ListWasmCheckpointPushesForIncarnation(ctx, sandboxID, incarnationID)
	if err != nil {
		s.logger.Warn("wasm checkpoint push history list failed",
			"sandbox_id", sandboxID,
			"error", err,
		)
		return
	}
	for i := keep; i < len(recs); i++ {
		s.reclaimWasmCheckpointPush(ctx, recs[i], "retention")
	}
}

// reclaimWasmCheckpointPush retires one history row: it deletes the pushed
// manifest and then the row — unless the manifest is still in use by the live
// sandbox, in which case only the row goes and the live lifetime keeps owning
// the artifact. Both retention and the orphan sweep go through here, so neither
// can delete what the other must keep.
//
// No-vacuum rule: the row is the only record tying the sandbox to its manifest,
// so a failed delete keeps the row for the next sweep.
func (s *Service) reclaimWasmCheckpointPush(ctx context.Context, rec store.WasmCheckpointPushRecord, reason string) {
	ref := strings.TrimSpace(rec.RegistryRef)
	if ref != "" && s.wasmCheckpointPusher != nil {
		inUse, err := s.store.WasmCheckpointRefInUse(ctx, rec.SandboxID, rec.ID, rec.IncarnationID, ref, rec.Digest)
		if err != nil {
			// Unknown is not "free": deleting on a failed check is how the live
			// checkpoint goes. Keep the row and try again next time.
			s.logger.Warn("wasm checkpoint ref in-use check failed; retaining row",
				"reason", reason, "push_id", rec.ID, "sandbox_id", rec.SandboxID, "error", err)
			return
		}
		if !inUse {
			if err := s.wasmCheckpointPusher.DeleteRef(ctx, ref); err != nil {
				s.logger.Warn("wasm checkpoint AOCR ref delete failed; will retry",
					"reason", reason, "push_id", rec.ID, "sandbox_id", rec.SandboxID,
					"registry_ref", ref, "error", err)
				return
			}
		}
	}
	if err := s.store.DeleteWasmCheckpointPush(ctx, rec.ID); err != nil {
		s.logger.Warn("wasm checkpoint push history row delete failed",
			"reason", reason, "push_id", rec.ID, "sandbox_id", rec.SandboxID, "error", err)
	}
}

// rehydrateWasmIfNeeded restores a passivated WASM sandbox from its checkpoint.
//
// Callers must hand it a sandbox whose Env is already materialised — the
// driver bakes the restored instance's baseEnv from that field and a store row
// never carries it. hydrateSandboxEnvForRestore is what does that; StartSandbox
// loads env inline for the same reason.
func (s *Service) rehydrateWasmIfNeeded(ctx context.Context, sandbox *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.Sandbox, error) {
	if sandbox == nil || !s.isWasmSandbox(sandbox) {
		return sandbox, nil
	}
	if sandbox.Status != models.SandboxStatusPassivated {
		return sandbox, nil
	}
	if !s.cfg.EnableWasm {
		return nil, fmt.Errorf("wasm runtime disabled; sandbox %s is passivated", sandbox.ID)
	}
	checkpointPath, err := s.ensureWasmCheckpointLocal(ctx, sandbox)
	if err != nil {
		return nil, err
	}
	if sandbox.CheckpointPath == "" {
		sandbox.CheckpointPath = checkpointPath
	}
	host, ok := s.wasm.(wasmruntime.CheckpointHost)
	if !ok {
		return nil, fmt.Errorf("wasm checkpoint host not available")
	}
	// Unseal per-tenant registry creds so a failover peer re-pulls a private
	// oci:// base module under the tenant's identity (codex C4).
	if err := s.attachWasmRegistryAuth(sandbox); err != nil {
		return nil, err
	}
	state, err := host.RehydrateSandbox(ctx, sandbox, hostMounts)
	if err != nil {
		if errors.Is(err, models.ErrSnapshotCorrupt) || errors.Is(err, models.ErrSnapshotFenced) {
			s.logger.Warn("wasm rehydrate failed; marking stopped",
				"sandbox_id", sandbox.ID,
				"error", err,
			)
			_ = s.store.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusStopped, err.Error())
			return nil, err
		}
		return nil, err
	}
	sandbox.ContainerID = state.ContainerID
	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
	sandbox.CheckpointPath = ""
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	return s.store.Get(ctx, sandbox.ID)
}
