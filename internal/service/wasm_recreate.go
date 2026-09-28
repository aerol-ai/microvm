package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// recreateWasmDurableSandbox restores a durable WASM sandbox on a new owner
// after cluster failover: pull mem.snap from AOCR when needed, rehydrate, replay ports.
//
// incarnationID is the lifetime being restored, taken from the authoritative
// placement. It has to be known BEFORE the checkpoint is fetched: the seed row
// used to get its lifetime only when it was persisted, after the pull, so the
// pull had nothing to bind to and read the id-wide :latest — whichever
// lifetime pushed last, a destroyed one included — and then adopted that
// snapshot's clone generation as if it were current.
func (s *Service) recreateWasmDurableSandbox(ctx context.Context, id, incarnationID string, spec models.CreateSandboxRequest, exposedPorts map[int]cluster.ExposedPortRoute) (bool, error) {
	incarnationID = strings.TrimSpace(incarnationID)
	if incarnationID == "" {
		return true, fmt.Errorf("recreate %s: placement carries no lifetime (incarnation); refusing to restore an unidentified checkpoint", id)
	}
	existing, err := s.store.Get(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return true, err
	}
	if existing != nil {
		// A local row from a DIFFERENT lifetime is not a retry of this restore;
		// rehydrating it would bring back the previous lifetime's state under
		// the current one's placement. Reconciliation retires the stale row.
		if local := strings.TrimSpace(existing.AuditIncarnationID); local != "" && local != incarnationID {
			return true, fmt.Errorf("recreate %s: local row belongs to lifetime %s, placement is %s", id, local, incarnationID)
		}
		attempted := existing.Status == models.SandboxStatusPassivated
		if _, err := s.ensureWasmCheckpointLocal(ctx, existing); err != nil {
			return true, fmt.Errorf("recreate %s: %w", id, err)
		}
		// This branch is the retry after a restore that failed once the row was
		// already persisted: the row comes from the store and therefore carries
		// no env, while the seed branch below builds it from the spec.
		if err := s.hydrateSandboxEnvForRestore(ctx, existing, spec.Env); err != nil {
			return true, fmt.Errorf("recreate %s: %w", id, err)
		}
		if _, err := s.rehydrateWasmIfNeeded(ctx, existing, nil); err != nil {
			return true, fmt.Errorf("recreate %s: rehydrate: %w", id, err)
		}
		s.ReconstructWakeArmedIfNeeded(ctx, existing)
		if err := s.replayClusterExposedPorts(ctx, id, exposedPorts); err != nil {
			return true, err
		}
		return attempted, nil
	}

	moduleRef := models.ModuleRefForCreate(spec)
	if moduleRef == "" {
		return true, fmt.Errorf("recreate %s: module_ref required for wasm", id)
	}
	checkpointPath := wasmCheckpointDir(s.cfg.WasmModulesDir, id)
	seed := &models.Sandbox{
		ID:                 id,
		Runtime:            models.RuntimeWasm,
		Durability:         models.DurabilityDurable,
		ModuleRef:          moduleRef,
		Image:              strings.TrimSpace(spec.Image),
		Status:             models.SandboxStatusPassivated,
		AllowPublicTraffic: spec.AllowPublicTraffic,
		// Set before the pull, so the checkpoint fetched is this lifetime's
		// and the clone generation adopted below is too.
		AuditIncarnationID: incarnationID,
	}
	if _, err := s.ensureWasmCheckpointLocal(ctx, seed); err != nil {
		return true, fmt.Errorf("recreate %s: pull checkpoint: %w", id, err)
	}
	if snap, readErr := wasmengine.ReadSnapshotDir(checkpointPath, wasmengine.EngineNameWazero()); readErr == nil {
		seed.CloneGeneration = snap.Config.CloneGeneration
		if seed.ModuleDigest == "" {
			seed.ModuleDigest = snap.Config.BaseModule.Digest
		}
	}
	seed.CheckpointPath = checkpointPath
	now := time.Now().UTC()
	seed.CPU = spec.CPU
	seed.MemoryMB = spec.MemoryMB
	seed.DiskGB = spec.DiskGB
	seed.Env = spec.Env
	seed.NetworkBlockAll = spec.NetworkBlockAll
	seed.NetworkAllowOut = spec.NetworkAllowOut
	seed.NetworkDenyOut = spec.NetworkDenyOut
	seed.ContainerCommand = spec.ContainerCommand
	seed.CreatedAt = now
	seed.UpdatedAt = now
	seed.OwnerRef = s.tenantOwnerRefForRecreate(ctx, id)
	if err := s.persistSandboxCreate(ctx, seed); err != nil {
		return true, fmt.Errorf("recreate %s: persist row: %w", id, err)
	}
	if _, err := s.rehydrateWasmIfNeeded(ctx, seed, nil); err != nil {
		return true, fmt.Errorf("recreate %s: rehydrate: %w", id, err)
	}
	if err := s.replayClusterExposedPorts(ctx, id, exposedPorts); err != nil {
		return true, err
	}
	return true, nil
}
