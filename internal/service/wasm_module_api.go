package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// WasmModuleResolver resolves a module reference to a local .wasm artifact.
type WasmModuleResolver interface {
	Resolve(ctx context.Context, ref string) (*wasmmod.ResolvedModule, error)
}

// SetWasmModuleResolver wires the pkg/wasmmod.Resolver used by
// CreateWasmModule and lazy create paths.
func (s *Service) SetWasmModuleResolver(r WasmModuleResolver) {
	s.wasmModuleResolver = r
}

// CreateWasmModule resolves module_ref on this host and upserts the catalogue.
// Idempotent when the caller supplies an explicit id that already points at
// the same module_ref; conflicting ids return ErrWasmModuleIDConflict.
func (s *Service) CreateWasmModule(ctx context.Context, req models.CreateWasmModuleRequest) (*models.WasmModule, error) {
	if !s.cfg.EnableWasm {
		return nil, fmt.Errorf("wasm module create requires SB_ENABLE_WASM: %w", models.ErrRuntimeNotImplemented)
	}
	if s.wasmModuleResolver == nil {
		return nil, errors.New("wasm module resolver is not configured")
	}
	moduleRef := strings.TrimSpace(req.ModuleRef)
	if moduleRef == "" {
		return nil, errors.New("module_ref is required")
	}
	explicitID := strings.TrimSpace(req.ID)
	if explicitID != "" {
		if existing, err := s.store.GetWasmModule(ctx, explicitID); err == nil {
			if strings.TrimSpace(existing.ModuleRef) == moduleRef {
				return wasmModuleFromRecord(existing), nil
			}
			return nil, store.ErrWasmModuleIDConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	resolved, err := s.wasmModuleResolver.Resolve(ctx, moduleRef)
	if err != nil {
		if explicitID != "" {
			now := time.Now().UTC()
			_ = s.store.UpsertWasmModule(ctx, store.WasmModuleRecord{
				ID:        explicitID,
				ModuleRef: moduleRef,
				Status:    string(models.WasmModuleStatusFailed),
				LastError: err.Error(),
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
		return nil, fmt.Errorf("resolve wasm module: %w", err)
	}

	id := explicitID
	if id == "" {
		id = strings.TrimSpace(resolved.Digest)
	}
	if id == "" {
		return nil, errors.New("resolved module has empty digest")
	}
	if existing, err := s.store.GetWasmModule(ctx, id); err == nil {
		if strings.TrimSpace(existing.ModuleRef) == moduleRef {
			return wasmModuleFromRecord(existing), nil
		}
		return nil, store.ErrWasmModuleIDConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	entrypoint := strings.TrimSpace(req.Entrypoint)
	if entrypoint == "" {
		entrypoint = "_start"
	}
	now := time.Now().UTC()
	rec := store.WasmModuleRecord{
		ID:              id,
		ModuleRef:       moduleRef,
		Status:          string(models.WasmModuleStatusReady),
		ModulePath:      resolved.Path,
		ModuleSizeBytes: resolved.SizeBytes,
		Digest:          resolved.Digest,
		Entrypoint:      entrypoint,
		HasWarm:         s.cfg.WasmPoolEnabled,
		CreatedAt:       now,
		UpdatedAt:       now,
		ReadyAt:         &now,
	}
	if err := s.store.UpsertWasmModule(ctx, rec); err != nil {
		return nil, err
	}
	s.invalidateWasmModuleInventoryCache()
	return wasmModuleFromRecord(rec), nil
}

func (s *Service) ListWasmModules(ctx context.Context) ([]*models.WasmModule, error) {
	if !s.cfg.EnableWasm {
		return nil, fmt.Errorf("wasm modules require SB_ENABLE_WASM: %w", models.ErrRuntimeNotImplemented)
	}
	records, err := s.store.ListWasmModules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*models.WasmModule, 0, len(records))
	for _, rec := range records {
		r := wasmModuleFromRecord(rec)
		out = append(out, r)
	}
	return out, nil
}

func (s *Service) GetWasmModule(ctx context.Context, id string) (*models.WasmModule, error) {
	if !s.cfg.EnableWasm {
		return nil, fmt.Errorf("wasm modules require SB_ENABLE_WASM: %w", models.ErrRuntimeNotImplemented)
	}
	rec, err := s.store.GetWasmModule(ctx, id)
	if err != nil {
		return nil, err
	}
	return wasmModuleFromRecord(rec), nil
}

// DeleteWasmModule removes a catalogue row when no sandbox references it.
func (s *Service) DeleteWasmModule(ctx context.Context, id string) error {
	if !s.cfg.EnableWasm {
		return fmt.Errorf("wasm modules require SB_ENABLE_WASM: %w", models.ErrRuntimeNotImplemented)
	}
	rec, err := s.store.GetWasmModule(ctx, id)
	if err != nil {
		return err
	}
	referenced, err := s.store.IsWasmModuleReferenced(ctx, rec.ID, rec.ModuleRef)
	if err != nil {
		return err
	}
	if referenced {
		return store.ErrWasmModuleInUse
	}
	if err := s.store.DeleteWasmModule(ctx, id); err != nil {
		return err
	}
	s.invalidateWasmModuleInventoryCache()
	return nil
}

func wasmModuleFromRecord(rec store.WasmModuleRecord) *models.WasmModule {
	return &models.WasmModule{
		ID:              rec.ID,
		ModuleRef:       rec.ModuleRef,
		Status:          models.WasmModuleStatus(rec.Status),
		ModulePath:      rec.ModulePath,
		ModuleSizeBytes: rec.ModuleSizeBytes,
		Digest:          rec.Digest,
		Entrypoint:      rec.Entrypoint,
		HasWarm:         rec.HasWarm,
		LastError:       rec.LastError,
		CreatedAt:       rec.CreatedAt,
		UpdatedAt:       rec.UpdatedAt,
		ReadyAt:         rec.ReadyAt,
	}
}

func (s *Service) invalidateWasmModuleInventoryCache() {
	s.localReadyWasmModuleIDsMu.Lock()
	s.localReadyWasmModuleIDsExpires = time.Time{}
	s.localReadyWasmModuleIDsMu.Unlock()
}
