package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// maxPushBytes caps a BYO upload body, mirroring wasmmod's 256MiB artifact cap.
const maxPushBytes = 256 << 20

// PushWasmModule validates a BYO .wasm upload and pushes it to the configured
// registry as an oci artifact, returning the oci:// ref the caller uses on a
// later create. The bytes are validated (core-wasip1, size) BEFORE upload so a
// component or oversized artifact is rejected without touching the registry.
func (s *Service) PushWasmModule(ctx context.Context, name, tag string, data io.Reader) (*models.PushWasmModuleResponse, error) {
	if !s.cfg.EnableWasm {
		return nil, fmt.Errorf("wasm module push requires SB_ENABLE_WASM: %w", models.ErrRuntimeNotImplemented)
	}
	host := strings.TrimRight(strings.TrimSpace(s.cfg.WasmRegistryPushHost), "/")
	if host == "" {
		return nil, errors.New("wasm module push is not configured (SB_WASM_REGISTRY_PUSH_HOST)")
	}
	name = strings.Trim(strings.TrimSpace(name), "/")
	if name == "" || strings.Contains(name, "://") || strings.ContainsAny(name, " \t") {
		return nil, fmt.Errorf("invalid module name %q", name)
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		tag = "latest"
	}

	tmp, err := os.CreateTemp("", "aerol-wasm-push-*.wasm")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	// Bounded copy + streaming digest: one read of the body computes the size,
	// the content sha256, and writes the temp file. Reading one byte past the
	// cap lets us reject an oversized upload without buffering it all.
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(data, maxPushBytes+1))
	_ = tmp.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if n > maxPushBytes {
		return nil, fmt.Errorf("%w: upload exceeds %d bytes", wasmmod.ErrModuleTooLarge, int64(maxPushBytes))
	}

	if err := wasmmod.ValidateFile(tmpPath); err != nil {
		return nil, err
	}
	digest := hex.EncodeToString(h.Sum(nil))

	registryRef := fmt.Sprintf("%s/%s:%s", host, name, tag)
	auth := wasmmod.ModuleAuth{Username: s.cfg.WasmRegistryUsername, PATPath: s.cfg.WasmRegistryPATPath}
	if _, err := wasmmod.PushModuleArtifact(ctx, auth, tmpPath, registryRef); err != nil {
		return nil, err
	}
	return &models.PushWasmModuleResponse{
		ModuleRef: "oci://" + registryRef,
		Digest:    digest,
		SizeBytes: n,
	}, nil
}

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
	referenced, err := s.store.IsWasmModuleReferenced(ctx, rec.ID, rec.ModuleRef, rec.Digest)
	if err != nil {
		return err
	}
	if referenced {
		return store.ErrWasmModuleInUse
	}
	if s.wasm != nil {
		if err := s.wasm.RemoveImage(ctx, rec.ModuleRef); err != nil {
			return err
		}
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
