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

// PushWasmModule is a STATELESS proxy: it validates a BYO .wasm upload
// (core-wasip1, size) and forwards it to the registry under the caller's own
// per-tenant credentials, returning the oci:// ref for a later create. The
// daemon never stores or serves the bytes — AOCR is the registry, this is just
// orchestration convenience for clients without oras/docker.
func (s *Service) PushWasmModule(ctx context.Context, name, tag, username, token string, data io.Reader) (*models.PushWasmModuleResponse, error) {
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

	// Bounded copy + streaming digest: one read computes size + content sha256
	// and writes the temp file. Reading one byte past the cap lets us reject an
	// oversized upload without buffering it all.
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
	// Per-tenant creds from the request are required — the daemon forwards
	// under the CALLER's identity, never a global one. The system config
	// identity (WasmRegistryPATPath) exists only for pulling standard modules,
	// not for tenant pushes.
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("registry credentials required: supply X-Registry-Token")
	}
	auth := wasmmod.ModuleAuth{Username: strings.TrimSpace(username), PAT: strings.TrimSpace(token)}
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

// WasmWarmPoolNotifier registers a resolved module as a warm-pool refill
// target. Production wiring passes *wasmpool.Pool; tests inject a recorder.
type WasmWarmPoolNotifier interface {
	NoteModule(digest, modulePath string)
}

// SetWasmWarmPool wires the warm pool into module registration.
func (s *Service) SetWasmWarmPool(p WasmWarmPoolNotifier) {
	s.wasmWarmPool = p
}

// noteWasmWarmModule marks digest/path as a warm-pool refill target.
// Registration is the earliest moment a non-standard module is local and
// validated; without this the pool only learns a digest inside Acquire, so
// the first create on each node pays the full cold compile (~2.8s for the
// bench module on t3.medium — the p90 tail in the 2026-07-05 UC-94 run).
// Best-effort and idempotent: the pool dedupes repeat notes, and a nil pool
// (SB_WASM_POOL_ENABLED=false) keeps registration a pure catalogue write.
func (s *Service) noteWasmWarmModule(digest, modulePath string) {
	if s.wasmWarmPool == nil || strings.TrimSpace(digest) == "" || strings.TrimSpace(modulePath) == "" {
		return
	}
	s.wasmWarmPool.NoteModule(digest, modulePath)
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
	owner := ownerRefForCreate(ctx)
	explicitID := strings.TrimSpace(req.ID)
	if explicitID != "" {
		if existing, err := s.store.GetWasmModule(ctx, explicitID); err == nil {
			// A row the caller cannot write (another tenant's, or an
			// operator-published "" row when the caller is a tenant) is not
			// theirs to echo back or adopt — report the id as taken, never
			// leak the owner's ref/path.
			if strings.TrimSpace(existing.ModuleRef) == moduleRef && wasmModuleWritable(ctx, existing) {
				// Re-registering an already-catalogued module re-arms the warm
				// pool: pool targets live in memory, so after a daemon restart
				// the catalogue row exists but the pool has forgotten it.
				s.noteWasmWarmModule(existing.Digest, existing.ModulePath)
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
				OwnerRef:  owner,
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
		if strings.TrimSpace(existing.ModuleRef) == moduleRef && wasmModuleWritable(ctx, existing) {
			s.noteWasmWarmModule(existing.Digest, existing.ModulePath)
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
		OwnerRef:        owner,
		CreatedAt:       now,
		UpdatedAt:       now,
		ReadyAt:         &now,
	}
	if err := s.store.UpsertWasmModule(ctx, rec); err != nil {
		return nil, err
	}
	s.invalidateWasmModuleInventoryCache()
	// Note AFTER the catalogue write: a module the pool warms should always
	// be one the catalogue can resolve, never the reverse.
	s.noteWasmWarmModule(resolved.Digest, resolved.Path)
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
		// A tenant sees only operator-published ("") and its own rows; an
		// operator/internal caller sees everything.
		if !wasmModuleVisible(ctx, rec) {
			continue
		}
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
	// 404 (not 403) for a module the caller cannot see, so a tenant cannot
	// probe ids to learn which modules (and registry refs) other tenants hold.
	if !wasmModuleVisible(ctx, rec) {
		return nil, store.ErrNotFound
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
	// A tenant may delete only its own rows. An operator-published ("") row is
	// read-only to tenants and writable only by the operator. Invisible rows
	// 404 so delete is not an existence oracle either.
	if !wasmModuleVisible(ctx, rec) {
		return store.ErrNotFound
	}
	if !wasmModuleWritable(ctx, rec) {
		return store.ErrNotFound
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

// wasmModuleVisible reports whether the caller may read a catalogue row.
// Operator/internal callers (unscoped) see every row. A tenant sees only
// operator-published rows (OwnerRef == "") and its own. The "" rule keeps
// standard/operator-pushed modules usable fleet-wide, as before owner scoping.
func wasmModuleVisible(ctx context.Context, rec store.WasmModuleRecord) bool {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return true
	}
	return rec.OwnerRef == "" || rec.OwnerRef == owner
}

// wasmModuleWritable reports whether the caller may delete/overwrite a row.
// It is stricter than visibility: an operator-published ("") row is read-only
// to a tenant, so a tenant can write only rows it owns. Operator/internal
// callers may write anything.
func wasmModuleWritable(ctx context.Context, rec store.WasmModuleRecord) bool {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return true
	}
	return rec.OwnerRef != "" && rec.OwnerRef == owner
}

// ResolveOwnedWasmModule is the owner-scoped create-time catalogue lookup wired
// into the module resolver (step 3 of ref resolution). A BYO catalogue id
// resolves to its local path + digest only when the caller may see the row,
// so a tenant cannot boot a sandbox from another tenant's catalogued module by
// naming its id. Only "ready" rows with a real path resolve.
func (s *Service) ResolveOwnedWasmModule(ctx context.Context, id string) (path, digest string, ok bool) {
	rec, err := s.store.GetWasmModule(ctx, id)
	if err != nil {
		return "", "", false
	}
	if !wasmModuleVisible(ctx, rec) {
		return "", "", false
	}
	if !strings.EqualFold(rec.Status, "ready") || strings.TrimSpace(rec.ModulePath) == "" {
		return "", "", false
	}
	return rec.ModulePath, rec.Digest, true
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
