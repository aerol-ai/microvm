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

// CreateWasmModule resolves module_ref on this host and upserts the catalogue
// row in the caller's own namespace (a tenant's account, or "" for operator and
// internal callers). The id defaults to the module's content digest, so two
// owners registering identical bytes each get their own row: rows in other
// namespaces are never read here, which is what keeps another owner's module
// from surfacing as a conflict. Idempotent when the caller re-registers an id
// it already holds for the same module_ref; the same id bound to a different
// module_ref in the caller's namespace returns ErrWasmModuleIDConflict.
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
		if existing, done, err := s.replayOwnWasmModule(ctx, owner, explicitID, moduleRef); done {
			return existing, err
		}
	}

	resolved, err := s.wasmModuleResolver.Resolve(wasmResolveContext(ctx), moduleRef)
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
	if existing, done, err := s.replayOwnWasmModule(ctx, owner, id, moduleRef); done {
		return existing, err
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

// replayOwnWasmModule checks id in owner's namespace before a create writes
// it. done=false means the id is free there and the create proceeds. An
// existing row for the same module_ref is echoed back (the idempotent retry);
// one for a different module_ref is ErrWasmModuleIDConflict. Only the
// caller's namespace is consulted, so the answer never depends on, or reveals,
// what another owner registered.
func (s *Service) replayOwnWasmModule(ctx context.Context, owner, id, moduleRef string) (mod *models.WasmModule, done bool, err error) {
	existing, err := s.store.GetWasmModule(ctx, owner, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if strings.TrimSpace(existing.ModuleRef) != moduleRef {
		return nil, true, store.ErrWasmModuleIDConflict
	}
	// Re-registering an already-catalogued module re-arms the warm pool: pool
	// targets live in memory, so after a daemon restart the catalogue row
	// exists but the pool has forgotten it.
	s.noteWasmWarmModule(existing.Digest, existing.ModulePath)
	return wasmModuleFromRecord(existing), true, nil
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
	// The caller's own row first, then the operator-published one. Another
	// owner's row with this id is never read, so a tenant probing ids gets the
	// same 404 whether or not someone else registered it.
	rec, err := s.store.ResolveWasmModule(ctx, ownerRefForCreate(ctx), id)
	if err != nil {
		return nil, err
	}
	return wasmModuleFromRecord(rec), nil
}

// DeleteWasmModule removes the caller's own catalogue row when no sandbox
// that resolves through it remains. Delete acts only inside the caller's
// namespace: another owner's row with the same id is out of reach, and an
// operator-published ("") row is read-only to a tenant, so both 404 like an
// id that does not exist.
func (s *Service) DeleteWasmModule(ctx context.Context, id string) error {
	if !s.cfg.EnableWasm {
		return fmt.Errorf("wasm modules require SB_ENABLE_WASM: %w", models.ErrRuntimeNotImplemented)
	}
	rec, err := s.store.GetWasmModule(ctx, ownerRefForCreate(ctx), id)
	if err != nil {
		return err
	}
	referenced, err := s.wasmModuleRowInUse(ctx, rec)
	if err != nil {
		return err
	}
	if referenced {
		return store.ErrWasmModuleInUse
	}
	shared, err := s.wasmModuleBytesShared(ctx, rec)
	if err != nil {
		return err
	}
	// Reclaim the bytes only for a host-capable caller. A tenant catalogue row
	// only ever REFERENCES module bytes on the host — operator-staged standard
	// modules (ModulesDir/python.wasm) and reserved keywords are provisioned by
	// the operator, and oci:// pulls live in a content-addressed cache the
	// operator reaps — so a tenant row-delete must drop the row alone. Without
	// this gate RemoveImage re-resolves rec.ModuleRef (e.g. "python") and
	// removes the shared file, letting one team break every tenant's Python
	// sandboxes on the node (issue #537). The row-visibility rule already fenced
	// the caller to its own namespace, so the row delete below is safe for all.
	if !shared && s.wasm != nil && hostCapable(ctx) {
		if err := s.wasm.RemoveImage(ctx, rec.ModuleRef); err != nil {
			return err
		}
	}
	if err := s.store.DeleteWasmModule(ctx, rec.OwnerRef, rec.ID); err != nil {
		return err
	}
	s.invalidateWasmModuleInventoryCache()
	return nil
}

// wasmModuleRowInUse reports whether a sandbox can still resolve through rec,
// which blocks deleting it. Only an owner's own creates resolve its rows, so a
// tenant row is checked against that tenant's sandboxes alone: another owner
// running the same bytes neither blocks the delete nor learns of it through
// a 409. Every namespace falls back to operator-published rows, so a "" row is
// checked against every sandbox on the host.
func (s *Service) wasmModuleRowInUse(ctx context.Context, rec store.WasmModuleRecord) (bool, error) {
	if rec.OwnerRef == "" {
		return s.store.IsWasmModuleReferenced(ctx, rec.ID, rec.ModuleRef, rec.Digest)
	}
	return s.store.IsWasmModuleReferencedByOwner(ctx, rec.OwnerRef, rec.ID, rec.ModuleRef, rec.Digest)
}

// wasmModuleBytesShared reports whether rec's bytes must outlive rec. Ids are
// per owner but the bytes are content-addressed and shared on the host (one
// cache file and one warm-pool target per digest), so they stay while any
// sandbox or any other catalogue row still uses them. It only decides whether
// the bytes go; the row delete succeeds either way, so nothing about other
// owners reaches the caller.
func (s *Service) wasmModuleBytesShared(ctx context.Context, rec store.WasmModuleRecord) (bool, error) {
	if rec.OwnerRef != "" {
		// The row gate looked at this owner's sandboxes only.
		inUse, err := s.store.IsWasmModuleReferenced(ctx, rec.ID, rec.ModuleRef, rec.Digest)
		if err != nil || inUse {
			return inUse, err
		}
	}
	return s.store.IsWasmDigestCataloguedElsewhere(ctx, rec.OwnerRef, rec.ID, rec.Digest)
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

// ResolveOwnedWasmModule is the owner-scoped create-time catalogue lookup wired
// into the module resolver (step 3 of ref resolution). A BYO catalogue id
// resolves in the booting owner's namespace first, then to an
// operator-published ("") row, so a tenant cannot boot a sandbox from another
// tenant's catalogued module by naming its id, and an own row shadows an
// operator row with the same id. Only "ready" rows with a real path resolve.
func (s *Service) ResolveOwnedWasmModule(ctx context.Context, id string) (path, digest string, ok bool) {
	rec, err := s.store.ResolveWasmModule(ctx, wasmCatalogueNamespace(ctx), id)
	if err != nil {
		return "", "", false
	}
	if !strings.EqualFold(rec.Status, "ready") || strings.TrimSpace(rec.ModulePath) == "" {
		return "", "", false
	}
	return rec.ModulePath, rec.Digest, true
}

// wasmCatalogueNamespace is the owner namespace a create-time boot resolves a
// catalogue id in: the owner pinned with wasmmod.WithCatalogueOwner (the owner
// of the sandbox being booted), else the caller's own. An operator or internal
// caller with no pin resolves only operator-published rows. That is stricter
// than its fleet-wide read access on purpose: a tenant must not be able to
// register an id that an operator create names and so hijack that boot onto
// its own bytes (the same rule as snapshotResolvableForCreate).
func wasmCatalogueNamespace(ctx context.Context) string {
	if owner, ok := wasmmod.CatalogueOwner(ctx); ok {
		return owner
	}
	return ownerRefForCreate(ctx)
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
