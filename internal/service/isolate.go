package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) isIsolateSandbox(sandbox *models.Sandbox) bool {
	return sandbox != nil && sandbox.Runtime == models.RuntimeIsolate
}

// createIsolateSandbox is the V8-isolate runtime create path
// (plans/isolate-runtime.md): validate unsupported options, authorize the
// tenant group key, resolve+pin the bundle, admit, driver.Create (group
// router + inject), persist the row with LIFO unwind.
func (s *Service) createIsolateSandbox(ctx context.Context, req models.CreateSandboxRequest, idOverride string) (*models.CreateSandboxResponse, error) {
	if req.GPUs != nil {
		return nil, fmt.Errorf("runtime %q does not support GPUs (see plans/isolate-runtime.md): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}
	if strings.TrimSpace(req.TemplateID) != "" {
		return nil, fmt.Errorf("runtime %q does not support template_id (templates are a Firecracker concept; isolates deploy bundles): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}
	// Isolates have no filesystem — the bundle plus host-KV state is the
	// entire storage surface (plans/isolate-runtime.md §3). Mounts can never
	// appear inside a fetch handler, so reject rather than silently ignore.
	if len(req.Mounts) > 0 {
		return nil, fmt.Errorf("runtime %q does not support mounts (isolates have no filesystem, see plans/isolate-runtime.md §3)", req.Runtime)
	}
	if req.NetworkBytesInLimit < 0 || req.NetworkBytesOutLimit < 0 {
		return nil, errors.New("network byte limits must be >= 0")
	}
	bundleRef := models.ModuleRefForCreate(req)
	if bundleRef == "" {
		return nil, errors.New("module_ref or image is required for isolate runtime (the JS/TS bundle reference)")
	}
	req.ModuleRef = bundleRef

	// file:// and bare-path bundle refs read a file off the HOST filesystem as
	// the daemon user. That is an operator/self-host convenience, not something
	// a scoped tenant may drive — otherwise module_ref:"file:///etc/…" turns
	// create into an arbitrary host-file read. Gate it to unscoped callers;
	// scoped callers must upload via POST /v1/js-bundles and reference a digest
	// or name.
	if _, scoped := ownerScope(ctx); scoped && jsbundle.IsFileRef(bundleRef) {
		return nil, fmt.Errorf("runtime %q: file:// bundle refs are operator-only; upload via /v1/js-bundles and reference the digest or name", req.Runtime)
	}

	// Owner-scoped bundle resolution + digest pin. The bundle name space is the
	// caller's identity (owner_ref), NOT the isolate-group key (tenant_id) —
	// those are different axes (who owns the code vs. which process co-hosts
	// it). Resolving here, before the driver, pins "sha256:<digest>" onto the
	// request so: the driver (and a failover peer) resolve the exact bytes by
	// digest regardless of tenant, create is idempotent under retry, and an
	// uploaded name a user references actually resolves under that user. When
	// no store is wired (SB_ENABLE_ISOLATE off in a unit harness) the ref is
	// left untouched for the driver to handle.
	if s.isolateBundles != nil {
		owner := ownerRefForCreate(ctx)
		resolved, resolveErr := jsbundle.NewResolver(s.isolateBundles).Resolve(ctx, owner, bundleRef)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve bundle %q: %w", bundleRef, resolveErr)
		}
		// Ensure the resolved bytes are in the store (a file:// ref is not yet),
		// so the driver's by-digest resolve and failover both find them. Put is
		// a fast no-op when this owner already holds the digest (the common
		// case), so this is the only boot-path I/O: one index rewrite the first
		// time a digest is staged, none thereafter (pr-review.md §2).
		if _, err := s.isolateBundles.Put(owner, "", resolved); err != nil {
			return nil, fmt.Errorf("stage bundle: %w", err)
		}
		req.ModuleRef = "sha256:" + resolved.Digest
		// Protect the staged digest from the bundle GC for the rest of this
		// create: it is not yet pinned by a store row, so a GC sweep between
		// here and store.Create would otherwise reap the blob and strand the
		// sandbox on the next reload/failover (a TOCTOU on the GC).
		s.pinStagingDigest(resolved.Digest)
		defer s.unpinStagingDigest(resolved.Digest)
	}

	tenantID, err := s.authorizeIsolateTenantID(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	req.TenantID = tenantID

	// Durability: isolates are ephemeral by default; passivatable is rejected
	// (nothing to checkpoint — the bundle IS the image) and durable is a Phase
	// 5 promise (ErrRuntimeNotImplemented), both handled by NormalizeCreate-
	// Durability.
	durability, err := models.NormalizeCreateDurability(req.Durability, req.Runtime)
	if err != nil {
		return nil, err
	}
	req.Durability = durability

	var lifecycle models.Lifecycle
	if req.Lifecycle != nil {
		if err := s.validateLifecycle(*req.Lifecycle); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
		lifecycle = *req.Lifecycle
	}

	if req.MemoryMB <= 0 {
		req.MemoryMB = models.DefaultMemoryMB
	}

	sandboxID := idOverride
	if sandboxID == "" {
		sandboxID, err = generateSandboxID()
		if err != nil {
			return nil, fmt.Errorf("generate sandbox id: %w", err)
		}
	}

	// Admission. Isolates share a workerd process per group, so the base
	// per-group RAM is not modeled here (surfaced via expvar, per the capacity
	// decision); each sandbox is admitted at its declared footprint —
	// conservative, never over-books.
	if s.admitter != nil {
		if err := s.admitter.Admit(sandboxID, capacityRequestFromCreate(req)); err != nil {
			return nil, err
		}
	}
	releaseAdmission := func() {
		if s.admitter != nil {
			s.admitter.Release(sandboxID)
		}
	}

	// Cold path: resolve bundle → group router → load. The driver reaps a
	// freshly-spawned group if load fails (§11 empty-group rule), so the only
	// thing to unwind here on a LATER failure is admission + the store row +
	// the driver's own state (Destroy).
	state, err := s.isolate.Create(ctx, req, sandboxID, "", nil)
	if err != nil {
		releaseAdmission()
		return nil, err
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:                   state.SandboxID,
		Image:                req.ModuleRef,
		Status:               state.Status,
		CPU:                  req.CPU,
		MemoryMB:             req.MemoryMB,
		Env:                  req.Env,
		NetworkBlockAll:      req.NetworkBlockAll,
		NetworkAllowOut:      req.NetworkAllowOut,
		NetworkDenyOut:       req.NetworkDenyOut,
		AllowPublicTraffic:   req.AllowPublicTraffic,
		Name:                 strings.TrimSpace(req.Name),
		Tags:                 req.Tags,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
		Lifecycle:            lifecycle,
		Failover:             req.Failover,
		Runtime:              req.Runtime,
		NetworkBytesInLimit:  req.NetworkBytesInLimit,
		NetworkBytesOutLimit: req.NetworkBytesOutLimit,
		Durability:           req.Durability,
		ModuleRef:            req.ModuleRef,
		ModuleDigest:         state.ModuleDigest,
		TenantID:             req.TenantID,
	}
	sandbox.OwnerRef = s.ownerRefForCreateOrRecreate(ctx, sandbox.ID)
	if err := s.persistSandboxCreate(ctx, sandbox); err != nil {
		if errors.Is(err, models.ErrSandboxExists) {
			// A concurrent create with the same id won the INSERT. Both callers
			// ran the full driver create for the SAME id — host.Load, the group
			// member set, and admission are all keyed by id and idempotent, so
			// the winner's driver state and reservation are shared and already
			// correct. Rolling back here (Destroy + Release) would tear down the
			// winner's live sandbox and free its reservation (pr-review.md §4:
			// never delete state another caller installed). Return the committed
			// row instead — idempotent success.
			stored, getErr := s.store.Get(ctx, sandbox.ID)
			if getErr != nil {
				return nil, getErr
			}
			return &models.CreateSandboxResponse{Sandbox: *stored}, nil
		}
		_ = s.isolate.Destroy(ctx, sandbox)
		releaseAdmission()
		return nil, err
	}

	s.logger.Info("audit sandbox created",
		"sandbox_id", sandbox.ID,
		"runtime", sandbox.Runtime,
		"durability", sandbox.Durability,
		"tenant", sandbox.TenantID,
	)
	stored, err := s.store.Get(ctx, sandbox.ID)
	if err != nil {
		return nil, err
	}
	return &models.CreateSandboxResponse{Sandbox: *stored}, nil
}

// authorizeIsolateTenantID enforces §2.1's server-authorization rule for the
// isolate-group key: a caller who can choose an arbitrary tenant_id can force
// co-residency inside another tenant's workerd process or evade isolation
// policy, so the value must match — or be authorized by — the authenticated
// identity.
//
//   - empty + scoped caller: resolves to a STABLE per-owner group key
//     (isolateGroupKeyForOwner) so each authenticated identity gets its own
//     workerd process. It must NOT return "" here — "" routes to the shared
//     DefaultGroupKey ("default"), which would co-locate every scoped tenant
//     that omits tenant_id in one process (the forced-co-residency this field
//     exists to prevent).
//   - empty + operator/unscoped caller: returns "" → the single default group.
//     The operator is one trust domain; it partitions customers by passing an
//     explicit tenant_id.
//   - user-scoped token with an explicit value: only its own OwnerRef is
//     authorized. Anything else is rejected — the forced-co-residency case.
//   - operator/PAT and internal callers: any well-formed value.
//
// Explicit values must additionally be well-formed group keys (they become
// chroot directory and cgroup names — isolate.SanitizeGroupKey is the single
// definition of well-formed).
func (s *Service) authorizeIsolateTenantID(ctx context.Context, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	owner, scoped := ownerScope(ctx)
	if requested == "" {
		if scoped {
			return isolateGroupKeyForOwner(owner), nil
		}
		return "", nil
	}
	if _, err := isolate.SanitizeGroupKey(requested); err != nil {
		return "", fmt.Errorf("invalid tenant_id: %w", err)
	}
	if scoped && requested != owner {
		return "", fmt.Errorf("tenant_id %q is not authorized for the authenticated identity", requested)
	}
	return requested, nil
}

// isolateGroupKeyForOwner derives a stable, valid isolate-group key from a
// scoped caller's OwnerRef. OwnerRef is a control-plane identity of unspecified
// shape, so it may not satisfy isolate.SanitizeGroupKey (it becomes a chroot
// dir + cgroup name). When it already is a valid key we use it verbatim so the
// group is human-legible; otherwise we hash it into a stable "own-<hex>" key.
// Deterministic, so restart reconcile and failover rebuild the same grouping.
func isolateGroupKeyForOwner(owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ""
	}
	if _, err := isolate.SanitizeGroupKey(owner); err == nil {
		return owner
	}
	sum := sha256.Sum256([]byte(owner))
	return "own-" + hex.EncodeToString(sum[:16])
}
