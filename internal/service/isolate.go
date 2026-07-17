package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) isIsolateSandbox(sandbox *models.Sandbox) bool {
	return sandbox != nil && sandbox.Runtime == models.RuntimeIsolate
}

// createIsolateSandbox is the V8-isolate runtime create path
// (plans/isolate-runtime.md). Phase 1 mirrors the wasm/firecracker
// scaffolding: validate unsupported options, authorize the tenant group key,
// dispatch to the driver. Create on the driver still returns
// ErrRuntimeNotImplemented until Phase 2 lands the cold path (bundle resolve
// → group router → inject); admission reservation and row persistence land
// with it — reserving capacity for a create that cannot yet succeed would
// only add a release path to unwind.
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
	sandbox.OwnerRef = ownerRefForCreate(ctx)

	// No caddy on the Phase-2 boot path: external inbound routing to the fetch
	// handler (guest_http.go + expose_port) lands in Phase 3, so a created
	// isolate is invocable by the driver but not yet publicly routed. This
	// matches the private-by-default posture and keeps the boot path free of
	// L7 work.
	if err := s.store.Create(ctx, sandbox); err != nil {
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
//   - empty: allowed for everyone; returns "" and the group key falls back to
//     the authenticated identity at group-routing time (single-tenant
//     self-hosters get one group with zero config).
//   - user-scoped token: only its own OwnerRef is authorized. Anything else
//     is rejected — this is the forced-co-residency regression case.
//   - operator/PAT and internal callers: any well-formed value. The operator
//     IS the platform; partitioning its customers into named tenant groups is
//     exactly what the field exists for.
//
// Explicit values must additionally be well-formed group keys (they become
// chroot directory and cgroup names — isolate.SanitizeGroupKey is the single
// definition of well-formed).
func (s *Service) authorizeIsolateTenantID(ctx context.Context, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", nil
	}
	if _, err := isolate.SanitizeGroupKey(requested); err != nil {
		return "", fmt.Errorf("invalid tenant_id: %w", err)
	}
	owner, scoped := ownerScope(ctx)
	if scoped && requested != owner {
		return "", fmt.Errorf("tenant_id %q is not authorized for the authenticated identity", requested)
	}
	return requested, nil
}
