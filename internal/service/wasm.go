package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) isWasmSandbox(sandbox *models.Sandbox) bool {
	return sandbox != nil && sandbox.Runtime == models.RuntimeWasm
}

// createWasmSandbox is the WASM runtime create path (plans/wasm-runtime.md).
// Phase 1 mirrors the firecracker scaffolding: validate unsupported options,
// reserve admission, dispatch to the driver, persist the row. Create on the
// driver still returns ErrRuntimeNotImplemented until Phase 2 lands the cold path.
func (s *Service) createWasmSandbox(ctx context.Context, req models.CreateSandboxRequest, idOverride string) (*models.CreateSandboxResponse, error) {
	if len(req.Mounts) > 0 {
		return nil, fmt.Errorf("runtime %q does not yet support mounts (see plans/wasm-runtime.md): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}
	if req.GPUs != nil {
		return nil, fmt.Errorf("runtime %q does not yet support GPUs (see plans/wasm-runtime.md): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}
	if req.NetworkBytesInLimit < 0 || req.NetworkBytesOutLimit < 0 {
		return nil, errors.New("network byte limits must be >= 0")
	}
	if req.NetworkBlockAll {
		return nil, unsupportedWasmOption("network_block_all")
	}
	if req.NetworkBytesInLimit > 0 || req.NetworkBytesOutLimit > 0 {
		return nil, unsupportedWasmOption("network byte limits")
	}
	if strings.TrimSpace(req.TemplateID) != "" {
		return nil, fmt.Errorf("runtime %q does not support template_id (see plans/wasm-runtime.md): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}
	moduleRef := models.ModuleRefForCreate(req)
	if moduleRef == "" {
		return nil, errors.New("module_ref or image is required for wasm runtime")
	}
	req.ModuleRef = moduleRef
	if strings.TrimSpace(req.Image) == "" {
		req.Image = moduleRef
	}

	var lifecycle models.Lifecycle
	if req.Lifecycle != nil {
		if err := s.validateLifecycle(*req.Lifecycle); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
		lifecycle = *req.Lifecycle
	}

	toolboxToken, err := generateToolboxToken()
	if err != nil {
		return nil, fmt.Errorf("generate toolbox token: %w", err)
	}
	authorizedKey, privateKeyPEM, err := generateSandboxSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("generate ssh keypair: %w", err)
	}

	sandboxID := idOverride
	if sandboxID == "" {
		sandboxID, err = generateSandboxID()
		if err != nil {
			return nil, fmt.Errorf("generate sandbox id: %w", err)
		}
	}

	if s.cfg.WasmMaxInstances > 0 {
		managed, listErr := s.wasm.ListManaged(ctx)
		if listErr != nil {
			return nil, fmt.Errorf("wasm instance cap check: %w", listErr)
		}
		if len(managed) >= s.cfg.WasmMaxInstances {
			return nil, fmt.Errorf("wasm instance cap %d reached: %w", s.cfg.WasmMaxInstances, capacity.ErrCapacityExceeded)
		}
	}

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

	state, err := s.wasm.Create(ctx, req, sandboxID, toolboxToken, nil)
	if err != nil {
		releaseAdmission()
		return nil, err
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:                   state.SandboxID,
		Image:                req.Image,
		Status:               state.Status,
		PublicURL:            s.caddy.SandboxPublicURL(state.SandboxID),
		ContainerID:          state.ContainerID,
		ContainerIP:          state.ContainerIP,
		CPU:                  req.CPU,
		MemoryMB:             req.MemoryMB,
		DiskGB:               req.DiskGB,
		OSUser:               req.OSUser,
		Env:                  req.Env,
		ToolboxEnabled:       true,
		ToolboxToken:         toolboxToken,
		SSHPublicKey:         authorizedKey,
		Name:                 strings.TrimSpace(req.Name),
		Tags:                 req.Tags,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
		ContainerCommand:     req.ContainerCommand,
		Lifecycle:            lifecycle,
		Failover:             req.Failover,
		Runtime:              req.Runtime,
		NetworkBytesInLimit:  req.NetworkBytesInLimit,
		NetworkBytesOutLimit: req.NetworkBytesOutLimit,
		Durability:           req.Durability,
		ModuleRef:            moduleRef,
		ModuleDigest:         state.ModuleDigest,
	}
	sandbox.OwnerRef = ownerRefForCreate(ctx)

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort, sandboxCustomHostnames(sandbox)); err != nil {
		_ = s.wasm.Destroy(ctx, sandbox)
		releaseAdmission()
		return nil, err
	}
	if err := s.store.Create(ctx, sandbox); err != nil {
		_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
		_ = s.wasm.Destroy(ctx, sandbox)
		releaseAdmission()
		return nil, err
	}
	if err := s.persistCustomDomainsOnCreate(ctx, sandbox.ID, req.CustomDomains); err != nil {
		_ = s.store.Delete(ctx, sandbox.ID)
		_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
		_ = s.wasm.Destroy(ctx, sandbox)
		releaseAdmission()
		return nil, err
	}

	s.logger.Info("audit sandbox created",
		"sandbox_id", sandbox.ID,
		"image", sandbox.Image,
		"runtime", sandbox.Runtime,
		"durability", sandbox.Durability,
	)
	stored, err := s.store.Get(ctx, sandbox.ID)
	if err != nil {
		return nil, err
	}
	return &models.CreateSandboxResponse{
		Sandbox:       *stored,
		SSHPrivateKey: privateKeyPEM,
	}, nil
}

func unsupportedWasmOption(option string) error {
	return fmt.Errorf("runtime %q does not yet support %s (see plans/wasm-runtime.md): %w",
		models.RuntimeWasm, option, models.ErrRuntimeNotImplemented)
}
