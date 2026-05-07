package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	store  *store.Store
	docker *docker.Client
	caddy  *caddy.Client
}

func New(cfg config.Config, logger *slog.Logger, db *store.Store, dockerClient *docker.Client, caddyClient *caddy.Client) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
		store:  db,
		docker: dockerClient,
		caddy:  caddyClient,
	}
}

func (s *Service) CreateSandbox(ctx context.Context, req models.CreateSandboxRequest) (*models.Sandbox, error) {
	req = normalizeCreateRequest(req)
	if req.Image == "" {
		return nil, errors.New("image is required")
	}

	runtime, err := s.docker.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	if runtime.SandboxID == "" {
		_ = s.docker.Destroy(ctx, &models.Sandbox{ContainerID: runtime.ContainerID, ContainerIP: runtime.ContainerIP})
		return nil, errors.New("docker runtime did not return a sandbox ID")
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:               runtime.SandboxID,
		Image:            req.Image,
		Status:           runtime.Status,
		PublicURL:        s.caddy.SandboxPublicURL(runtime.SandboxID),
		ContainerID:      runtime.ContainerID,
		ContainerIP:      runtime.ContainerIP,
		CPU:              req.CPU,
		MemoryMB:         req.MemoryMB,
		DiskGB:           req.DiskGB,
		OSUser:           req.OSUser,
		Env:              req.Env,
		NetworkBlockAll:  req.NetworkBlockAll,
		ToolboxEnabled:   true,
		CreatedAt:        now,
		UpdatedAt:        now,
		LastActiveAt:     now,
		ContainerCommand: req.ContainerCommand,
	}

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort); err != nil {
		_ = s.docker.Destroy(ctx, sandbox)
		return nil, err
	}

	if err := s.store.Create(ctx, sandbox); err != nil {
		_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
		_ = s.docker.Destroy(ctx, sandbox)
		return nil, err
	}

	return s.store.Get(ctx, sandbox.ID)
}

func (s *Service) GetSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) ListSandboxes(ctx context.Context) ([]*models.Sandbox, error) {
	return s.store.List(ctx)
}

func (s *Service) StartSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	runtime, err := s.docker.Start(ctx, sandboxContainerRef(sandbox))
	if err != nil {
		_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
		return nil, err
	}

	sandbox.ContainerID = runtime.ContainerID
	sandbox.ContainerIP = runtime.ContainerIP
	sandbox.Status = runtime.Status
	sandbox.UpdatedAt = time.Now().UTC()
	sandbox.LastActiveAt = time.Now().UTC()

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort); err != nil {
		return nil, err
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port.Port); err != nil {
			return nil, err
		}
	}

	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	return s.store.Get(ctx, id)
}

func (s *Service) StopSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.docker.Stop(ctx, sandboxContainerRef(sandbox)); err != nil {
		return nil, err
	}
	sandbox.Status = models.SandboxStatusStopped
	sandbox.UpdatedAt = time.Now().UTC()
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	return sandbox, nil
}

func (s *Service) DestroySandbox(ctx context.Context, id string) error {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	for _, port := range sandbox.ExposedPorts {
		_ = s.caddy.DeletePortRoute(ctx, sandbox.ID, port.Port)
	}
	_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
	if err := s.docker.Destroy(ctx, sandbox); err != nil {
		return err
	}
	return s.store.Delete(ctx, id)
}

func (s *Service) ResizeSandbox(ctx context.Context, id string, req models.ResizeSandboxRequest) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.docker.Resize(ctx, sandboxContainerRef(sandbox), req); err != nil {
		return nil, err
	}
	if req.CPU > 0 {
		sandbox.CPU = req.CPU
	}
	if req.MemoryMB > 0 {
		sandbox.MemoryMB = req.MemoryMB
	}
	if req.DiskGB > 0 {
		sandbox.DiskGB = req.DiskGB
	}
	sandbox.UpdatedAt = time.Now().UTC()
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	return s.store.Get(ctx, id)
}

func (s *Service) ExposePort(ctx context.Context, id string, port int) (string, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if port <= 0 || port > 65535 {
		return "", errors.New("invalid port")
	}

	publicURL := s.caddy.PortPublicURL(id, port)
	if err := s.caddy.UpsertPortRoute(ctx, id, sandbox.ContainerIP, port); err != nil {
		return "", err
	}

	exposure := models.ExposedPort{
		SandboxID: id,
		Port:      port,
		PublicURL: publicURL,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertPort(ctx, exposure); err != nil {
		return "", err
	}
	return publicURL, nil
}

func (s *Service) UnexposePort(ctx context.Context, id string, port int) error {
	if err := s.caddy.DeletePortRoute(ctx, id, port); err != nil {
		return err
	}
	return s.store.DeletePort(ctx, id, port)
}

func (s *Service) ToolboxTarget(ctx context.Context, id string) (string, error) {
	if err := s.TouchSandbox(ctx, id); err != nil {
		return "", err
	}
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if sandbox.ContainerIP == "" {
		return "", errors.New("sandbox container IP is not available")
	}
	return fmt.Sprintf("http://%s:%d", sandbox.ContainerIP, s.cfg.ToolboxPort), nil
}

func (s *Service) TouchSandbox(ctx context.Context, id string) error {
	return s.store.Touch(ctx, id, time.Now().UTC())
}

func (s *Service) Health(ctx context.Context) (models.HealthStatus, error) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		return models.HealthStatus{}, err
	}

	dockerStatus := "ok"
	if err := s.docker.Ping(ctx); err != nil {
		dockerStatus = err.Error()
	}

	caddyStatus := "ok"
	if err := s.caddy.Ping(ctx); err != nil {
		caddyStatus = err.Error()
	}

	status := "ok"
	if dockerStatus != "ok" || caddyStatus != "ok" {
		status = "degraded"
	}

	return models.HealthStatus{
		Status:    status,
		Sandboxes: len(sandboxes),
		Docker:    dockerStatus,
		Caddy:     caddyStatus,
		Version:   version.Version,
	}, nil
}

func (s *Service) TLSDomainAllowed(host string) bool {
	return s.caddy.AllowTLSDomain(host)
}

func (s *Service) Reconcile(ctx context.Context) error {
	known, err := s.store.List(ctx)
	if err != nil {
		return err
	}

	managed, err := s.docker.ListManaged(ctx)
	if err != nil {
		return err
	}

	for _, sandbox := range known {
		runtime, ok := managed[sandbox.ID]
		if !ok {
			sandbox.Status = models.SandboxStatusDestroyed
			sandbox.ContainerIP = ""
			sandbox.ContainerID = ""
			sandbox.UpdatedAt = time.Now().UTC()
			if err := s.store.Upsert(ctx, sandbox); err != nil {
				return err
			}
			_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
			for _, port := range sandbox.ExposedPorts {
				_ = s.caddy.DeletePortRoute(ctx, sandbox.ID, port.Port)
			}
			continue
		}

		sandbox.ContainerID = runtime.ContainerID
		sandbox.ContainerIP = runtime.ContainerIP
		sandbox.Status = runtime.Status
		sandbox.PublicURL = s.caddy.SandboxPublicURL(sandbox.ID)
		sandbox.UpdatedAt = time.Now().UTC()
		if runtime.Status == models.SandboxStatusStarted {
			if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort); err != nil {
				return err
			}
			for _, port := range sandbox.ExposedPorts {
				if err := s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port.Port); err != nil {
					return err
				}
			}
		}
		if err := s.store.Upsert(ctx, sandbox); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) StartIdleMonitor(ctx context.Context) {
	idleTimeout := s.cfg.IdleTimeout()
	if idleTimeout <= 0 {
		return
	}

	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runIdleSweep(context.Background(), idleTimeout)
			}
		}
	}()
}

func (s *Service) runIdleSweep(ctx context.Context, idleTimeout time.Duration) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("idle sweep failed", "error", err)
		return
	}

	deadline := time.Now().Add(-idleTimeout)
	for _, sandbox := range sandboxes {
		if sandbox.Status != models.SandboxStatusStarted {
			continue
		}
		if sandbox.LastActiveAt.After(deadline) {
			continue
		}
		if _, err := s.StopSandbox(ctx, sandbox.ID); err != nil {
			s.logger.Warn("auto-stop failed", "sandbox_id", sandbox.ID, "error", err)
		}
	}
}

func normalizeCreateRequest(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	if req.CPU <= 0 {
		req.CPU = 1
	}
	if req.MemoryMB <= 0 {
		req.MemoryMB = 1024
	}
	if req.DiskGB <= 0 {
		req.DiskGB = 10
	}
	if req.OSUser == "" {
		req.OSUser = "root"
	}
	if req.Env == nil {
		req.Env = map[string]string{}
	}
	return req
}

func sandboxContainerRef(sandbox *models.Sandbox) string {
	if sandbox == nil {
		return ""
	}
	return sandbox.ContainerID
}
