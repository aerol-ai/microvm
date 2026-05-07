package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
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

func (s *Service) CreateSandbox(ctx context.Context, req models.CreateSandboxRequest) (*models.CreateSandboxResponse, error) {
	req = normalizeCreateRequest(req)
	if req.Image == "" {
		return nil, errors.New("image is required")
	}

	toolboxToken, err := generateToolboxToken()
	if err != nil {
		return nil, fmt.Errorf("generate toolbox token: %w", err)
	}

	authorizedKey, privateKeyPEM, err := generateSandboxSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("generate ssh keypair: %w", err)
	}

	runtime, err := s.docker.Create(ctx, req, toolboxToken)
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
		ToolboxToken:     toolboxToken,
		SSHPublicKey:     authorizedKey,
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

	s.logger.Info("audit sandbox created",
		"sandbox_id", sandbox.ID,
		"image", sandbox.Image,
		"cpu", sandbox.CPU,
		"memory_mb", sandbox.MemoryMB,
		"disk_gb", sandbox.DiskGB,
		"network_block_all", sandbox.NetworkBlockAll,
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

// generateSandboxSSHKeys produces an ed25519 keypair scoped to a single
// sandbox. The OpenSSH-format authorized public key is what the gateway will
// store on the sandbox record; the PEM-encoded private key is returned to the
// caller exactly once and never persisted.
func generateSandboxSSHKeys() (authorizedKey, privateKeyPEM string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("derive signer: %w", err)
	}
	authorizedKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	block, err := ssh.MarshalPrivateKey(priv, "sandbox-library sandbox key")
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	privateKeyPEM = string(pem.EncodeToMemory(block))
	return authorizedKey, privateKeyPEM, nil
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
	refreshed, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.syncAllowedPorts(ctx, refreshed)
	return refreshed, nil
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
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("audit sandbox destroyed", "sandbox_id", id, "image", sandbox.Image)
	return nil
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

	if updated, err := s.store.Get(ctx, id); err == nil {
		s.syncAllowedPorts(ctx, updated)
	}
	return publicURL, nil
}

func (s *Service) UnexposePort(ctx context.Context, id string, port int) error {
	if err := s.caddy.DeletePortRoute(ctx, id, port); err != nil {
		return err
	}
	if err := s.store.DeletePort(ctx, id, port); err != nil {
		return err
	}
	if updated, err := s.store.Get(ctx, id); err == nil {
		s.syncAllowedPorts(ctx, updated)
	}
	return nil
}

type ToolboxEndpoint struct {
	URL   string
	Token string
}

func (s *Service) ToolboxTarget(ctx context.Context, id string) (ToolboxEndpoint, error) {
	if err := s.TouchSandbox(ctx, id); err != nil {
		return ToolboxEndpoint{}, err
	}
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return ToolboxEndpoint{}, err
	}
	if sandbox.ContainerIP == "" {
		return ToolboxEndpoint{}, errors.New("sandbox container IP is not available")
	}
	return ToolboxEndpoint{
		URL:   fmt.Sprintf("http://%s:%d", sandbox.ContainerIP, s.cfg.ToolboxPort),
		Token: sandbox.ToolboxToken,
	}, nil
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

	knownIDs := make(map[string]struct{}, len(known))
	for _, sandbox := range known {
		knownIDs[sandbox.ID] = struct{}{}
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
			s.syncAllowedPorts(ctx, sandbox)
		}
		if err := s.store.Upsert(ctx, sandbox); err != nil {
			return err
		}
	}

	// Orphan containers: managed by us but no DB row. Remove them so leaked
	// state from a crashed create or a wiped DB doesn't accumulate.
	for sandboxID, runtime := range managed {
		if _, ok := knownIDs[sandboxID]; ok {
			continue
		}
		s.logger.Warn("removing orphan container",
			"sandbox_id", sandboxID,
			"container_id", runtime.ContainerID,
		)
		stub := &models.Sandbox{ContainerID: runtime.ContainerID, ContainerIP: runtime.ContainerIP}
		if err := s.docker.Destroy(ctx, stub); err != nil {
			s.logger.Warn("orphan container removal failed",
				"sandbox_id", sandboxID,
				"error", err,
			)
		}
		_ = s.caddy.DeleteSandboxRoute(ctx, sandboxID)
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
				sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				s.runIdleSweep(sweepCtx, idleTimeout)
				cancel()
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

func (s *Service) StartReconcileLoop(ctx context.Context) {
	interval := s.cfg.ReconcileInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				if err := s.Reconcile(reconcileCtx); err != nil {
					s.logger.Warn("periodic reconcile failed", "error", err)
				}
				cancel()
			}
		}
	}()
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

func generateToolboxToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// syncAllowedPorts pushes the sandbox's current set of exposed ports to
// toolboxd's in-memory allowlist. Best-effort — logged on failure. Without
// this, /proxy/<port>/ on the public sandbox URL refuses every request.
func (s *Service) syncAllowedPorts(ctx context.Context, sandbox *models.Sandbox) {
	if sandbox == nil || sandbox.Status != models.SandboxStatusStarted || sandbox.ContainerIP == "" {
		return
	}
	ports := make([]int, 0, len(sandbox.ExposedPorts))
	for _, p := range sandbox.ExposedPorts {
		ports = append(ports, p.Port)
	}
	if err := s.docker.PushAllowedPorts(ctx, sandbox.ContainerIP, sandbox.ToolboxToken, ports); err != nil {
		s.logger.Warn("failed to sync allowed ports", "sandbox_id", sandbox.ID, "error", err)
	}
}
