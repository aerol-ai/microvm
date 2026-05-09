package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/crypto/ssh"
)

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	store  *store.Store
	// docker holds the lifecycle-only runtime abstraction. The field name
	// stays "docker" because every existing call site is shaped around it;
	// the type is runtime.Runtime so a non-Docker driver can be slotted in
	// without touching service code.
	docker runtime.Runtime
	// events is the concrete Docker client for the daemon /events stream and
	// any other Docker-API-shaped surface that intentionally stays outside
	// the runtime abstraction. Today both fields point at the same instance.
	events   *docker.Client
	caddy    *caddy.Client
	cipher   *secrets.Cipher
	mounts   *mounts.Manager
	admitter *capacity.Admitter
}

func New(cfg config.Config, logger *slog.Logger, db *store.Store, runtimeDriver runtime.Runtime, eventsClient *docker.Client, caddyClient *caddy.Client, cipher *secrets.Cipher, mountManager *mounts.Manager, admitter *capacity.Admitter) *Service {
	return &Service{
		cfg:      cfg,
		logger:   logger,
		store:    db,
		docker:   runtimeDriver,
		events:   eventsClient,
		caddy:    caddyClient,
		cipher:   cipher,
		mounts:   mountManager,
		admitter: admitter,
	}
}

func (s *Service) CreateSandbox(ctx context.Context, req models.CreateSandboxRequest) (*models.CreateSandboxResponse, error) {
	req = normalizeCreateRequest(req)
	if req.Image == "" {
		return nil, errors.New("image is required")
	}

	// Validate the requested runtime and resolve "" to the host default. We
	// write the resolved value back into req so the runtime layer sees an
	// explicit choice and the persisted sandbox row records what was actually
	// used — empty stays empty only on pre-migration rows.
	chosenRuntime, err := models.ValidRuntime(req.Runtime)
	if err != nil {
		return nil, err
	}
	if chosenRuntime == "" {
		chosenRuntime = s.cfg.Runtime
	}
	// "kata" is reserved as a future runtime. Accept it through validation
	// (so operators can pre-stage the host default) but reject individual
	// create requests until the runtime is wired up. Surfaced as a clear
	// 4xx-shaped error so clients see "not implemented" rather than a
	// generic Docker failure 30s later.
	if chosenRuntime == models.RuntimeKata {
		return nil, fmt.Errorf("runtime %q: %w", chosenRuntime, models.ErrRuntimeNotImplemented)
	}
	req.Runtime = chosenRuntime

	if len(req.Mounts) > models.MaxMountsPerSandbox {
		return nil, fmt.Errorf("too many mounts: max %d", models.MaxMountsPerSandbox)
	}
	for i := range req.Mounts {
		if err := req.Mounts[i].Validate(s.cfg.ToolboxMountPath); err != nil {
			return nil, fmt.Errorf("mount %d: %w", i, err)
		}
	}

	var lifecycle models.Lifecycle
	if req.Lifecycle != nil {
		if err := req.Lifecycle.Validate(); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
		lifecycle = *req.Lifecycle
	}

	if req.GPUs != nil {
		if err := req.GPUs.Validate(); err != nil {
			return nil, fmt.Errorf("invalid gpu request: %w", err)
		}
	}

	sealedMounts, err := s.sealMounts(req.Mounts)
	if err != nil {
		return nil, err
	}

	toolboxToken, err := generateToolboxToken()
	if err != nil {
		return nil, fmt.Errorf("generate toolbox token: %w", err)
	}

	authorizedKey, privateKeyPEM, err := generateSandboxSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("generate ssh keypair: %w", err)
	}

	// Choose the sandbox ID up-front so we have stable host paths to bind
	// before docker.Create runs. The ID also becomes the container's name.
	sandboxID, err := generateSandboxID()
	if err != nil {
		return nil, fmt.Errorf("generate sandbox id: %w", err)
	}

	// Admission check uses normalized values (req.CPU/MemoryMB are guaranteed
	// > 0 by normalizeCreateRequest above), so a default-sized request still
	// counts against the host budget. Reservation happens here; every failure
	// path below must release it.
	if s.admitter != nil {
		if err := s.admitter.Admit(sandboxID, capacity.Request{
			CPU:      req.CPU,
			MemoryMB: req.MemoryMB,
		}); err != nil {
			return nil, err
		}
	}
	releaseAdmission := func() {
		if s.admitter != nil {
			s.admitter.Release(sandboxID)
		}
	}

	binds, err := s.mounts.MountAll(ctx, sandboxID, req.Mounts)
	if err != nil {
		releaseAdmission()
		return nil, fmt.Errorf("mount external storage: %w", err)
	}
	cleanupMounts := func() {
		if err := s.mounts.UnmountAll(sandboxID); err != nil {
			s.logger.Warn("cleanup unmount failed", "sandbox_id", sandboxID, "error", err)
		}
	}

	state, err := s.docker.Create(ctx, req, sandboxID, toolboxToken, binds)
	if err != nil {
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:               state.SandboxID,
		Image:            req.Image,
		Status:           state.Status,
		PublicURL:        s.caddy.SandboxPublicURL(state.SandboxID),
		ContainerID:      state.ContainerID,
		ContainerIP:      state.ContainerIP,
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
		Lifecycle:        lifecycle,
		Runtime:          chosenRuntime,
		GPUs:             req.GPUs,
	}

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort); err != nil {
		_ = s.docker.Destroy(ctx, sandbox)
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	if err := s.store.Create(ctx, sandbox); err != nil {
		_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
		_ = s.docker.Destroy(ctx, sandbox)
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	if len(sealedMounts) > 0 {
		if err := s.store.PutMounts(ctx, sandbox.ID, sealedMounts); err != nil {
			_ = s.store.Delete(ctx, sandbox.ID)
			_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
			_ = s.docker.Destroy(ctx, sandbox)
			cleanupMounts()
			releaseAdmission()
			return nil, fmt.Errorf("persist sandbox mounts: %w", err)
		}
	}

	s.logger.Info("audit sandbox created",
		"sandbox_id", sandbox.ID,
		"image", sandbox.Image,
		"cpu", sandbox.CPU,
		"memory_mb", sandbox.MemoryMB,
		"disk_gb", sandbox.DiskGB,
		"network_block_all", sandbox.NetworkBlockAll,
		"mount_count", len(req.Mounts),
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

// sealMounts marshals the user's mount specs and encrypts the JSON for
// at-rest storage. Returns nil when there are no mounts.
func (s *Service) sealMounts(specs []models.MountSpec) ([]byte, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	plain, err := json.Marshal(models.MountSpecFile{Mounts: specs})
	if err != nil {
		return nil, fmt.Errorf("marshal mounts: %w", err)
	}
	sealed, err := s.cipher.Encrypt(plain)
	if err != nil {
		return nil, fmt.Errorf("encrypt mounts: %w", err)
	}
	return sealed, nil
}

// loadMounts reads, decrypts, and unmarshals a sandbox's stored mount specs.
// Returns nil, nil when the sandbox has no mounts.
func (s *Service) loadMounts(ctx context.Context, sandboxID string) ([]models.MountSpec, error) {
	sealed, err := s.store.GetMounts(ctx, sandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := s.cipher.Decrypt(sealed)
	if err != nil {
		return nil, fmt.Errorf("decrypt mounts: %w", err)
	}
	var file models.MountSpecFile
	if err := json.Unmarshal(plain, &file); err != nil {
		return nil, fmt.Errorf("unmarshal mounts: %w", err)
	}
	return file.Mounts, nil
}

// ListMounts returns the redacted mount config for a sandbox. Credentials are
// never included in the response — they are write-only via CreateSandbox.
func (s *Service) ListMounts(ctx context.Context, sandboxID string) ([]models.MountSpecRedacted, error) {
	if _, err := s.store.Get(ctx, sandboxID); err != nil {
		return nil, err
	}
	specs, err := s.loadMounts(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	return models.RedactMounts(specs), nil
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
	block, err := ssh.MarshalPrivateKey(priv, "AerolVM sandbox key")
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

	specs, err := s.loadMounts(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(specs) > 0 {
		if err := s.mounts.Reestablish(ctx, id, specs); err != nil {
			return nil, fmt.Errorf("reestablish mounts: %w", err)
		}
	}

	state, err := s.docker.Start(ctx, sandboxContainerRef(sandbox))
	if err != nil {
		_ = s.mounts.UnmountAll(id)
		_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
		return nil, err
	}

	sandbox.ContainerID = state.ContainerID
	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
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
	if err := s.mounts.UnmountAll(id); err != nil {
		s.logger.Warn("unmount on stop failed", "sandbox_id", id, "error", err)
	}
	// Drop the Caddy routes while the container is down so requests hit the
	// fallback "sandbox not found" handler instead of a 502 from a stale
	// upstream IP. StartSandbox re-upserts every route on the way back up.
	for _, port := range sandbox.ExposedPorts {
		if err := s.caddy.DeletePortRoute(ctx, sandbox.ID, port.Port); err != nil {
			s.logger.Warn("caddy port route cleanup on stop failed", "sandbox_id", id, "port", port.Port, "error", err)
		}
	}
	if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		s.logger.Warn("caddy route cleanup on stop failed", "sandbox_id", id, "error", err)
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
	if err := s.mounts.UnmountAll(id); err != nil {
		s.logger.Warn("unmount on destroy failed", "sandbox_id", id, "error", err)
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	if s.admitter != nil {
		s.admitter.Release(id)
	}
	s.logger.Info("audit sandbox destroyed", "sandbox_id", id, "image", sandbox.Image)
	s.maybeRemoveImage(ctx, sandbox.Image)
	return nil
}

func (s *Service) ResizeSandbox(ctx context.Context, id string, req models.ResizeSandboxRequest) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decide what the post-resize footprint will be and re-admit against it
	// before mutating Docker. Admit is idempotent per ID — it computes the
	// delta against the existing reservation, so a downsize will free budget
	// and an upsize that exceeds the budget is rejected with no changes.
	if s.admitter != nil {
		newCPU := sandbox.CPU
		newMem := sandbox.MemoryMB
		if req.CPU > 0 {
			newCPU = req.CPU
		}
		if req.MemoryMB > 0 {
			newMem = req.MemoryMB
		}
		if newCPU != sandbox.CPU || newMem != sandbox.MemoryMB {
			if err := s.admitter.Admit(id, capacity.Request{CPU: newCPU, MemoryMB: newMem}); err != nil {
				return nil, err
			}
		}
	}

	if err := s.docker.Resize(ctx, sandboxContainerRef(sandbox), req); err != nil {
		// Restore the prior reservation; the resize did not actually take
		// effect on the container, so accounting must reflect the unchanged
		// footprint.
		if s.admitter != nil {
			s.admitter.Reserve(id, capacity.Request{CPU: sandbox.CPU, MemoryMB: sandbox.MemoryMB})
		}
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

// UpdateLifecycle replaces the lifecycle timers on an existing sandbox.
// Full-replacement semantics: pass zero in any field to clear that timer.
// The sweep picks up the new values on its next tick (within ~1 minute),
// so a tightened deadline can fire as soon as the next sweep runs.
func (s *Service) UpdateLifecycle(ctx context.Context, id string, l models.Lifecycle) (*models.Sandbox, error) {
	if err := l.Validate(); err != nil {
		return nil, fmt.Errorf("invalid lifecycle: %w", err)
	}
	if err := s.store.UpdateLifecycle(ctx, id, l); err != nil {
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

	live := 0
	for _, sandbox := range sandboxes {
		if sandbox.Status != models.SandboxStatusDestroyed {
			live++
		}
	}

	dockerStatus := "ok"
	if err := s.docker.Ping(ctx); err != nil {
		dockerStatus = err.Error()
	}

	caddyStatus := "ok"
	if err := s.caddy.Ping(ctx); err != nil {
		caddyStatus = err.Error()
	}

	// "disabled" is distinct from "ok" / failure — it tells the operator
	// "we didn't probe this on purpose" rather than masking a real fault.
	sshStatus := "disabled"
	if s.cfg.EnableSSHGateway {
		if err := probeSSHGateway(ctx, s.cfg.SSHListenAddr); err != nil {
			sshStatus = err.Error()
		} else {
			sshStatus = "ok"
		}
	}

	status := "ok"
	if dockerStatus != "ok" || caddyStatus != "ok" {
		status = "degraded"
	}
	// SSH gateway being down only degrades health when it's expected to be up.
	if s.cfg.EnableSSHGateway && sshStatus != "ok" {
		status = "degraded"
	}

	return models.HealthStatus{
		Status:     status,
		Sandboxes:  live,
		Docker:     dockerStatus,
		Caddy:      caddyStatus,
		SSHGateway: sshStatus,
		Version:    version.Version,
	}, nil
}

// Capacity returns the admitter's current snapshot. Returns the zero value
// when no admitter is configured (e.g. in tests).
func (s *Service) Capacity() capacity.Snapshot {
	if s.admitter == nil {
		return capacity.Snapshot{CanAdmit: true}
	}
	return s.admitter.Snapshot()
}

// ReplayReservations re-populates the admitter from persistent state. Without
// this, after a daemon restart the admitter sees zero reservations and the
// host can be overcommitted on the first wave of new sandboxes. Destroyed
// sandboxes are skipped — they still occupy a row but no longer hold
// resources. Best-effort: a store error is logged, not returned, since
// admission control degrading to "unaware" is preferable to refusing to
// boot.
func (s *Service) ReplayReservations(ctx context.Context) {
	if s.admitter == nil {
		return
	}
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("replay reservations: list failed", "error", err)
		return
	}
	replayed := 0
	for _, sandbox := range sandboxes {
		if sandbox.Status == models.SandboxStatusDestroyed {
			continue
		}
		s.admitter.Reserve(sandbox.ID, capacity.Request{
			CPU:      sandbox.CPU,
			MemoryMB: sandbox.MemoryMB,
		})
		replayed++
	}
	s.logger.Info("capacity reservations replayed", "count", replayed)
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
		state, ok := managed[sandbox.ID]
		if !ok {
			previousStatus := sandbox.Status
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
			_ = s.mounts.UnmountAll(sandbox.ID)
			// Only GC and release admitter capacity on the transition into
			// destroyed — a row that was already destroyed at the start of
			// this reconcile pass already had its chance, and re-running the
			// check on every tick would be wasted work. Without the Release
			// here, capacity reservations leak when a container disappears
			// out-of-band (manual `docker rm`, OOM kill, host reboot) and
			// the admitter eventually refuses new sandboxes.
			if previousStatus != models.SandboxStatusDestroyed {
				if s.admitter != nil {
					s.admitter.Release(sandbox.ID)
				}
				s.maybeRemoveImage(ctx, sandbox.Image)
			}
			continue
		}

		sandbox.ContainerID = state.ContainerID
		sandbox.ContainerIP = state.ContainerIP
		sandbox.Status = state.Status
		sandbox.PublicURL = s.caddy.SandboxPublicURL(sandbox.ID)
		sandbox.UpdatedAt = time.Now().UTC()
		if state.Status == models.SandboxStatusStarted {
			if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort); err != nil {
				return err
			}
			for _, port := range sandbox.ExposedPorts {
				if err := s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port.Port); err != nil {
					return err
				}
			}
			s.syncAllowedPorts(ctx, sandbox)
			// Re-establish host-side mounts for running sandboxes after a
			// sandboxd restart. Idempotent — only mounts that aren't already
			// tracked are spawned.
			if specs, err := s.loadMounts(ctx, sandbox.ID); err != nil {
				s.logger.Warn("load mounts during reconcile", "sandbox_id", sandbox.ID, "error", err)
			} else if len(specs) > 0 {
				if err := s.mounts.Reestablish(ctx, sandbox.ID, specs); err != nil {
					s.logger.Warn("reestablish mounts", "sandbox_id", sandbox.ID, "error", err)
				}
			}
		}
		if err := s.store.Upsert(ctx, sandbox); err != nil {
			return err
		}
	}

	// Orphan containers: managed by us but no DB row. Remove them so leaked
	// state from a crashed create or a wiped DB doesn't accumulate.
	for sandboxID, state := range managed {
		if _, ok := knownIDs[sandboxID]; ok {
			continue
		}
		s.logger.Warn("removing orphan container",
			"sandbox_id", sandboxID,
			"container_id", state.ContainerID,
		)
		stub := &models.Sandbox{ContainerID: state.ContainerID, ContainerIP: state.ContainerIP}
		if err := s.docker.Destroy(ctx, stub); err != nil {
			s.logger.Warn("orphan container removal failed",
				"sandbox_id", sandboxID,
				"error", err,
			)
		}
		_ = s.caddy.DeleteSandboxRoute(ctx, sandboxID)
		_ = s.mounts.UnmountAll(sandboxID)
	}

	// Stale-mount sweep. Anything under /var/lib/sandboxd/mounts/ that
	// doesn't correspond to a sandbox we're going to keep is a leftover
	// from a crashed create or a previous orphan removal. Kill any FUSE
	// process still attached and remove the directory tree. Mounts the
	// manager already tracks in-process are skipped inside Sweep itself.
	keep := make(map[string]struct{}, len(managed))
	for id, state := range managed {
		if state.Status == models.SandboxStatusStarted {
			keep[id] = struct{}{}
		}
	}
	s.mounts.Sweep(keep)

	// Optional row-level GC. Disabled by default (TTL=0): destroyed rows
	// stay forever as an audit record. When enabled, anything in destroyed
	// status that last transitioned more than TTL ago is deleted. Image GC
	// has already had its turn on this tick, so a row being purged here is
	// either holding the last reference to an image we already removed, or
	// to one another live sandbox is keeping pinned — both are safe.
	if ttl := s.cfg.DestroyedRowTTL; ttl > 0 {
		cutoff := time.Now().UTC().Add(-ttl)
		purged, err := s.store.PurgeDestroyedBefore(ctx, cutoff)
		if err != nil {
			s.logger.Warn("destroyed row purge failed", "error", err)
		} else if purged > 0 {
			s.logger.Info("audit destroyed rows purged",
				"count", purged,
				"older_than", ttl.String(),
			)
		}
	}

	return nil
}

// StartLifecycleSweep launches the per-sandbox lifecycle ticker. Every minute
// it evaluates each sandbox's Lifecycle timers (StopIfIdleFor / DestroyIfIdleFor
// / StopAtAge / DestroyAtAge) plus the legacy global SB_IDLE_TIMEOUT_MIN
// fallback for sandboxes that don't declare any per-sandbox timers. Without
// either configured, the sweep still runs but is a no-op — kept on so a
// later UpdateLifecycle call doesn't need to start a goroutine.
func (s *Service) StartLifecycleSweep(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				s.runLifecycleSweep(sweepCtx)
				cancel()
			}
		}
	}()
}

func (s *Service) runLifecycleSweep(ctx context.Context) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("lifecycle sweep failed", "error", err)
		return
	}

	now := time.Now().UTC()
	globalIdle := s.cfg.IdleTimeout()
	for _, sandbox := range sandboxes {
		switch lifecycleActionFor(sandbox, now, globalIdle) {
		case lifecycleDestroy:
			if err := s.DestroySandbox(ctx, sandbox.ID); err != nil {
				s.logger.Warn("auto-destroy failed", "sandbox_id", sandbox.ID, "error", err)
			} else {
				s.logger.Info("audit lifecycle auto-destroy", "sandbox_id", sandbox.ID)
			}
		case lifecycleStop:
			if _, err := s.StopSandbox(ctx, sandbox.ID); err != nil {
				s.logger.Warn("auto-stop failed", "sandbox_id", sandbox.ID, "error", err)
			} else {
				s.logger.Info("audit lifecycle auto-stop", "sandbox_id", sandbox.ID)
			}
		}
	}
}

type lifecycleAction int

const (
	lifecycleNone lifecycleAction = iota
	lifecycleStop
	lifecycleDestroy
)

// lifecycleActionFor decides what the sweep should do for one sandbox given
// the current time and the operator's global idle fallback. Pure function:
// no DB, no Docker, easy to exhaustively test.
//
// Priority rules:
//  1. Already destroyed → none. The sweep cannot un-destroy or further
//     destroy something already gone.
//  2. Any destroy timer fired → destroy. Destroy supersedes stop on the
//     same tick to avoid a wasted Stop call followed by Destroy.
//  3. Any stop timer fired AND status is started → stop. Stopping an
//     already-stopped sandbox would be a no-op so we skip it.
//  4. No per-sandbox config and global SB_IDLE_TIMEOUT_MIN would fire →
//     stop. Backwards-compat with the pre-Lifecycle behavior.
//  5. Otherwise → none.
func lifecycleActionFor(sb *models.Sandbox, now time.Time, globalIdle time.Duration) lifecycleAction {
	if sb == nil || sb.Status == models.SandboxStatusDestroyed {
		return lifecycleNone
	}
	idle := now.Sub(sb.LastActiveAt)
	age := now.Sub(sb.CreatedAt)

	l := sb.Lifecycle
	// Destroy first: if any destroy condition is met we go straight there.
	if l.DestroyIfIdleFor > 0 && idle >= l.DestroyIfIdleFor {
		return lifecycleDestroy
	}
	if l.DestroyAtAge > 0 && age >= l.DestroyAtAge {
		return lifecycleDestroy
	}
	// Stop only applies to running sandboxes — re-stopping a stopped one
	// is wasted Docker calls and noisy logs.
	if sb.Status != models.SandboxStatusStarted {
		return lifecycleNone
	}
	if l.StopIfIdleFor > 0 && idle >= l.StopIfIdleFor {
		return lifecycleStop
	}
	if l.StopAtAge > 0 && age >= l.StopAtAge {
		return lifecycleStop
	}
	// Legacy global idle fallback: only applies when the sandbox has no
	// per-sandbox config, so an explicit "no auto-stop" Lifecycle (e.g.
	// just DestroyAtAge=24h with stop fields zero) doesn't accidentally
	// inherit the operator's global timeout.
	if l.IsZero() && globalIdle > 0 && idle >= globalIdle {
		return lifecycleStop
	}
	return lifecycleNone
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

// generateSandboxID returns a 16-hex-char sandbox identifier. It is used as
// both the daemon's primary key for the sandbox and the Docker container's
// name, so it must satisfy Docker's name restrictions ([a-zA-Z0-9_.-]).
func generateSandboxID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "sb-" + hex.EncodeToString(buf), nil
}

// imageStillReferenced reports whether any sandbox in the given slice still
// holds a live reference to image. A reference is "live" when the sandbox's
// status is anything other than destroyed — stopped, started, creating, and
// error all count, because their image is needed for a future start. The
// check is exact-match on the Image string, so a sandbox created with
// "alpine" and one with "alpine:latest" are treated as different images
// (matching the way Docker stores tags).
//
// This is the in-memory specification of the GC policy and is used in unit
// tests. Production callers go through Store.HasActiveImageRef so the check
// stays constant-cost as the destroyed-row history grows.
func imageStillReferenced(sandboxes []*models.Sandbox, image string) bool {
	if image == "" {
		return true
	}
	for _, sb := range sandboxes {
		if sb == nil {
			continue
		}
		if sb.Image == image && sb.Status != models.SandboxStatusDestroyed {
			return true
		}
	}
	return false
}

// maybeRemoveImage deletes the given image from Docker if no non-destroyed
// sandbox still references it. Best-effort: store and Docker errors are
// logged, never returned, because image GC must not block the sandbox
// lifecycle path that called us. Uses Store.HasActiveImageRef so the cost
// is one indexed query rather than a full table scan, even when there are
// 10k+ destroyed rows in history.
func (s *Service) maybeRemoveImage(ctx context.Context, image string) {
	if image == "" {
		return
	}
	stillUsed, err := s.store.HasActiveImageRef(ctx, image)
	if err != nil {
		s.logger.Warn("image gc reference check failed", "image", image, "error", err)
		return
	}
	if stillUsed {
		return
	}
	if err := s.docker.RemoveImage(ctx, image); err != nil {
		s.logger.Warn("image gc remove failed", "image", image, "error", err)
		return
	}
	s.logger.Info("audit image removed", "image", image)
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

// probeSSHGateway opens a TCP connection to the gateway's listen address with
// a short timeout. We don't speak the SSH handshake — connect is enough to
// distinguish "process is up and accepting" from "wedged or never started."
// Listener is bound to 0.0.0.0 in production; we dial 127.0.0.1 explicitly so
// we don't depend on the box having a public IP.
func probeSSHGateway(ctx context.Context, listenAddr string) error {
	if listenAddr == "" {
		return errors.New("ssh listen addr is empty")
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid ssh listen addr %q: %w", listenAddr, err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return fmt.Errorf("ssh gateway dial: %w", err)
	}
	_ = conn.Close()
	return nil
}
