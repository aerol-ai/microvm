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
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

// allocatorRandomAttempts caps the random-first phase of host-port allocation.
// With a 10k-port pool and a few hundred allocations live, collisions are
// rare; the linear-scan fallback only runs when the pool is genuinely
// near-full, so this keeps p95 low without spinning forever in tight pools.
const allocatorRandomAttempts = 16

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
	// l4Ready latches true once caddy.EnsureLayer4 has succeeded — either at
	// boot or lazily on the first TCP/TLS expose call. Boot bootstrap is
	// best-effort (caddy may not be reachable yet on a cold start), so the
	// expose path retries under l4Mu when the latch is still false. atomic
	// load gives a lock-free fast path on the steady-state hot path.
	l4Mu    sync.Mutex
	l4Ready atomic.Bool
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
		if err := s.upsertExposedPortRoute(ctx, sandbox, port); err != nil {
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
		if err := s.deleteExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("caddy port route cleanup on stop failed", "sandbox_id", id, "port", port.Port, "protocol", port.Protocol, "error", err)
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
		_ = s.deleteExposedPortRoute(ctx, sandbox, port)
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

// ExposePort publishes a sandbox container port through one of three caddy
// surfaces, selected by protocol:
//   - "" / "http": existing Caddy HTTP reverse-proxy route, returns
//     https://<id>-<port>.<domain> (or the path-mode equivalent).
//   - "tcp": allocates a parent-host TCP port from the [SB_L4_PORT_RANGE_START,
//     SB_L4_PORT_RANGE_END] pool, points caddy-l4 at it, and returns
//     tcp://<public-host>:<host-port>. This is what unblocks native Postgres /
//     Redis / MySQL DSNs in the spawn-postgres docs.
//   - "tls": adds a TLS-SNI route to the shared layer4 server. Requires
//     --domain (so the SNI hostname has a place to resolve) and a non-empty
//     SB_L4_TLS_LISTEN. Returns tls://<id>-<port>.<domain>:<l4-port>.
func (s *Service) ExposePort(ctx context.Context, id string, port int, protocol string) (string, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if port <= 0 || port > 65535 {
		return "", errors.New("invalid port")
	}
	canonicalProto, err := models.ValidExposedPortProtocol(protocol)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	switch canonicalProto {
	case models.ExposedPortProtocolHTTP:
		publicURL := s.caddy.PortPublicURL(id, port)
		if err := s.caddy.UpsertPortRoute(ctx, id, sandbox.ContainerIP, port); err != nil {
			return "", err
		}
		exposure := models.ExposedPort{
			SandboxID: id,
			Port:      port,
			Protocol:  canonicalProto,
			PublicURL: publicURL,
			CreatedAt: now,
		}
		if err := s.store.UpsertPort(ctx, exposure); err != nil {
			_ = s.caddy.DeletePortRoute(ctx, id, port)
			return "", err
		}
		s.touchAllowedPorts(ctx, id)
		return publicURL, nil

	case models.ExposedPortProtocolTCP:
		// Lazy bootstrap: boot's EnsureLayer4 is best-effort, so retry here
		// in case caddy was not reachable at start-up. Idempotent and cheap
		// after the first success (atomic load).
		if err := s.EnsureLayer4Ready(ctx); err != nil {
			return "", err
		}
		// Fast-path idempotency: a re-expose for an already-TCP port reuses
		// the existing host_port reservation. Without this, the allocator
		// would loop on PK collisions in TryReserveHostPort and exhaust the
		// pool. A different protocol on the same (id, port) is rejected
		// outright — the caller must unexpose first to switch protocols.
		if existing := findExposure(sandbox, port); existing != nil {
			if existing.Protocol != models.ExposedPortProtocolTCP {
				return "", fmt.Errorf("port %d already exposed as %s; unexpose it first", port, existing.Protocol)
			}
			if existing.HostPort > 0 {
				if err := s.caddy.UpsertTCPRoute(ctx, id, sandbox.ContainerIP, port, existing.HostPort); err != nil {
					return "", err
				}
				s.touchAllowedPorts(ctx, id)
				return existing.PublicURL, nil
			}
		}
		hostPort, publicURL, reused, err := s.allocateHostPort(ctx, id, port, now)
		if err != nil {
			return "", err
		}
		if err := s.caddy.UpsertTCPRoute(ctx, id, sandbox.ContainerIP, port, hostPort); err != nil {
			// Only roll back rows we ourselves inserted. A reused row was
			// installed by a concurrent caller and is not ours to delete.
			if !reused {
				_ = s.store.DeletePort(ctx, id, port)
			}
			return "", err
		}
		s.touchAllowedPorts(ctx, id)
		return publicURL, nil

	case models.ExposedPortProtocolTLS:
		sniHost := s.caddy.SNIHost(id, port)
		if sniHost == "" {
			return "", errors.New("TLS-SNI exposure requires --domain to be configured")
		}
		if s.caddy.L4TLSListen() == "" {
			return "", errors.New("TLS-SNI exposure requires SB_L4_TLS_LISTEN to be set")
		}
		// Lazy bootstrap: retry here so a failed boot doesn't break the
		// first TLS-SNI exposure. The shared SNI mux server lives inside
		// the layer4 app, so this is the gate before any UpsertTLSSNIRoute.
		if err := s.EnsureLayer4Ready(ctx); err != nil {
			return "", err
		}
		publicURL := s.caddy.TLSPublicEndpoint(id, port, s.caddy.L4TLSListen())
		if err := s.caddy.UpsertTLSSNIRoute(ctx, id, sniHost, sandbox.ContainerIP, port); err != nil {
			return "", err
		}
		exposure := models.ExposedPort{
			SandboxID: id,
			Port:      port,
			Protocol:  canonicalProto,
			PublicURL: publicURL,
			CreatedAt: now,
		}
		if err := s.store.UpsertPort(ctx, exposure); err != nil {
			_ = s.caddy.DeleteTLSSNIRoute(ctx, id, port)
			return "", err
		}
		s.touchAllowedPorts(ctx, id)
		return publicURL, nil
	}
	return "", fmt.Errorf("unhandled protocol %q", canonicalProto)
}

// EnsureLayer4Ready bootstraps the caddy-l4 app under a single-flight
// mutex and latches success. Safe to call from boot AND from each L4
// exposure path: the atomic fast-path turns it into a single load on the
// steady state, and a failed boot is recovered by the very next TCP/TLS
// expose call instead of surfacing as a confusing "layer4 app missing"
// error from caddy.
func (s *Service) EnsureLayer4Ready(ctx context.Context) error {
	if s.l4Ready.Load() {
		return nil
	}
	s.l4Mu.Lock()
	defer s.l4Mu.Unlock()
	if s.l4Ready.Load() {
		return nil
	}
	if err := s.caddy.EnsureLayer4(ctx, s.cfg.L4TLSListen, s.cfg.L4TLSFallback); err != nil {
		return fmt.Errorf("bootstrap caddy layer4: %w", err)
	}
	s.l4Ready.Store(true)
	return nil
}

// allocateHostPort reserves a parent-host port for a raw-TCP exposure. The
// random-first phase tries up to allocatorRandomAttempts candidates from the
// configured pool — each attempt is one INSERT OR IGNORE protected by the
// partial unique index on host_port, so concurrent allocators serialize at
// the DB without a process-level lock. When randoms collide enough times we
// fall back to a deterministic linear scan, which is the p99 path that
// guarantees we exhaust the pool before giving up.
//
// Returns reused=true when a concurrent caller installed the (sandbox_id,
// port) row first; the returned host_port and public URL come from that
// existing row. The flag lets the caller skip rollback on caddy failures so
// it doesn't delete a row it didn't create.
func (s *Service) allocateHostPort(ctx context.Context, sandboxID string, containerPort int, now time.Time) (hostPort int, publicURL string, reused bool, err error) {
	if s.cfg.L4PortRangeEnd <= s.cfg.L4PortRangeStart {
		return 0, "", false, errors.New("L4 port pool is misconfigured")
	}
	span := s.cfg.L4PortRangeEnd - s.cfg.L4PortRangeStart + 1

	tryCandidate := func(candidate int) (int, string, bool, bool, error) {
		candidateURL := s.caddy.TCPPublicEndpoint(candidate)
		result, err := s.store.TryReserveHostPort(ctx, sandboxID, containerPort, candidate, models.ExposedPortProtocolTCP, candidateURL, now)
		if err != nil {
			return 0, "", false, false, err
		}
		if result.Reserved {
			return candidate, candidateURL, false, true, nil
		}
		if result.Existing != nil {
			// Race: a concurrent ExposePort installed the row first. Reuse
			// when protocols match; otherwise refuse (avoids the pool walk
			// AND prevents silently leaking the prior route).
			if result.Existing.Protocol != models.ExposedPortProtocolTCP {
				return 0, "", false, false, fmt.Errorf("port %d already exposed as %s; unexpose it first", containerPort, result.Existing.Protocol)
			}
			if result.Existing.HostPort > 0 {
				return result.Existing.HostPort, result.Existing.PublicURL, true, true, nil
			}
		}
		return 0, "", false, false, nil
	}

	for i := 0; i < allocatorRandomAttempts; i++ {
		candidate := s.cfg.L4PortRangeStart + mathrand.Intn(span)
		hp, url, r, done, terr := tryCandidate(candidate)
		if terr != nil {
			return 0, "", false, terr
		}
		if done {
			return hp, url, r, nil
		}
	}

	for candidate := s.cfg.L4PortRangeStart; candidate <= s.cfg.L4PortRangeEnd; candidate++ {
		hp, url, r, done, terr := tryCandidate(candidate)
		if terr != nil {
			return 0, "", false, terr
		}
		if done {
			return hp, url, r, nil
		}
	}
	return 0, "", false, errors.New("L4 port pool exhausted")
}

func (s *Service) UnexposePort(ctx context.Context, id string, port int) error {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	exposure := findExposure(sandbox, port)
	// Best-effort tear-down of every caddy surface the exposure could be on.
	// We dispatch on the recorded protocol when it's known, but also fall
	// back to the legacy HTTP path so old rows that pre-date the protocol
	// column are still cleaned up correctly.
	if exposure == nil {
		_ = s.caddy.DeletePortRoute(ctx, id, port)
	} else {
		if err := s.deleteExposedPortRoute(ctx, sandbox, *exposure); err != nil {
			return err
		}
	}
	if err := s.store.DeletePort(ctx, id, port); err != nil {
		return err
	}
	s.touchAllowedPorts(ctx, id)
	return nil
}

// findExposure returns the exposure matching port, or nil. Linear scan is
// fine because ExposedPorts is bounded by the host port pool size and in
// practice rarely exceeds a handful per sandbox.
func findExposure(sandbox *models.Sandbox, port int) *models.ExposedPort {
	if sandbox == nil {
		return nil
	}
	for i := range sandbox.ExposedPorts {
		if sandbox.ExposedPorts[i].Port == port {
			return &sandbox.ExposedPorts[i]
		}
	}
	return nil
}

// upsertExposedPortRoute republishes one exposure to caddy based on its
// stored protocol. Used everywhere a sandbox transitions to running
// (StartSandbox, Reconcile when a container is back, docker start events).
func (s *Service) upsertExposedPortRoute(ctx context.Context, sandbox *models.Sandbox, port models.ExposedPort) error {
	switch port.Protocol {
	case "", models.ExposedPortProtocolHTTP:
		return s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port.Port)
	case models.ExposedPortProtocolTCP:
		return s.caddy.UpsertTCPRoute(ctx, sandbox.ID, sandbox.ContainerIP, port.Port, port.HostPort)
	case models.ExposedPortProtocolTLS:
		return s.caddy.UpsertTLSSNIRoute(ctx, sandbox.ID, s.caddy.SNIHost(sandbox.ID, port.Port), sandbox.ContainerIP, port.Port)
	default:
		return fmt.Errorf("unknown protocol %q on exposed port %d", port.Protocol, port.Port)
	}
}

// deleteExposedPortRoute drops one exposure's caddy entity. Used everywhere
// a sandbox transitions out of running (StopSandbox, DestroySandbox, exit
// events, reconcile destroyed pass).
func (s *Service) deleteExposedPortRoute(ctx context.Context, sandbox *models.Sandbox, port models.ExposedPort) error {
	switch port.Protocol {
	case "", models.ExposedPortProtocolHTTP:
		return s.caddy.DeletePortRoute(ctx, sandbox.ID, port.Port)
	case models.ExposedPortProtocolTCP:
		return s.caddy.DeleteTCPRoute(ctx, port.HostPort)
	case models.ExposedPortProtocolTLS:
		return s.caddy.DeleteTLSSNIRoute(ctx, sandbox.ID, port.Port)
	default:
		return fmt.Errorf("unknown protocol %q on exposed port %d", port.Protocol, port.Port)
	}
}

// touchAllowedPorts is a small wrapper that refreshes the toolbox's allowlist
// after a port-table mutation. The store round-trip pulls the fresh ExposedPorts
// so syncAllowedPorts sees post-write state.
func (s *Service) touchAllowedPorts(ctx context.Context, id string) {
	if updated, err := s.store.Get(ctx, id); err == nil {
		s.syncAllowedPorts(ctx, updated)
	}
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
				_ = s.deleteExposedPortRoute(ctx, sandbox, port)
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
				if err := s.upsertExposedPortRoute(ctx, sandbox, port); err != nil {
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

	// Zombie caddy entry sweep. The destroyed-sandbox loop above already
	// drops routes for sandboxes that exist in the DB but lost their
	// container — this catches the orthogonal case where caddy holds an
	// entry for a sandbox row that was purged out (DB wipe, destroyed-row
	// TTL pass, manual surgery) and no destroy ran. Without this, caddy
	// accumulates dead routes forever.
	s.gcZombieCaddyEntries(ctx, known)

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

// gcZombieCaddyEntries deletes caddy routes/servers whose @id (or layer4
// server name) follows our convention but doesn't correspond to any live
// sandbox row. The DB is the source of truth; anything in caddy that doesn't
// trace back to a non-destroyed sandbox is a leak from one of:
//   - a sandbox row that was purged (DestroyedRowTTL).
//   - a development DB wipe leaving caddy with stale state.
//   - an out-of-band caddy admin call from a previous version of this code.
//
// Best-effort: every cleanup runs through a non-fatal path so a single
// failing DELETE doesn't abort the rest of the sweep. The legitimate-set
// computation excludes destroyed sandboxes — by the time this runs, the
// destroyed-loop earlier in Reconcile has already cleaned their routes.
func (s *Service) gcZombieCaddyEntries(ctx context.Context, sandboxes []*models.Sandbox) {
	if !s.caddy.Enabled() {
		return
	}
	snap, err := s.caddy.Snapshot(ctx)
	if err != nil {
		s.logger.Warn("caddy snapshot for zombie gc failed", "error", err)
		return
	}

	expectedHTTP := make(map[string]struct{})
	expectedTCPServers := make(map[string]struct{})
	expectedTLSRoutes := make(map[string]struct{})

	for _, sb := range sandboxes {
		if sb == nil || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		// The toolbox route lives at @id "sandbox-<id>"; per-port HTTP routes
		// at "sandbox-<id>-port-<p>". Keep both unconditionally — the rest
		// of Reconcile guarantees they're upserted for running sandboxes,
		// but stopped sandboxes intentionally lack routes and should still
		// not be GC'd here (they'll be rebuilt on Start).
		expectedHTTP["sandbox-"+sb.ID] = struct{}{}
		for _, p := range sb.ExposedPorts {
			switch p.Protocol {
			case "", models.ExposedPortProtocolHTTP:
				expectedHTTP[fmt.Sprintf("sandbox-%s-port-%d", sb.ID, p.Port)] = struct{}{}
			case models.ExposedPortProtocolTCP:
				if p.HostPort > 0 {
					expectedTCPServers[fmt.Sprintf("tcp-port-%d", p.HostPort)] = struct{}{}
				}
			case models.ExposedPortProtocolTLS:
				expectedTLSRoutes[fmt.Sprintf("sandbox-%s-port-%d-tls", sb.ID, p.Port)] = struct{}{}
			}
		}
	}

	for _, id := range snap.HTTPRouteIDs {
		if _, ok := expectedHTTP[id]; ok {
			continue
		}
		if err := s.caddy.DeleteRouteByID(ctx, id); err != nil {
			s.logger.Warn("zombie http route delete failed", "route_id", id, "error", err)
			continue
		}
		s.logger.Info("audit zombie http route removed", "route_id", id)
	}
	for _, sid := range snap.L4TCPServerIDs {
		if _, ok := expectedTCPServers[sid]; ok {
			continue
		}
		if err := s.caddy.DeleteTCPServer(ctx, sid); err != nil {
			s.logger.Warn("zombie tcp server delete failed", "server_id", sid, "error", err)
			continue
		}
		s.logger.Info("audit zombie tcp server removed", "server_id", sid)
	}
	for _, id := range snap.L4TLSRouteIDs {
		if _, ok := expectedTLSRoutes[id]; ok {
			continue
		}
		if err := s.caddy.DeleteRouteByID(ctx, id); err != nil {
			s.logger.Warn("zombie tls route delete failed", "route_id", id, "error", err)
			continue
		}
		s.logger.Info("audit zombie tls route removed", "route_id", id)
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
