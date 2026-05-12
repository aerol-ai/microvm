package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const defaultToolboxPort = 2280

type Config struct {
	PATToken            string
	APIHost             string
	APIPort             int
	Domain              string
	PublicHost          string
	CaddyAdminURL       string
	CaddyServerID       string
	DBPath              string
	DockerNetwork       string
	ToolboxBinaryPath   string
	ToolboxMountPath    string
	ToolboxPort         int
	IdleTimeoutMinutes  int
	ContainerPrivileged bool
	ResourceLimitsOff   bool
	// Runtime is the host default container runtime for new sandboxes.
	// Per-sandbox CreateSandboxRequest.Runtime overrides it. Allowed values
	// are "docker" (default), "gvisor", or "kata"; validation lives in Load().
	Runtime string
	AutoReconcile       bool
	EnableCaddy         bool
	EnableNetworkRules  bool
	EnableEventMonitor  bool
	EnableSSHGateway    bool
	SSHListenAddr       string
	SSHHostKeyPath      string
	CredentialEncryptionKey     string
	CredentialEncryptionKeyPath string
	MountsRootPath              string
	MountsCredentialsRuntimeDir string
	MountWaitTimeout            time.Duration
	LogLevel                 string
	ShutdownTimeout          time.Duration
	HTTPClientTimeout        time.Duration
	DockerRuntimeWaitTimeout time.Duration
	ToolboxWaitTimeout       time.Duration
	ReconcileInterval        time.Duration
	UploadMaxBytes           int64

	// Admission control. Admission is purely resource-math: CPU/memory
	// reservation ratios plus a live memory floor. There is no fixed sandbox
	// count cap — the host runs as many sandboxes as the math allows.
	CPUReservationRatio    float64
	MemoryReservationRatio float64
	MemoryFloorRatio       float64
	// CPUOverProvisionFactor and MemoryOverProvisionFactor multiply the
	// reservation budgets above. Docker --cpus is a CFS cap (not a hard
	// reservation) and Linux lazy-allocates memory pages, so a host with
	// mostly-idle sandboxes can safely accept far more reservations than its
	// nominal capacity. The live MemoryFloorRatio check is the backstop that
	// catches real pressure when reservations and reality diverge. 0 or <1
	// is clamped to 1.0 (no overcommit) — operators that want strict packing
	// should lower the reservation ratios instead.
	CPUOverProvisionFactor    float64
	MemoryOverProvisionFactor float64
	HostCPUCoresOverride      int
	HostMemoryMBOverride      int

	// L4PortRangeStart / L4PortRangeEnd bound the parent-host port pool that
	// raw-TCP sandbox exposures (caddy-l4) are allocated from. The allocator
	// picks a random candidate first; collisions fall back to a deterministic
	// scan. Both sides are inclusive.
	//
	// The default range [22000, 23000] sits ABOVE the Linux registered-ports
	// boundary (1024) and BELOW the default ephemeral-port range
	// (net.ipv4.ip_local_port_range, typically 32768-60999). Keeping the pool
	// out of the ephemeral range matters: if these ports overlapped, the
	// kernel could hand any of them to an unrelated outbound connection as a
	// source port, and the next L4 expose attempt to bind() that number would
	// race-fail with EADDRINUSE. 1000 slots is the deliberate concurrent-TCP-
	// exposure cap per host; raise it via the env vars if you need more, but
	// keep both bounds outside the host's ephemeral range.
	L4PortRangeStart int
	L4PortRangeEnd   int
	// L4TLSListen is the listen address for the shared TLS-SNI multiplexer.
	// Empty disables TLS-SNI exposure entirely (the daemon will reject
	// protocol="tls" requests). When set, caddy-l4 binds this address and
	// routes by SNI to per-sandbox subdomains.
	//
	// install.sh sets this to ":443" in domain mode (which always uses
	// DNS-01 wildcard issuance, so :443 is free of ACME traffic and caddy-l4
	// can own it). The HTTPS Caddy server is moved to 127.0.0.1:8443 in that
	// case. In IP/path mode (no --domain) this stays empty and caddy-l4
	// is never started.
	L4TLSListen string
	// L4TLSFallback is the local address caddy-l4 forwards a TLS connection
	// to when no per-sandbox SNI route matches — i.e. the regular HTTPS site
	// served by Caddy itself (sandbox API and the catch-all 404).
	// Required when L4TLSListen is non-empty; ignored otherwise. Default is
	// "127.0.0.1:8443" to match install.sh's relocated HTTPS listener.
	L4TLSFallback string

	// Cluster mode (Phase 1). When EnableCluster is false the daemon runs as
	// a standalone single-node sandbox runner — byte-identical to the legacy
	// behavior. When true, this node joins (or bootstraps) a Raft+gossip
	// cluster that owns the placement map (sandbox_id -> owner node). Each
	// sandbox is owned by exactly one node; the owner's local SQLite remains
	// the source of truth for sandbox state. Hot-path traffic (toolbox,
	// sessions, port forwards) is transparently reverse-proxied to the owner.
	EnableCluster            bool
	NodeID                   string
	RaftBindAddr             string
	RaftAdvertiseAddr        string
	RaftDataDir              string
	GossipBindAddr           string
	GossipAdvertiseAddr      string
	BootstrapPeers           []string
	ClusterBootstrap         bool
	SelfAPIAdvertiseURL      string
	ClusterRaftCommitTimeout time.Duration
	ClusterCapacityGossipInterval time.Duration
	// ClusterDeadOwnerGrace is how long the leader waits after memberlist marks
	// a node dead before orphaning its placements and removing it from the
	// raft configuration. Long enough to absorb transient gossip flap
	// (network blips, GC pauses) but short enough that operators don't have
	// to wait minutes to recover.
	ClusterDeadOwnerGrace time.Duration
	// ClusterGossipSecretKey, when non-empty, enables AES gossip encryption +
	// authentication. Accepts a base64-encoded 16/24/32-byte key (AES-128/192/256).
	// When empty, gossip is plaintext — acceptable only on a fully private
	// network, since voter auto-promotion will otherwise admit any reachable
	// peer to the raft configuration. SB_GOSSIP_SECRET_KEY.
	ClusterGossipSecretKey string
}

func Load() (Config, error) {
	exe, _ := os.Executable()
	defaultToolboxPath := filepath.Join(filepath.Dir(exe), "toolboxd")

	cfg := Config{
		PATToken:            strings.TrimSpace(os.Getenv("SB_PAT_TOKEN")),
		APIHost:             getEnv("SB_API_HOST", "0.0.0.0"),
		APIPort:             getEnvInt("SB_API_PORT", 21212),
		Domain:              normalizeHost(os.Getenv("SB_DOMAIN")),
		PublicHost:          normalizeHost(getEnv("SB_PUBLIC_HOST", "127.0.0.1")),
		CaddyAdminURL:       getEnv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:2019"),
		CaddyServerID:       getEnv("SB_CADDY_SERVER_ID", "srv0"),
		DBPath:              getEnv("SB_DB_PATH", "/var/lib/sandboxd/state.db"),
		DockerNetwork:       getEnv("SB_DOCKER_NETWORK", "bridge"),
		ToolboxBinaryPath:   getEnv("SB_TOOLBOX_BINARY_PATH", defaultToolboxPath),
		ToolboxMountPath:    getEnv("SB_TOOLBOX_MOUNT_PATH", "/usr/local/bin/toolboxd"),
		ToolboxPort:         getEnvInt("SB_TOOLBOX_PORT", defaultToolboxPort),
		IdleTimeoutMinutes:  getEnvInt("SB_IDLE_TIMEOUT_MIN", 0),
		ContainerPrivileged: getEnvBool("SB_CONTAINER_PRIVILEGED", false),
		ResourceLimitsOff:   getEnvBool("SB_RESOURCE_LIMITS_DISABLED", false),
		Runtime:             getEnv("SB_CONTAINER_RUNTIME", models.RuntimeDocker),
		AutoReconcile:       getEnvBool("SB_AUTO_RECONCILE", true),
		EnableCaddy:         getEnvBool("SB_ENABLE_CADDY", true),
		EnableNetworkRules:  getEnvBool("SB_ENABLE_NETWORK_RULES", true),
		EnableEventMonitor:  getEnvBool("SB_ENABLE_EVENT_MONITOR", true),
		EnableSSHGateway:    getEnvBool("SB_ENABLE_SSH_GATEWAY", true),
		SSHListenAddr:       getEnv("SB_SSH_LISTEN_ADDR", "0.0.0.0:2220"),
		SSHHostKeyPath:      getEnv("SB_SSH_HOST_KEY_PATH", "/var/lib/sandboxd/ssh_host_ed25519_key"),
		CredentialEncryptionKey:     strings.TrimSpace(os.Getenv("SB_CREDENTIAL_ENCRYPTION_KEY")),
		CredentialEncryptionKeyPath: getEnv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", "/var/lib/sandboxd/credential_encryption.key"),
		MountsRootPath:              getEnv("SB_MOUNTS_ROOT", "/var/lib/sandboxd/mounts"),
		MountsCredentialsRuntimeDir: getEnv("SB_MOUNTS_CRED_DIR", "/run/sandboxd"),
		MountWaitTimeout:            getEnvDuration("SB_MOUNT_WAIT_TIMEOUT", 30*time.Second),
		LogLevel:            strings.ToLower(getEnv("SB_LOG_LEVEL", "info")),
		ShutdownTimeout:          getEnvDuration("SB_SHUTDOWN_TIMEOUT", 10*time.Second),
		HTTPClientTimeout:        getEnvDuration("SB_HTTP_CLIENT_TIMEOUT", 60*time.Second),
		DockerRuntimeWaitTimeout: getEnvDuration("SB_DOCKER_WAIT_TIMEOUT", 30*time.Second),
		ToolboxWaitTimeout:       getEnvDuration("SB_TOOLBOX_WAIT_TIMEOUT", 30*time.Second),
		ReconcileInterval:        getEnvDuration("SB_RECONCILE_INTERVAL", 5*time.Minute),
		UploadMaxBytes:           int64(getEnvInt("SB_UPLOAD_MAX_BYTES", 256*1024*1024)),

		CPUReservationRatio:       getEnvFloat("SB_CPU_RESERVATION_RATIO", 0.9),
		MemoryReservationRatio:    getEnvFloat("SB_MEMORY_RESERVATION_RATIO", 0.85),
		MemoryFloorRatio:          getEnvFloat("SB_MEMORY_FLOOR_RATIO", 0.05),
		CPUOverProvisionFactor:    getEnvFloat("SB_CPU_OVERPROVISION_FACTOR", 10.0),
		MemoryOverProvisionFactor: getEnvFloat("SB_MEMORY_OVERPROVISION_FACTOR", 10.0),
		HostCPUCoresOverride:      getEnvInt("SB_HOST_CPU_CORES", 0),
		HostMemoryMBOverride:      getEnvInt("SB_HOST_MEMORY_MB", 0),

		L4PortRangeStart: getEnvInt("SB_L4_PORT_RANGE_START", 22000),
		L4PortRangeEnd:   getEnvInt("SB_L4_PORT_RANGE_END", 23000),
		L4TLSListen:      strings.TrimSpace(os.Getenv("SB_L4_TLS_LISTEN")),
		L4TLSFallback:    getEnv("SB_L4_TLS_FALLBACK", "127.0.0.1:8443"),

		EnableCluster:                 getEnvBool("SB_ENABLE_CLUSTER", false),
		NodeID:                        strings.TrimSpace(os.Getenv("SB_NODE_ID")),
		RaftBindAddr:                  getEnv("SB_RAFT_BIND_ADDR", "0.0.0.0:7000"),
		RaftAdvertiseAddr:             strings.TrimSpace(os.Getenv("SB_RAFT_ADVERTISE_ADDR")),
		RaftDataDir:                   strings.TrimSpace(os.Getenv("SB_RAFT_DATA_DIR")),
		GossipBindAddr:                getEnv("SB_GOSSIP_BIND_ADDR", "0.0.0.0:7001"),
		GossipAdvertiseAddr:           strings.TrimSpace(os.Getenv("SB_GOSSIP_ADVERTISE_ADDR")),
		BootstrapPeers:                splitAndTrim(os.Getenv("SB_BOOTSTRAP_PEERS"), ","),
		ClusterBootstrap:              getEnvBool("SB_CLUSTER_BOOTSTRAP", false),
		SelfAPIAdvertiseURL:           strings.TrimSpace(os.Getenv("SB_API_ADVERTISE_URL")),
		ClusterRaftCommitTimeout:      getEnvDuration("SB_RAFT_COMMIT_TIMEOUT", 5*time.Second),
		ClusterCapacityGossipInterval: getEnvDuration("SB_CAPACITY_GOSSIP_INTERVAL", 5*time.Second),
		ClusterDeadOwnerGrace:         getEnvDuration("SB_DEAD_OWNER_GRACE", 30*time.Second),
		ClusterGossipSecretKey:        strings.TrimSpace(os.Getenv("SB_GOSSIP_SECRET_KEY")),
	}

	if cfg.PATToken == "" {
		return Config{}, errors.New("SB_PAT_TOKEN is required")
	}

	if cfg.DBPath == "" {
		return Config{}, errors.New("SB_DB_PATH is required")
	}

	if cfg.ToolboxMountPath == "" || !strings.HasPrefix(cfg.ToolboxMountPath, "/") {
		return Config{}, fmt.Errorf("SB_TOOLBOX_MOUNT_PATH must be an absolute path")
	}

	if cfg.Domain == "" && cfg.PublicHost == "" {
		return Config{}, errors.New("SB_PUBLIC_HOST is required when SB_DOMAIN is empty")
	}

	// SB_CONTAINER_RUNTIME must be one of the runtimes we know how to drive.
	// We reject "" here too: the caller substitutes the host default when a
	// per-sandbox value is empty, but the host default itself must always be
	// explicit. "kata" is a valid identifier but not implemented yet — we
	// allow it as the host default so operators can pre-stage config, and
	// reject individual create requests until the runtime is wired up.
	if _, err := models.ValidRuntime(cfg.Runtime); err != nil || cfg.Runtime == "" {
		return Config{}, fmt.Errorf("invalid SB_CONTAINER_RUNTIME=%q (allowed: %s, %s, %s)", cfg.Runtime, models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeKata)
	}

	// L4 port pool sanity. Out-of-range or inverted bounds would silently
	// brick raw-TCP exposure later; surface it at boot instead.
	if cfg.L4PortRangeStart < 1024 || cfg.L4PortRangeEnd > 65535 || cfg.L4PortRangeStart >= cfg.L4PortRangeEnd {
		return Config{}, fmt.Errorf("invalid SB_L4_PORT_RANGE_START/END (%d-%d): require 1024 <= start < end <= 65535",
			cfg.L4PortRangeStart, cfg.L4PortRangeEnd)
	}

	// If TLS-SNI multiplexing is enabled, the fallback HTTPS address must be
	// set — otherwise non-sandbox SNI (the API itself, the catch-all 404)
	// would land nowhere. An operator who explicitly sets
	// SB_L4_TLS_FALLBACK="" while also setting SB_L4_TLS_LISTEN is
	// misconfigured; surface it at boot.
	if cfg.L4TLSListen != "" && cfg.L4TLSFallback == "" {
		return Config{}, errors.New("SB_L4_TLS_FALLBACK must be set when SB_L4_TLS_LISTEN is set (caddy-l4 needs a target for non-sandbox SNI)")
	}

	// Cluster-mode invariants. Single-node mode (EnableCluster=false) skips
	// all of this — defaults are non-load-bearing in that case.
	if cfg.EnableCluster {
		if cfg.RaftDataDir == "" {
			cfg.RaftDataDir = filepath.Join(filepath.Dir(cfg.DBPath), "raft")
		}
		if cfg.RaftAdvertiseAddr == "" {
			cfg.RaftAdvertiseAddr = cfg.RaftBindAddr
		}
		if cfg.GossipAdvertiseAddr == "" {
			cfg.GossipAdvertiseAddr = cfg.GossipBindAddr
		}
		if cfg.SelfAPIAdvertiseURL == "" {
			host, _ := os.Hostname()
			if host == "" {
				host = "127.0.0.1"
			}
			cfg.SelfAPIAdvertiseURL = fmt.Sprintf("http://%s:%d", host, cfg.APIPort)
		}
		if !cfg.ClusterBootstrap && len(cfg.BootstrapPeers) == 0 {
			return Config{}, errors.New("SB_BOOTSTRAP_PEERS is required when SB_ENABLE_CLUSTER=true and SB_CLUSTER_BOOTSTRAP=false")
		}
	}

	return cfg, nil
}

func splitAndTrim(s, sep string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (c Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.APIHost, c.APIPort)
}

func (c Config) DomainMode() bool {
	return c.Domain != ""
}

func (c Config) IdleTimeout() time.Duration {
	if c.IdleTimeoutMinutes <= 0 {
		return 0
	}
	return time.Duration(c.IdleTimeoutMinutes) * time.Minute
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func normalizeHost(value string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://"))
}
