package containerd

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// Config holds containerd-driver settings projected from daemon config.
type Config struct {
	Socket             string
	Namespace          string
	ToolboxBinaryPath  string
	ToolboxMountPath   string
	ToolboxPort        int
	Privileged         bool
	ResourceLimitsOff  bool
	DefaultRuntime     string
	WaitTimeout        time.Duration
	ToolboxWaitTimeout time.Duration
	ReadyEnabled       bool
	ReadyDir           string
	ReadinessPollInit  time.Duration
	ReadinessPollMax   time.Duration
	PullMaxConcurrent  int
	PullFailureBackoff time.Duration
	HTTPClientTimeout  time.Duration
	LogDir             string
	RunDir             string
	NativeNetnsPool    bool
}

// FromDaemonConfig maps internal config into driver-local settings.
func FromDaemonConfig(cfg config.Config) Config {
	// Resolve runDir's fallback FIRST so the log dir derives from the effective
	// run dir — otherwise an empty ContainerdRunDir would place logs at "/logs"
	// (host root) while files land under the real default.
	runDir := cfg.ContainerdRunDir
	if runDir == "" {
		runDir = config.DefaultContainerdRunDir
	}
	logDir := cfg.ContainerdLogDir
	if logDir == "" {
		logDir = runDir + "/logs"
	}
	return Config{
		Socket:             cfg.ContainerdSocket,
		Namespace:          cfg.ContainerdNamespace,
		ToolboxBinaryPath:  cfg.ToolboxBinaryPath,
		ToolboxMountPath:   cfg.ToolboxMountPath,
		ToolboxPort:        cfg.ToolboxPort,
		Privileged:         cfg.ContainerPrivileged,
		ResourceLimitsOff:  cfg.ResourceLimitsOff,
		DefaultRuntime:     cfg.Runtime,
		WaitTimeout:        cfg.DockerRuntimeWaitTimeout,
		ToolboxWaitTimeout: cfg.ToolboxWaitTimeout,
		ReadyEnabled:       cfg.DockerReadySocketEffective(),
		ReadyDir:           cfg.DockerReadySocketDir(),
		ReadinessPollInit:  cfg.DockerReadinessPollInitial,
		ReadinessPollMax:   cfg.DockerReadinessPollMax,
		PullMaxConcurrent:  cfg.ImagePullMaxConcurrent,
		PullFailureBackoff: cfg.ImagePullFailureBackoff,
		HTTPClientTimeout:  cfg.HTTPClientTimeout,
		LogDir:             logDir,
		RunDir:             runDir,
		NativeNetnsPool:    cfg.ContainerdNativeNetnsPoolEnabled,
	}
}

// Driver implements runtime.ContainerRuntime against a local containerd.
type Driver struct {
	logger       *slog.Logger
	cfg          Config
	networkRules *netrules.Manager

	// clientMu single-flights lazy connection establishment so a burst of
	// concurrent first-creates dials containerd once instead of racing on the
	// client field and leaking all-but-one gRPC connection.
	clientMu sync.Mutex
	client   *Client

	// pullGroup collapses concurrent pulls of the same ref; pullSem caps
	// concurrent pulls of distinct refs; pullFailUntil rate-limits retries of
	// a ref that just failed. Together they replace dockerd's pull dedup.
	pullGroup     singleflight.Group
	pullSem       chan struct{}
	pullFailMu    sync.Mutex
	pullFailUntil map[string]time.Time

	warmPool WarmPool
	netns    NetnsHandoff
}

// New constructs a Driver. The containerd connection is lazy — Ping and
// Create establish it on first use so unit tests can inject a fake client.
func New(cfg Config, rules *netrules.Manager, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	var sem chan struct{}
	if cfg.PullMaxConcurrent > 0 {
		sem = make(chan struct{}, cfg.PullMaxConcurrent)
	}
	return &Driver{
		logger:        logger,
		cfg:           cfg,
		networkRules:  rules,
		pullSem:       sem,
		pullFailUntil: make(map[string]time.Time),
	}
}

// SetNetnsHandoff wires the native netns pool (Phase 2). Nil disables it.
func (d *Driver) SetNetnsHandoff(h NetnsHandoff) {
	d.netns = h
}
func (d *Driver) SetClient(c *Client) {
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	d.client = c
}

// connectFn dials containerd; tests override to avoid a live socket.
var connectFn = Connect

func (d *Driver) ensureClient() (*Client, error) {
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	if d.client != nil {
		return d.client, nil
	}
	c, err := connectFn(d.cfg.Socket, d.cfg.Namespace)
	if err != nil {
		return nil, err
	}
	d.client = c
	return c, nil
}

// Ping verifies containerd is reachable.
func (d *Driver) Ping(ctx context.Context) error {
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	return client.Ping(ctx)
}
