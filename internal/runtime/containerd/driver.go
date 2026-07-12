package containerd

import (
	"context"
	"log/slog"
	"time"

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
}

// FromDaemonConfig maps internal config into driver-local settings.
func FromDaemonConfig(cfg config.Config) Config {
	logDir := cfg.ContainerdLogDir
	if logDir == "" {
		logDir = cfg.ContainerdRunDir + "/logs"
	}
	runDir := cfg.ContainerdRunDir
	if runDir == "" {
		runDir = "/var/lib/sandboxd/containerd"
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
	}
}

// Driver implements runtime.ContainerRuntime against a local containerd.
type Driver struct {
	logger       *slog.Logger
	cfg          Config
	networkRules *netrules.Manager
	client       *Client
}

// New constructs a Driver. The containerd connection is lazy — Ping and
// Create establish it on first use so unit tests can inject a fake client.
func New(cfg Config, rules *netrules.Manager, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Driver{
		logger:       logger,
		cfg:          cfg,
		networkRules: rules,
	}
}

// SetClient injects a containerd API client (tests / fakes).
func (d *Driver) SetClient(c *Client) {
	d.client = c
}

func (d *Driver) ensureClient() (*Client, error) {
	if d.client != nil {
		return d.client, nil
	}
	c, err := Connect(d.cfg.Socket, d.cfg.Namespace)
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
