package docker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// managedLabelKey is the Docker label every sandbox container we create
// carries (value "true"). It is the ownership boundary between sandboxd-
// managed containers and any other Docker workloads sharing the same
// daemon: ListManaged filters on this label, and the Docker /events stream
// is subscribed with the same label filter (see pkg/docker/events.go), so
// reconcile and the event monitor are guaranteed never to see — let alone
// stop, destroy, or modify — a container we did not create. Do not relax
// either filter without first reasoning through the multi-tenant case;
// without the gate, a `docker run` started by an unrelated process on the
// host would be picked up as an "orphan" and force-removed.
const managedLabelKey = "aerolvm.managed"

// SandboxRuntime is the Docker-layer alias of the canonical
// models.SandboxRuntimeState type. The alias keeps every existing reference
// in pkg/docker compiling unchanged while letting non-Docker runtime
// implementations import only pkg/models.
type SandboxRuntime = models.SandboxRuntimeState

type Client struct {
	logger             *slog.Logger
	socketPath         string
	network            string
	toolboxBinaryPath  string
	toolboxMountPath   string
	toolboxPort        int
	privileged         bool
	resourceLimitsOff  bool
	defaultRuntime     string
	httpClient         *http.Client
	streamClient       *http.Client
	toolboxClient      *http.Client
	networkRules       *netrules.Manager
	waitTimeout        time.Duration
	toolboxWaitTimeout time.Duration
	readyEnabled       bool
	readyDir           string
	readinessPollInit  time.Duration
	readinessPollMax   time.Duration
	pullMu             sync.Mutex
	pulls              map[string]*imagePull
	pullSlots          chan struct{}
	pullBackoff        time.Duration
	pullFailures       map[string]imagePullFailure
	// Mirror configuration: zero value disables rewriting and the pull
	// path behaves exactly as it did before AOCR mirror support landed.
	// Set via ConfigureMirror after construction; main() is responsible
	// for loading the key ring once and handing it in.
	mirrorCfg    MirrorConfig
	wrapKeyRing  *secrets.UpstreamWrapKeyRing
	pullObserver PullObserver
	// aocrPullAuth is the node-local cluster PAT used to pull cluster-owned
	// artifacts (snapshots + Firecracker templates) from AOCR. nil disables it
	// (anonymous pulls). Set via ConfigureAOCRPullAuth after construction. See
	// aocr_pull_auth.go.
	aocrPullAuth *aocrClusterPullAuth
}

type imagePull struct {
	done chan struct{}
	err  error
}

type imagePullFailure struct {
	err       error
	retryAt   time.Time
	createdAt time.Time
}

func New(logger *slog.Logger, cfg config.Config, rules *netrules.Manager) (*Client, error) {
	if cfg.ToolboxBinaryPath == "" {
		return nil, errors.New("SB_TOOLBOX_BINARY_PATH is required")
	}

	socketPath := "/var/run/docker.sock"
	if rawDockerHost := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(rawDockerHost, "unix://") {
		socketPath = strings.TrimPrefix(rawDockerHost, "unix://")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}

	var pullSlots chan struct{}
	if cfg.ImagePullMaxConcurrent > 0 {
		pullSlots = make(chan struct{}, cfg.ImagePullMaxConcurrent)
	}
	return &Client{
		logger:             logger,
		socketPath:         socketPath,
		network:            cfg.DockerNetwork,
		toolboxBinaryPath:  cfg.ToolboxBinaryPath,
		toolboxMountPath:   cfg.ToolboxMountPath,
		toolboxPort:        cfg.ToolboxPort,
		privileged:         cfg.ContainerPrivileged,
		resourceLimitsOff:  cfg.ResourceLimitsOff,
		defaultRuntime:     cfg.Runtime,
		httpClient:         &http.Client{Timeout: cfg.HTTPClientTimeout, Transport: transport},
		streamClient:       &http.Client{Transport: transport},
		toolboxClient:      &http.Client{Timeout: cfg.HTTPClientTimeout},
		networkRules:       rules,
		waitTimeout:        cfg.DockerRuntimeWaitTimeout,
		toolboxWaitTimeout: cfg.ToolboxWaitTimeout,
		readyEnabled:       cfg.DockerReadySocketEffective(),
		readyDir:           cfg.DockerReadySocketDir(),
		readinessPollInit:  cfg.DockerReadinessPollInitial,
		readinessPollMax:   cfg.DockerReadinessPollMax,
		pulls:              make(map[string]*imagePull),
		pullSlots:          pullSlots,
		pullBackoff:        cfg.ImagePullFailureBackoff,
		pullFailures:       make(map[string]imagePullFailure),
	}, nil
}

// ConfigureMirror installs the AOCR mirror policy onto an existing Client.
// Both arguments are optional: a zero MirrorConfig disables rewriting, and
// a nil key ring disables identity-token wrapping (the pull falls back to
// raw username/password in X-Registry-Auth). main() is expected to load the
// wrap key ring exactly once at startup and hand it in here.
func (c *Client) ConfigureMirror(cfg MirrorConfig, ring *secrets.UpstreamWrapKeyRing) {
	c.mirrorCfg = cfg
	c.wrapKeyRing = ring
}

// PullObserver is invoked exactly once per successful pull that BOTH went
// through a mirror rewrite AND used non-anonymous upstream credentials —
// the precondition for the F21 auto-import flow. The sandboxID is whatever
// the caller stashed on the context with WithSandboxID; empty IDs skip the
// observer call (no row to flag).
//
// Errors inside the observer are the caller's problem: pullImage does not
// surface them, so the observer must not panic and should handle its own
// retry/logging. The observer runs synchronously on the pull goroutine; keep
// it fast.
type PullObserver func(ctx context.Context, sandboxID string)

// SetPullObserver installs a single observer. Calling again replaces the
// previous one. Pass nil to disable. main() is expected to set this once at
// startup to wire the post-pull AutoImportPending flag.
func (c *Client) SetPullObserver(obs PullObserver) {
	c.pullObserver = obs
}

// sandboxIDCtxKey is the unexported type used to stash the sandbox ID on the
// pull context so pullImage can pass it to the PullObserver without us
// having to grow signatures across the (already wide) pull stack.
type sandboxIDCtxKey struct{}

// WithSandboxID returns a context derived from parent that carries the
// sandbox identifier the pull is being executed on behalf of. Used by the
// Create path so the PullObserver fired after a successful private mirror
// pull can flag the correct row. Empty IDs are ignored.
func WithSandboxID(parent context.Context, sandboxID string) context.Context {
	if strings.TrimSpace(sandboxID) == "" {
		return parent
	}
	return context.WithValue(parent, sandboxIDCtxKey{}, sandboxID)
}

// sandboxIDFromContext is the readback half of WithSandboxID. Returns "" if
// no ID was stashed — callers must treat empty as "no observer call".
func sandboxIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(sandboxIDCtxKey{}).(string)
	return v
}

// ClearNetworkRules releases any per-IP network rules previously attached to a
// sandbox. Used by the event-driven path when a container exits or is destroyed
// out-of-band, since Destroy() handles this for us during normal teardown.
// Clears both egress (NetworkBlockAll / quota egress) and ingress (quota
// ingress) rules — once the IP is gone there is nothing left to firewall on.
func (c *Client) ClearNetworkRules(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	if err := c.networkRules.ClearBlockAllEgress(containerIP); err != nil {
		return err
	}
	return c.networkRules.ClearBlockAllIngress(containerIP)
}

// ApplyNetworkBlockAll installs the per-IP egress DROP rule. Idempotent —
// the underlying rule manager checks for an existing match before inserting.
// Called on Create (initial install), StartSandbox (after a Stop+Start cycle
// drops the rule on the stop event), and reconcile (to heal after host-side
// state loss).
func (c *Client) ApplyNetworkBlockAll(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.BlockAllEgress(containerIP)
}

// ContainerPID returns the host PID of a running container's init process.
// The PID is the entry point into the container's network namespace —
// /proc/<pid>/net/dev is per-netns, so the netstats poller reads byte
// counters straight from there with no nsenter / veth-iflink dance. Returns
// 0 when the container is not running (Docker reports Pid:0 in that case).
func (c *Client) ContainerPID(ctx context.Context, containerRef string) (int, error) {
	inspect, err := c.inspectContainer(ctx, containerRef)
	if err != nil {
		return 0, err
	}
	if inspect.State == nil {
		return 0, nil
	}
	return inspect.State.Pid, nil
}

// ApplyNetworkBlockIngress installs the per-IP ingress DROP rule used by the
// network-quota enforcer when net_bytes_in_limit is crossed. Idempotent.
func (c *Client) ApplyNetworkBlockIngress(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.BlockAllIngress(containerIP)
}

// ClearNetworkBlockIngress removes the per-IP ingress DROP rule. Service layer
// only calls this when the inbound limit is raised above current usage.
func (c *Client) ClearNetworkBlockIngress(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.ClearBlockAllIngress(containerIP)
}

// ClearNetworkBlockEgress removes the per-IP egress DROP rule. Symmetric to
// ApplyNetworkBlockAll. The underlying rule is shared with NetworkBlockAll, so
// the service must consult sandbox.NetworkBlockAll before invoking this on a
// quota-clear path — otherwise it would silently undo the operator's egress
// block.
func (c *Client) ClearNetworkBlockEgress(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.ClearBlockAllEgress(containerIP)
}

// ApplyEgressPolicy installs the selective-egress CIDR policy. Idempotent —
// called on Create (initial install), StartSandbox (after a Stop+Start cycle
// drops the rules on the stop event), and reconcile (to heal host-side state
// loss). A no-op when no policy is set or network rules are disabled.
func (c *Client) ApplyEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.ApplyEgressPolicy(containerIP, allowCIDRs, denyCIDRs)
}

// ClearEgressPolicy removes the selective-egress rules for the IP. Called on
// stop/destroy before Docker recycles the IP — a stale ACCEPT/DROP would
// otherwise re-attach to whoever next gets this IP from the IPAM pool.
func (c *Client) ClearEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.ClearEgressPolicy(containerIP, allowCIDRs, denyCIDRs)
}

func (c *Client) Ping(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return fmt.Errorf("docker ping failed with status %d", response.StatusCode)
	}
	return nil
}

// Create provisions and starts a managed container. The caller chooses the
// sandbox ID up-front; we set it as the container's Docker name so the name
// is the canonical sandbox identifier end-to-end (the container ID is an
// internal detail). Host-side mounts are passed as bind sources prepared by
// the mounts manager; sandboxd never writes a mounts.json into the container.
func (c *Client) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID string, toolboxToken string, hostMounts []mounts.ContainerBind) (*SandboxRuntime, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("sandbox ID is required")
	}
	if err := c.ensureToolboxBinary(); err != nil {
		return nil, err
	}

	// Resolve the effective user-facing runtime: per-sandbox override wins
	// over the host default. The service layer is expected to substitute the
	// host default into req.Runtime before calling Create, but we re-resolve
	// here as a safety net so direct use of the docker client (e.g. tests)
	// still works.
	effectiveRuntime := strings.TrimSpace(req.Runtime)
	if effectiveRuntime == "" {
		effectiveRuntime = c.defaultRuntime
	}
	// gVisor refuses privileged containers — its userspace kernel cannot
	// safely grant the host capabilities --privileged implies. Catch the
	// conflict here, before pulling the image and 30s into a doomed start.
	if effectiveRuntime == models.RuntimeGvisor && c.privileged {
		return nil, fmt.Errorf("runtime %q is incompatible with privileged containers", effectiveRuntime)
	}
	// gVisor's user-space kernel cannot pass through host GPU drivers. Fail
	// before any image pull so the error is immediate and actionable.
	if req.GPUs != nil && effectiveRuntime == models.RuntimeGvisor {
		return nil, fmt.Errorf(
			"GPU access is not supported with the %q runtime: gVisor's user-space kernel "+
				"cannot safely pass through host GPU drivers; use the %q runtime for GPU workloads",
			models.RuntimeGvisor, models.RuntimeDocker,
		)
	}
	// Translate user-facing name to the OCI runtime binary Docker actually
	// looks up in /etc/docker/daemon.json. ResolveOCIRuntime returns "" for
	// "docker" (let Docker use its compiled-in default) and "runsc" for
	// "gvisor". "kata" returns ErrRuntimeNotImplemented; the service layer
	// rejects those requests upfront, but we double-check here as a safety
	// net for direct callers.
	ociRuntime, err := models.ResolveOCIRuntime(effectiveRuntime)
	if err != nil {
		return nil, err
	}

	// Locally-built images (BuildImage tags them with content-addressed
	// names that don't exist on any registry) must skip the pull, otherwise
	// the daemon would 401/404 trying to fetch them from Docker Hub. We
	// can't decide that purely from the name though — a real registry image
	// could legitimately use a name in BuiltImageNamespace. Inspect first;
	// if the image is already local, the pull is unnecessary regardless of
	// where it came from. If the inspect fails (image missing) we fall
	// through to a normal pull attempt and let that surface the registry
	// error.
	imageInspect, err := c.inspectImage(ctx, req.Image)
	if err != nil {
		if IsLocalOnlyImageRef(req.Image) || req.ImageDistributionMode == models.ImageDistributionLocalOnly {
			return nil, fmt.Errorf("image %q is local-only and is not present on this node; push/register it to a registry or pre-distribute it before failover recreate", req.Image)
		}
		// Stash the sandbox ID on the pull context so the PullObserver can
		// route the post-pull AutoImportPending flag to the right row when
		// the pull qualifies (mirror rewrite + private creds).
		pullCtx := WithSandboxID(ctx, sandboxID)
		if pullErr := c.pullImageDedup(pullCtx, req.Image, req.Registry); pullErr != nil {
			return nil, pullErr
		}
		imageInspect, err = c.inspectImage(ctx, req.Image)
		if err != nil {
			return nil, fmt.Errorf("inspect image: %w", err)
		}
	}

	workingDir := strings.TrimSpace(imageInspect.Config.WorkingDir)
	if workingDir == "" {
		workingDir = "/"
	}

	envValues := make([]string, 0, len(req.Env)+3)
	envValues = append(envValues,
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", c.toolboxPort),
		"SB_TOOLBOX_TOKEN="+toolboxToken,
	)
	for key, value := range req.Env {
		envValues = append(envValues, key+"="+value)
	}
	sort.Strings(envValues)

	labels := map[string]string{
		managedLabelKey: "true",
	}

	userCommand := req.ContainerCommand
	if len(userCommand) == 0 {
		userCommand = append(append([]string{}, imageInspect.Config.Entrypoint...), imageInspect.Config.Cmd...)
	}

	createRequest := map[string]any{
		"Image":      req.Image,
		"WorkingDir": workingDir,
		"Entrypoint": []string{c.toolboxMountPath},
		"Cmd":        userCommand,
		"Env":        envValues,
		"Labels":     labels,
	}

	binds := []string{
		fmt.Sprintf("%s:%s:ro", c.toolboxBinaryPath, c.toolboxMountPath),
	}

	var readyListener *ReadyListener
	var readyListenerClosed bool
	var readySocketCreated bool
	var keepReadySocket bool
	defer func() {
		if readyListener != nil && !readyListenerClosed {
			_ = readyListener.Close()
		}
		if readySocketCreated && !keepReadySocket {
			RemoveReadySocketsForSandbox(c.readyDir, sandboxID)
		}
	}()

	if c.readyEnabled {
		readyNonce, err := mintReadyNonce()
		if err != nil {
			return nil, fmt.Errorf("mint ready nonce: %w", err)
		}
		readyListener, err = NewReadyListener(c.readyDir, sandboxID, toolboxToken, readyNonce)
		if err != nil {
			return nil, fmt.Errorf("ready listener: %w", err)
		}
		readySocketCreated = true
		binds = append(binds, readyListener.BindSpec())
		envValues = append(envValues, readyListener.EnvVars()...)
		sort.Strings(envValues)
		// envValues was sized to len(req.Env)+3, so appending the two ready
		// vars reallocates the backing array — the slice already stored under
		// createRequest["Env"] still points at the pre-append array. Re-store
		// the grown slice or toolboxd never sees SB_READY_SOCKET/NONCE and the
		// push silently degrades to health-poll on every create.
		createRequest["Env"] = envValues
	}

	for _, m := range hostMounts {
		entry := fmt.Sprintf("%s:%s", m.HostPath, m.ContainerPath)
		if m.ReadOnly {
			entry += ":ro"
		}
		binds = append(binds, entry)
	}
	// AMD ROCm exposes render nodes as a directory (/dev/dri). Bind-mount it
	// before hostConfig captures the slice; /dev/kfd is added via Devices later.
	if req.GPUs != nil && req.GPUs.Vendor == models.GPUVendorAMD {
		binds = append(binds, "/dev/dri:/dev/dri")
	}

	hostConfig := map[string]any{
		"Privileged": c.privileged,
		"Binds":      binds,
	}

	if c.network != "" && c.network != "bridge" {
		hostConfig["NetworkMode"] = c.network
	}

	// Only set HostConfig.Runtime when we actually need to override the
	// daemon's default. ResolveOCIRuntime returns "" for the "docker"
	// identifier so we leave the field unset — safer on hosts that haven't
	// explicitly registered "runc" in /etc/docker/daemon.json, since Docker
	// then falls back to its compiled-in default runtime.
	if ociRuntime != "" {
		hostConfig["Runtime"] = ociRuntime
	}

	if !c.resourceLimitsOff {
		resources := map[string]any{}
		if req.CPU > 0 {
			// CpuPeriod 100ms + CpuQuota = CPU*100000μs gives fractional cores
			// (e.g. 0.5 CPU → 50000μs quota per 100ms period).
			resources["CpuPeriod"] = int64(100000)
			resources["CpuQuota"] = int64(req.CPU * 100000)
		}
		if req.MemoryMB > 0 {
			resources["Memory"] = int64(req.MemoryMB) * 1024 * 1024
			resources["MemorySwap"] = int64(req.MemoryMB) * 1024 * 1024
		}
		if req.DiskGB > 0 {
			// gVisor does not honor StorageOpt size — silently applying it
			// would mislead operators into thinking quota is enforced. Drop
			// the field with a warning when gvisor is in use.
			if effectiveRuntime == models.RuntimeGvisor {
				c.logger.Warn("ignoring disk quota: gvisor does not support StorageOpt size",
					"sandbox_id", sandboxID, "disk_gb", req.DiskGB)
			} else {
				hostConfig["StorageOpt"] = map[string]string{"size": fmt.Sprintf("%dG", req.DiskGB)}
			}
		}
		hostConfig["Resources"] = resources
	}

	if req.GPUs != nil {
		count := req.GPUs.Count
		if count == 0 {
			count = 1
		}
		switch req.GPUs.Vendor {
		case models.GPUVendorNVIDIA:
			// Standard Docker GPU interface for NVIDIA. Requires
			// nvidia-container-toolkit on the host.
			hostConfig["DeviceRequests"] = []map[string]any{{
				"Driver":       "nvidia",
				"Count":        count,
				"DeviceIDs":    req.GPUs.DeviceIDs,
				"Capabilities": [][]string{{"gpu"}},
				"Options":      map[string]string{},
			}}
		case models.GPUVendorAMD:
			// AMD ROCm: /dev/kfd is the compute driver added as a cgroup device
			// so Docker sets the correct cgroup permissions. /dev/dri (render
			// nodes) is already in Binds above. Non-privileged containers also
			// need the container user in the "video" and "render" groups.
			hostConfig["Devices"] = []map[string]any{{
				"PathOnHost":        "/dev/kfd",
				"PathInContainer":   "/dev/kfd",
				"CgroupPermissions": "mrw",
			}}
		case models.GPUVendorApple:
			// Apple Metal GPU via Docker Desktop's experimental Metal support.
			// Only functional on macOS with Docker Desktop; a Linux Docker host
			// will receive a daemon error at container creation time.
			hostConfig["DeviceRequests"] = []map[string]any{{
				"Driver":       "apple",
				"Count":        count,
				"Capabilities": [][]string{{"gpu"}},
				"Options":      map[string]string{},
			}}
		}
	}

	createRequest["HostConfig"] = hostConfig

	var created struct {
		ID string `json:"Id"`
	}
	createQuery := url.Values{}
	createQuery.Set("name", sandboxID)
	err = c.doJSON(ctx, http.MethodPost, "/containers/create", createQuery, createRequest, nil, &created)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil, nil, nil); err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		return nil, fmt.Errorf("start container: %w", err)
	}

	runtimeWaitStart := time.Now()
	containerIP, inspect, err := c.waitForContainerRunning(ctx, created.ID)
	runtimeWait := time.Since(runtimeWaitStart)
	if err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		return nil, err
	}

	toolboxWaitStart := time.Now()
	toolboxSource, err := c.waitForToolboxReady(ctx, containerIP, readyListener)
	toolboxWait := time.Since(toolboxWaitStart)
	if timing := CreateTimingFrom(ctx); timing != nil {
		timing.RecordDockerWaits(runtimeWait, toolboxWait, toolboxSource)
	}
	if err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		return nil, err
	}
	if readyListener != nil {
		readyListenerClosed = true
		_ = readyListener.Close()
		if err := readyListener.ParkBindSource(); err != nil {
			c.logger.Warn("park ready socket bind source failed", "sandbox_id", sandboxID, "error", err)
		}
		readyListener = nil
	}

	runtime := &SandboxRuntime{
		SandboxID:   sandboxIDFromContainerName(inspect.Name),
		ContainerID: inspect.ID,
		ContainerIP: containerIP,
		Status:      models.SandboxStatusStarted,
	}

	if req.NetworkBlockAll {
		if err := c.networkRules.BlockAllEgress(runtime.ContainerIP); err != nil {
			// Fail closed: the user opted into network isolation, so a sandbox
			// that came up without the DROP rule must not be left running.
			// Clear any partial state and tear the container down before
			// returning the error.
			_ = c.networkRules.ClearBlockAllEgress(runtime.ContainerIP)
			_ = c.removeContainer(ctx, created.ID, true)
			return nil, fmt.Errorf("apply network block: %w", err)
		}
	}

	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := c.networkRules.ApplyEgressPolicy(runtime.ContainerIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			// Fail closed, same rationale as NetworkBlockAll: the user opted
			// into a restricted egress policy, so a sandbox that came up with
			// only a partial rule set must not be left running. Roll the
			// partial policy back and tear the container down.
			_ = c.networkRules.ClearEgressPolicy(runtime.ContainerIP, req.NetworkAllowOut, req.NetworkDenyOut)
			_ = c.removeContainer(ctx, created.ID, true)
			return nil, fmt.Errorf("apply egress policy: %w", err)
		}
	}

	runtime.SandboxID = sandboxID
	keepReadySocket = true
	return runtime, nil
}

func (c *Client) Start(ctx context.Context, containerRef string) (*SandboxRuntime, error) {
	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/start", nil, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}
	return c.waitForRuntime(ctx, containerRef)
}

func (c *Client) Stop(ctx context.Context, containerRef string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/stop", queryValues(map[string]string{"t": "10"}), nil, nil, nil)
}

func (c *Client) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox != nil {
		// Clear both directions: a stale ingress DROP would re-attach to whoever
		// next gets this IP from Docker's IPAM pool.
		_ = c.ClearNetworkRules(sandbox.ContainerIP)
		// The selective-egress rules are comment-tagged and keyed by allow/deny
		// CIDR, so the blanket clear above does not touch them — clear them
		// explicitly from the persisted policy before the IP is recycled.
		_ = c.ClearEgressPolicy(sandbox.ContainerIP, sandbox.NetworkAllowOut, sandbox.NetworkDenyOut)
	}
	if sandbox == nil {
		return nil
	}
	RemoveReadySocketsForSandbox(c.readyDir, sandbox.ID)
	containerRef := strings.TrimSpace(sandbox.ContainerID)
	if containerRef == "" {
		return errors.New("sandbox container ID is not available")
	}
	return c.removeContainer(ctx, containerRef, true)
}

// SweepOrphanReadySockets removes ready sockets not referenced by existing
// managed Docker containers. Docker persists bind mounts across stop/start, so
// deleting a stopped container's ready-socket source would make docker start
// fail before toolboxd can boot.
func (c *Client) SweepOrphanReadySockets(ctx context.Context) error {
	if strings.TrimSpace(c.readyDir) == "" {
		return nil
	}
	keep, err := c.readySocketBindSources(ctx)
	if err != nil {
		return err
	}
	return SweepOrphanReadySocketsExcept(c.readyDir, keep)
}

func (c *Client) readySocketBindSources(ctx context.Context) (map[string]struct{}, error) {
	query := queryValues(map[string]string{"all": "1"})
	var containers []containerSummary
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json", query, nil, nil, &containers); err != nil {
		return nil, fmt.Errorf("list managed containers for ready sockets: %w", err)
	}
	keep := map[string]struct{}{}
	for _, summary := range containers {
		if summary.Labels[managedLabelKey] != "true" {
			continue
		}
		inspect, err := c.inspectContainer(ctx, summary.ID)
		if err != nil {
			return nil, fmt.Errorf("inspect managed container %s for ready sockets: %w", summary.ID, err)
		}
		for _, src := range readySocketBindSourcesFromInspect(inspect) {
			if c.readySocketPathOwnedByDir(src) {
				keep[src] = struct{}{}
			}
		}
	}
	return keep, nil
}

func (c *Client) readySocketPathOwnedByDir(path string) bool {
	dir := filepath.Clean(strings.TrimSpace(c.readyDir))
	path = filepath.Clean(strings.TrimSpace(path))
	if dir == "." || path == "." {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != "" && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func readySocketBindSourcesFromInspect(inspect containerInspect) []string {
	var out []string
	for _, bind := range inspect.HostConfig.Binds {
		if src, ok := readySocketSourceFromBind(bind); ok {
			out = append(out, src)
		}
	}
	for _, mount := range inspect.Mounts {
		if mount.Destination == GuestReadySocketPath && strings.TrimSpace(mount.Source) != "" {
			out = append(out, strings.TrimSpace(mount.Source))
		}
	}
	return out
}

func readySocketSourceFromBind(bind string) (string, bool) {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 || parts[1] != GuestReadySocketPath {
		return "", false
	}
	src := strings.TrimSpace(parts[0])
	if src == "" {
		return "", false
	}
	return src, true
}

func (c *Client) CreateSnapshot(ctx context.Context, containerRef, imageRef string) (string, error) {
	repo, tag, err := splitSnapshotImageRef(imageRef)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	query.Set("container", strings.TrimSpace(containerRef))
	query.Set("repo", repo)
	if tag != "" {
		query.Set("tag", tag)
	}

	var response struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/commit", query, nil, nil, &response); err != nil {
		return "", fmt.Errorf("commit snapshot: %w", err)
	}
	return strings.TrimSpace(response.ID), nil
}

func (c *Client) Resize(ctx context.Context, containerRef string, req models.ResizeSandboxRequest) error {
	if c.resourceLimitsOff {
		return nil
	}

	updateRequest := map[string]any{}
	if req.CPU > 0 {
		updateRequest["CpuPeriod"] = int64(100000)
		updateRequest["CpuQuota"] = int64(req.CPU * 100000)
	}
	if req.MemoryMB > 0 {
		updateRequest["Memory"] = int64(req.MemoryMB) * 1024 * 1024
		updateRequest["MemorySwap"] = int64(req.MemoryMB) * 1024 * 1024
	}

	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/update", nil, updateRequest, nil, nil); err != nil {
		return fmt.Errorf("resize container: %w", err)
	}
	return nil
}

// PushAllowedPorts updates the toolbox's in-memory allowlist of ports that
// /proxy/<port>/... is permitted to reach. The list should match the sandbox's
// currently exposed ports. Best-effort: callers log on failure.
func (c *Client) PushAllowedPorts(ctx context.Context, containerIP, toolboxToken string, ports []int) error {
	if containerIP == "" {
		return errors.New("container IP is empty")
	}
	if ports == nil {
		ports = []int{}
	}
	body, err := json.Marshal(map[string]any{"ports": ports})
	if err != nil {
		return fmt.Errorf("marshal ports: %w", err)
	}

	target := fmt.Sprintf("http://%s:%d/admin/allowed-ports", containerIP, c.toolboxPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if toolboxToken != "" {
		req.Header.Set("Authorization", "Bearer "+toolboxToken)
	}

	resp, err := c.toolboxClient.Do(req)
	if err != nil {
		return fmt.Errorf("push allowed ports: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push allowed ports: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Inspect(ctx context.Context, containerRef string) (*SandboxRuntime, error) {
	inspect, err := c.inspectContainer(ctx, containerRef)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	return &SandboxRuntime{
		SandboxID:   sandboxIDFromContainerName(inspect.Name),
		ContainerID: inspect.ID,
		ContainerIP: getContainerIP(inspect, c.network),
		Status:      containerStatus(inspect),
	}, nil
}

func (c *Client) ListManaged(ctx context.Context) (map[string]*SandboxRuntime, error) {
	query := queryValues(map[string]string{"all": "1"})
	var containers []containerSummary
	err := c.doJSON(ctx, http.MethodGet, "/containers/json", query, nil, nil, &containers)
	if err != nil {
		return nil, fmt.Errorf("list managed containers: %w", err)
	}

	result := make(map[string]*SandboxRuntime, len(containers))
	for _, summary := range containers {
		if summary.Labels[managedLabelKey] != "true" {
			continue
		}
		inspect, err := c.inspectContainer(ctx, summary.ID)
		if err != nil {
			continue
		}
		runtime := &SandboxRuntime{
			SandboxID:   sandboxIDFromContainerName(inspect.Name),
			ContainerID: inspect.ID,
			ContainerIP: getContainerIP(inspect, c.network),
			Status:      containerStatus(inspect),
		}
		if runtime.SandboxID != "" {
			result[runtime.SandboxID] = runtime
		}
	}

	return result, nil
}

func (c *Client) ensureToolboxBinary() error {
	info, err := os.Stat(c.toolboxBinaryPath)
	if err != nil {
		return fmt.Errorf("toolbox binary not found at %s: %w", c.toolboxBinaryPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("toolbox binary path is a directory: %s", c.toolboxBinaryPath)
	}
	if !filepath.IsAbs(c.toolboxBinaryPath) {
		return fmt.Errorf("toolbox binary path must be absolute: %s", c.toolboxBinaryPath)
	}
	return nil
}

func (c *Client) pullImage(ctx context.Context, imageRef string, auth *models.RegistryAuth) error {
	// Apply mirror rewrite first so the auth payload we build below can be
	// keyed off the *upstream* host (the AOCR auth service wants the
	// upstream's username/password wrapped inside an identity token, not the
	// mirror vhost as the serveraddress).
	rewrite := RewriteImageRefForMirror(imageRef, c.mirrorCfg)
	pullRef := rewrite.RewrittenRef

	headers := map[string]string{}
	if auth != nil && auth.Username != "" {
		authPayload := map[string]string{
			"username":      auth.Username,
			"password":      auth.Password,
			"serveraddress": auth.Server,
		}
		// When the ref was rewritten and we have a wrap key ring, hand
		// the upstream credentials to AOCR as a wrapped identity token.
		// Docker's auth handling treats `identitytoken` as authoritative
		// and ignores username/password when it's present, which is what
		// we want — the mirror sees only the opaque blob.
		if rewrite.Rewritten && c.wrapKeyRing != nil {
			creds := secrets.UpstreamCredentials{
				UpstreamHost: rewrite.UpstreamHost,
				Username:     auth.Username,
				Password:     auth.Password,
				Scope:        "repository:" + rewrite.UpstreamRepo + ":pull",
			}
			token, err := secrets.WrapUpstreamCreds(c.wrapKeyRing, creds)
			if err != nil {
				return fmt.Errorf("wrap upstream credentials: %w", err)
			}
			// Identity token is authoritative: blank username/password so
			// the mirror never sees the upstream PAT in cleartext, even
			// in error paths.
			authPayload = map[string]string{
				"identitytoken": token,
				"serveraddress": c.mirrorCfg.Host,
			}
		}
		encoded, err := json.Marshal(authPayload)
		if err != nil {
			return fmt.Errorf("marshal registry auth: %w", err)
		}
		headers["X-Registry-Auth"] = base64.StdEncoding.EncodeToString(encoded)
	}

	query := queryValues(map[string]string{"fromImage": pullRef})
	target := "http://docker/images/create?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return fmt.Errorf("pull image: %w", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	// Use streamClient (no timeout) — pulling large images can take minutes and
	// http.Client.Timeout covers the entire response body read.
	response, err := c.streamClient.Do(request)
	if err != nil {
		return fmt.Errorf("pull image: %w", err)
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return fmt.Errorf("docker API POST /images/create failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	defer response.Body.Close()

	// Docker's /images/create streams NDJSON progress. Errors are reported in
	// the body (e.g. {"errorDetail":{"message":"manifest unknown"}}) with the
	// HTTP status still 200, so we have to scan the stream.
	decoder := json.NewDecoder(response.Body)
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				if err := c.aliasMirrorPull(ctx, rewrite); err != nil {
					return err
				}
				c.firePullObserver(ctx, rewrite, auth)
				return nil
			}
			return fmt.Errorf("decode pull stream: %w", err)
		}
		if msg.ErrorDetail.Message != "" {
			return fmt.Errorf("pull image %s: %s", imageRef, msg.ErrorDetail.Message)
		}
		if msg.Error != "" {
			return fmt.Errorf("pull image %s: %s", imageRef, msg.Error)
		}
	}
}

// aliasMirrorPull tags a successfully-pulled mirror image under its
// user-visible original ref. Docker stores pulled images keyed by the
// `fromImage` name, so a pull of `mirror.aocr.aerol.ai/aocr/ghcr/foo:v1`
// lands ONLY under that name — subsequent inspect/Create calls keyed off
// the original `ghcr.io/foo:v1` 404. We add the alias here so the rest
// of the pull path (Create's `imageInspect(req.Image)` and `Image:
// req.Image` in the container spec) keeps working unchanged.
//
// Pre-conditions for tagging:
//   - The rewrite actually fired (Rewritten=true). Passthrough pulls
//     (Docker Hub, unknown host, mirror disabled) already land under
//     the original ref — no alias needed.
//   - The original ref is tag-based, not digest-based. Digest pulls
//     are content-addressable and inspect resolves them via image ID
//     regardless of which name they were pulled under.
func (c *Client) aliasMirrorPull(ctx context.Context, rewrite MirrorRewrite) error {
	if !rewrite.Rewritten {
		return nil
	}
	if strings.Contains(rewrite.OriginalRef, "@") {
		return nil
	}
	repo, tag := splitDestRef(rewrite.OriginalRef)
	if repo == "" {
		return nil
	}
	return c.tagImage(ctx, rewrite.RewrittenRef, repo, tag)
}

// firePullObserver invokes the registered observer iff the pull was a
// private-image pull that went through the mirror — the F21 precondition.
// Anonymous pulls (no auth), pass-through pulls (no rewrite), missing sandbox
// ID, and an unset observer all short-circuit cheaply.
func (c *Client) firePullObserver(ctx context.Context, rewrite MirrorRewrite, auth *models.RegistryAuth) {
	if c.pullObserver == nil || !rewrite.Rewritten {
		return
	}
	if auth == nil || strings.TrimSpace(auth.Username) == "" {
		return
	}
	sandboxID := sandboxIDFromContext(ctx)
	if sandboxID == "" {
		return
	}
	c.pullObserver(ctx, sandboxID)
}

func (c *Client) pullImageDedup(ctx context.Context, imageRef string, auth *models.RegistryAuth) error {
	finishMetric := beginImagePullMetric()
	var resultErr error
	defer func() { finishMetric(resultErr) }()

	// Back-fill the cluster PAT for AOCR `cluster/...` refs when the caller
	// supplied no credentials. This is the single chokepoint for both consumer
	// paths that pull cluster-owned artifacts anonymously today: the create-path
	// snapshot pull (Create) and the Firecracker template puller (PullImage).
	// Resolving here — before the dedup key is computed — keeps the key,
	// backoff, and pull all keyed off the credential that will actually be used.
	// No-op (returns nil) for non-AOCR hosts, non-cluster repos, or when AOCR
	// pull auth was never configured.
	if auth == nil {
		auth = c.resolveAOCRPullAuth(imageRef)
	}

	key := imagePullKey(imageRef, auth)
	c.pullMu.Lock()
	if inFlight := c.pulls[key]; inFlight != nil {
		recordImagePullDedupWaiter()
		c.pullMu.Unlock()
		select {
		case <-ctx.Done():
			resultErr = ctx.Err()
			return resultErr
		case <-inFlight.done:
			resultErr = inFlight.err
			return resultErr
		}
	}
	if failure, blocked := c.pullBackoffFailureLocked(key, time.Now()); blocked {
		recordImagePullBackoffReject()
		c.pullMu.Unlock()
		resultErr = fmt.Errorf("pull image %s suppressed by failure backoff until %s: %w", imageRef, failure.retryAt.Format(time.RFC3339), failure.err)
		return resultErr
	}
	inFlight := &imagePull{done: make(chan struct{})}
	c.pulls[key] = inFlight
	c.pullMu.Unlock()

	slotAcquired, err := c.acquirePullSlot(ctx)
	if err != nil {
		inFlight.err = err
	} else {
		inFlight.err = c.pullImage(ctx, imageRef, auth)
		if slotAcquired {
			c.releasePullSlot()
		}
	}

	c.pullMu.Lock()
	delete(c.pulls, key)
	c.recordPullFailureLocked(key, inFlight.err)
	c.pullMu.Unlock()
	close(inFlight.done)
	resultErr = inFlight.err
	return resultErr
}

func (c *Client) pullBackoffFailureLocked(key string, now time.Time) (imagePullFailure, bool) {
	if c.pullBackoff <= 0 || c.pullFailures == nil {
		return imagePullFailure{}, false
	}
	failure, ok := c.pullFailures[key]
	if !ok {
		return imagePullFailure{}, false
	}
	if now.Before(failure.retryAt) {
		return failure, true
	}
	delete(c.pullFailures, key)
	return imagePullFailure{}, false
}

func (c *Client) recordPullFailureLocked(key string, err error) {
	if c.pullFailures == nil {
		c.pullFailures = make(map[string]imagePullFailure)
	}
	if err == nil || c.pullBackoff <= 0 {
		delete(c.pullFailures, key)
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		delete(c.pullFailures, key)
		return
	}
	now := time.Now()
	c.pullFailures[key] = imagePullFailure{
		err:       err,
		createdAt: now,
		retryAt:   now.Add(c.pullBackoff),
	}
	// Opportunistically prune entries whose backoff window has already
	// elapsed: they would normally be deleted lazily on the next pull of the
	// same key, but a unique image/auth combination that fails once and is
	// never retried would otherwise sit in the map forever. We bound the
	// per-call work so the lock stays cheap even with a large map.
	pruneExpiredPullFailuresLocked(c.pullFailures, now, pullFailureMaxPrunePerCall)
}

// pullFailureMaxPrunePerCall caps how many expired entries a single
// recordPullFailureLocked call evicts. The bound keeps the critical section
// short under pull-storm conditions; subsequent calls keep draining the map.
const pullFailureMaxPrunePerCall = 32

func pruneExpiredPullFailuresLocked(failures map[string]imagePullFailure, now time.Time, budget int) {
	if budget <= 0 || len(failures) == 0 {
		return
	}
	for key, failure := range failures {
		if budget == 0 {
			return
		}
		if !now.Before(failure.retryAt) {
			delete(failures, key)
			budget--
		}
	}
}

func (c *Client) acquirePullSlot(ctx context.Context) (bool, error) {
	if c.pullSlots == nil {
		return false, nil
	}
	select {
	case c.pullSlots <- struct{}{}:
		imagePullInflight.Add(1)
		return true, nil
	default:
	}
	imagePullQueued.Add(1)
	defer imagePullQueued.Add(-1)
	select {
	case c.pullSlots <- struct{}{}:
		imagePullInflight.Add(1)
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (c *Client) releasePullSlot() {
	if c.pullSlots == nil {
		return
	}
	select {
	case <-c.pullSlots:
		imagePullInflight.Add(-1)
	default:
	}
}

func imagePullKey(imageRef string, auth *models.RegistryAuth) string {
	if auth == nil {
		return strings.TrimSpace(imageRef)
	}
	return strings.TrimSpace(imageRef) + "\x00" + strings.TrimSpace(auth.Server) + "\x00" + strings.TrimSpace(auth.Username)
}

func IsLocalOnlyImageRef(imageRef string) bool {
	imageRef = strings.TrimSpace(imageRef)
	return strings.HasPrefix(imageRef, BuiltImageNamespace+"/") || strings.HasPrefix(imageRef, "snapshots/")
}

func (c *Client) waitForRuntime(ctx context.Context, containerRef string) (*SandboxRuntime, error) {
	containerIP, inspect, err := c.waitForContainerRunning(ctx, containerRef)
	if err != nil {
		return nil, err
	}
	if _, err := c.waitForToolboxReady(ctx, containerIP, nil); err != nil {
		return nil, err
	}
	return &SandboxRuntime{
		SandboxID:   sandboxIDFromContainerName(inspect.Name),
		ContainerID: inspect.ID,
		ContainerIP: containerIP,
		Status:      models.SandboxStatusStarted,
	}, nil
}

func (c *Client) waitForContainerRunning(ctx context.Context, containerRef string) (string, containerInspect, error) {
	deadline := time.Now().Add(c.waitTimeout)
	sleep := c.readinessPollInterval()
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", containerInspect{}, err
		}
		inspect, err := c.inspectContainer(ctx, containerRef)
		if err != nil {
			return "", containerInspect{}, fmt.Errorf("inspect container: %w", err)
		}
		containerIP := getContainerIP(inspect, c.network)
		if inspect.State != nil && inspect.State.Running && containerIP != "" {
			return containerIP, inspect, nil
		}
		time.Sleep(sleep())
	}
	return "", containerInspect{}, fmt.Errorf("timed out waiting for sandbox runtime: %s", containerRef)
}

func (c *Client) waitForToolboxReady(ctx context.Context, containerIP string, listener *ReadyListener) (string, error) {
	if listener == nil {
		// Push disabled (non-cluster) — plain health poll. Deliberately do not
		// touch readySocketFallbackHealth: there was no socket to fall back
		// from, and counting disabled-path creates here would make the metric
		// useless for spotting real socket losses (old toolbox image, gVisor
		// without host-uds) in cluster mode.
		if err := c.pollToolboxHealth(ctx, containerIP); err != nil {
			return "", err
		}
		return "health", nil
	}

	start := time.Now()
	raceCtx, cancel := context.WithTimeout(ctx, c.toolboxWaitTimeout)
	defer cancel()

	type result struct {
		source string
		err    error
	}
	ch := make(chan result, 2)

	go func() {
		err := listener.Wait(raceCtx)
		select {
		case ch <- result{source: "socket", err: err}:
		case <-raceCtx.Done():
		}
	}()

	go func() {
		timer := time.NewTimer(readyHealthPollGrace)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-raceCtx.Done():
			return
		}
		err := c.pollToolboxHealth(raceCtx, containerIP)
		select {
		case ch <- result{source: "health", err: err}:
		case <-raceCtx.Done():
		}
	}()

	res := <-ch
	cancel()
	// Drain the loser so its goroutine can exit without leaking a dial.
	go func() {
		select {
		case <-ch:
		case <-time.After(c.toolboxWaitTimeout):
		}
	}()

	if res.err != nil {
		return "", res.err
	}
	waitMS := time.Since(start).Milliseconds()
	if res.source == "socket" {
		recordReadySocketHit(waitMS)
	} else {
		recordReadySocketFallback(waitMS)
	}
	return res.source, nil
}

func (c *Client) pollToolboxHealth(ctx context.Context, containerIP string) error {
	target := fmt.Sprintf("http://%s:%d/health", containerIP, c.toolboxPort)
	deadline := time.Now().Add(c.toolboxWaitTimeout)
	sleep := c.readinessPollInterval()
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		resp, err := c.toolboxClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(sleep())
	}
	return fmt.Errorf("toolbox did not become healthy on %s", target)
}

func (c *Client) readinessPollInterval() func() time.Duration {
	initial := c.readinessPollInit
	if initial <= 0 {
		initial = 20 * time.Millisecond
	}
	maximum := c.readinessPollMax
	if maximum < initial {
		maximum = 300 * time.Millisecond
	}
	cur := initial
	return func() time.Duration {
		d := cur
		if cur < maximum {
			cur *= 2
			if cur > maximum {
				cur = maximum
			}
		}
		return d
	}
}

func (c *Client) waitForToolbox(ctx context.Context, containerIP string) error {
	_, err := c.waitForToolboxReady(ctx, containerIP, nil)
	return err
}

func (c *Client) inspectContainer(ctx context.Context, id string) (containerInspect, error) {
	var inspect containerInspect
	err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, nil, &inspect)
	return inspect, err
}

func (c *Client) inspectImage(ctx context.Context, imageRef string) (imageInspect, error) {
	var inspect imageInspect
	err := c.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(imageRef)+"/json", nil, nil, nil, &inspect)
	return inspect, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, requestBody any, headers map[string]string, responseBody any) error {
	response, err := c.doRequest(ctx, method, path, query, requestBody, headers)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if responseBody == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(response.Body).Decode(responseBody)
}

func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values, requestBody any, headers map[string]string) (*http.Response, error) {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}

	target := "http://docker" + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("docker API %s %s failed with status %d: %s", method, path, response.StatusCode, strings.TrimSpace(string(data)))
	}
	return response, nil
}

func getContainerIP(inspect containerInspect, preferredNetwork string) string {
	if preferredNetwork != "" {
		if endpoint, ok := inspect.NetworkSettings.Networks[preferredNetwork]; ok && endpoint.IPAddress != "" {
			return endpoint.IPAddress
		}
	}

	for _, endpoint := range inspect.NetworkSettings.Networks {
		if endpoint.IPAddress != "" {
			return endpoint.IPAddress
		}
	}

	return ""
}

func containerStatus(inspect containerInspect) models.SandboxStatus {
	if inspect.State == nil {
		return models.SandboxStatusError
	}
	if inspect.State.Running {
		return models.SandboxStatusStarted
	}
	if inspect.State.Status == "exited" || inspect.State.Status == "created" {
		return models.SandboxStatusStopped
	}
	return models.SandboxStatusError
}

type imageInspect struct {
	Config struct {
		WorkingDir string   `json:"WorkingDir"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"Config"`
	Metadata struct {
		// LastTagTime is updated by the daemon every time the image is
		// (re)tagged. We use it as the "freshness" signal for built-image GC
		// because a content-cache-hit build returns an image whose Created
		// timestamp may be days old — but the tag was just written.
		LastTagTime time.Time `json:"LastTagTime"`
	} `json:"Metadata"`
}

type containerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State *struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
		Pid     int    `json:"Pid"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	HostConfig struct {
		Binds []string `json:"Binds"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

type containerSummary struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

func splitSnapshotImageRef(imageRef string) (repo, tag string, err error) {
	trimmed := strings.TrimSpace(imageRef)
	if trimmed == "" {
		return "", "", errors.New("snapshot name is required")
	}
	if strings.Contains(trimmed, "@") {
		return "", "", errors.New("snapshot name must not include a digest")
	}
	lastSlash := strings.LastIndex(trimmed, "/")
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon > lastSlash {
		repo = trimmed[:lastColon]
		tag = trimmed[lastColon+1:]
		if strings.TrimSpace(repo) == "" || strings.TrimSpace(tag) == "" {
			return "", "", errors.New("snapshot name must be a valid image reference")
		}
		return repo, tag, nil
	}
	return trimmed, "", nil
}

func queryValues(values map[string]string) url.Values {
	if len(values) == 0 {
		return nil
	}
	query := url.Values{}
	for key, value := range values {
		query.Set(key, value)
	}
	return query
}

func (c *Client) removeContainer(ctx context.Context, containerRef string, force bool) error {
	query := url.Values{}
	if force {
		query.Set("force", "1")
	}
	err := c.doJSON(ctx, http.MethodDelete, "/containers/"+url.PathEscape(containerRef), query, nil, nil, nil)
	if err == nil {
		return nil
	}
	// 404 = already gone. The post-condition we want ("container no longer
	// exists") is already satisfied, so swallow it. Without this, a retry of
	// a destroy that partially succeeded — or a destroy that races a
	// `docker rm` / `--rm`-on-exit / lifecycle auto-destroy on the same
	// container — propagates an error up through Service.DestroySandbox,
	// which then skips the post-destroy cleanup the caller relies on (e.g.
	// runLifecycleSweep's else-branch DeletePlacement). The result is a
	// stranded FSM placement pointing at a node with no container.
	// 409 is intentionally NOT benign: with force=true Docker won't return
	// 409 for "container in use", so a 409 here means a real constraint
	// the caller needs to see.
	if isContainerRemoveBenignError(err.Error()) {
		return nil
	}
	return err
}

// isContainerRemoveBenignError matches the substring doRequest emits for HTTP
// 404 from the Docker daemon when deleting a container. The post-condition of
// removeContainer is "container is gone"; 404 means it already is.
func isContainerRemoveBenignError(message string) bool {
	return strings.Contains(message, "status 404")
}

// RemoveImage deletes an image from the local Docker daemon by reference
// (name:tag or digest). 404 (already gone) and 409 (still in use) are treated
// as success: the goal is "image is no longer occupying disk on our account",
// and a 409 means another container raced ahead and started using the image
// between the caller's eligibility check and this call — leaving it is
// correct, not an error. Other failures are returned for the caller to log.
func (c *Client) RemoveImage(ctx context.Context, imageRef string) error {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return nil
	}
	err := c.doJSON(ctx, http.MethodDelete, "/images/"+url.PathEscape(imageRef), nil, nil, nil, nil)
	if err == nil {
		return nil
	}
	if isImageRemoveBenignError(err.Error()) {
		return nil
	}
	return err
}

// isImageRemoveBenignError matches the substrings doRequest emits for HTTP
// 404 and 409 from the Docker daemon. Both are non-failures for image GC:
// 404 = already deleted, 409 = something is referencing it, leave it alone.
func isImageRemoveBenignError(message string) bool {
	return strings.Contains(message, "status 404") || strings.Contains(message, "status 409")
}

// sandboxIDFromContainerName extracts the sandbox ID from Docker's container
// name field. Docker stores names with a leading slash (e.g. "/abc123def456");
// we trim it. The sandbox ID is the canonical identifier we set as the
// container's name at create time.
func sandboxIDFromContainerName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "/")
	return name
}
