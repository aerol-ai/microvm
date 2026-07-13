package containerd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Create provisions and starts a managed task in the aerolvm namespace.
func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	// Validate the ID charset BEFORE it is used to build host filesystem
	// paths (host files dir, task log). The ID can arrive attacker-controlled
	// via the X-Cluster-Create-ID header; without this a "../"-laden ID would
	// traverse out of RunDir/LogDir on write, and the failure-path RemoveAll
	// would delete an attacker-chosen host directory. Mirrors the docker and
	// firecracker drivers' defense-in-depth check.
	if err := validateSandboxID(sandboxID); err != nil {
		return nil, err
	}
	if err := d.ensureToolboxBinary(); err != nil {
		return nil, err
	}
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}

	effectiveRuntime := strings.TrimSpace(req.Runtime)
	if effectiveRuntime == "" {
		effectiveRuntime = d.cfg.DefaultRuntime
	}
	logf := func(msg string, args ...any) { d.logger.Warn(msg, args...) }
	if err := models.ValidateRuntimeRequest(req, effectiveRuntime, d.cfg.Privileged, logf); err != nil {
		return nil, err
	}
	ociRuntime, err := models.ResolveOCIRuntime(effectiveRuntime)
	if err != nil {
		return nil, err
	}

	if d.warmPool != nil {
		if warm, warmErr := d.tryWarmAdopt(ctx, req, sandboxID, toolboxToken, hostMounts, effectiveRuntime); warmErr == nil {
			return warm, nil
		} else if errors.Is(warmErr, dockerpkg.ErrSandboxContainerExists) {
			return nil, warmErr
		} else if !errors.Is(warmErr, containerdpool.ErrNoSlot) {
			d.logger.Warn("containerd warm adopt failed; falling back to cold create",
				"sandbox_id", sandboxID, "error", warmErr)
		}
	}

	var (
		netnsPath        string
		prepaidIP        string
		netnsProvisioned bool
	)
	if d.cfg.NativeNetnsPool && d.netns != nil {
		netnsPath, prepaidIP, err = d.netns.Provision(ctx, sandboxID)
		if err != nil {
			return nil, fmt.Errorf("provision netns: %w", err)
		}
		netnsProvisioned = true
		createtiming.From(ctx).RecordStageDesc("containerd_netns", 0, "provisioned")
	}

	committed := false
	// createdContainer gates host-side teardown: a caller that loses the
	// concurrent-duplicate race (AlreadyExists at NewContainer) must NOT run
	// LIFO teardown, because the host files and ready socket are keyed by
	// sandboxID and belong to the winner — removing them would yank the bind
	// mounts out from under the live winning container.
	createdContainer := false
	var (
		container cntr.Container
		task      cntr.Task
		logPath   string
		logCloser func()
		hostFiles *sandboxHostFiles
	)
	defer func() {
		if committed || !createdContainer {
			if logCloser != nil {
				logCloser()
			}
			return
		}
		if logCloser != nil {
			logCloser()
		}
		d.lifoTeardown(ctx, client, container, task, logPath, hostFiles)
	}()
	defer func() {
		if committed || !netnsProvisioned || d.netns == nil {
			return
		}
		_ = d.netns.Release(ctx, sandboxID)
	}()

	imageStart := time.Now()
	image, err := d.ensureImage(ctx, client, req.Image, req.Registry)
	if err != nil {
		return nil, err
	}
	createtiming.From(ctx).RecordStageDesc("containerd_image", time.Since(imageStart), "resolved")

	hostFiles, err = prepareSandboxHostFiles(d.cfg.RunDir, sandboxID)
	if err != nil {
		return nil, err
	}

	envValues := buildEnv(req, sandboxID, toolboxToken, d.cfg.ToolboxPort)
	userCommand := req.ContainerCommand
	if len(userCommand) == 0 {
		userCommand, err = imageDefaultCommand(ctx, client, image)
		if err != nil {
			return nil, fmt.Errorf("read image command: %w", err)
		}
	}

	var readyListener *dockerpkg.ReadyListener
	var readySocketCreated bool
	var keepReadySocket bool
	defer func() {
		if readyListener != nil {
			_ = readyListener.Close()
		}
		// Only reap the ready socket when this call owns it: on success we keep
		// it, and on the AlreadyExists loser path (!createdContainer) it belongs
		// to the winner — RemoveReadySocketsForSandbox is keyed by sandboxID and
		// would nuke the winner's socket too.
		if readySocketCreated && !keepReadySocket && createdContainer {
			dockerpkg.RemoveReadySocketsForSandbox(d.cfg.ReadyDir, sandboxID)
		}
	}()

	// Assemble the COMPLETE spec-opts slice before handing it to
	// cntr.WithNewSpec. A variadic spread captures the slice at the call site;
	// appending security/resource/ready opts afterward would silently drop
	// them (append reallocates, leaving the WithNewSpec closure bound to the
	// old backing array) — every non-privileged sandbox would then run with no
	// seccomp, no NoNewPrivileges, no cap trim, and no cgroup limits.
	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(image),
		oci.WithProcessArgs(append([]string{d.cfg.ToolboxMountPath}, userCommand...)...),
		oci.WithHostname(sandboxID),
	}
	if !d.cfg.Privileged {
		specOpts = append(specOpts, securitySpecOpts()...)
	}
	if !d.cfg.ResourceLimitsOff {
		specOpts = append(specOpts, resourceSpecOpts(req)...)
	}
	if netnsPath != "" {
		specOpts = append(specOpts, withNetworkNamespace(netnsPath))
	}
	mountSpecs := buildMounts(d.cfg, hostFiles, hostMounts)

	if d.cfg.ReadyEnabled {
		readyListener, err = d.setupReadySocket(&envValues, &mountSpecs, sandboxID, toolboxToken)
		if err != nil {
			return nil, err
		}
		readySocketCreated = true
	}
	// Env and mounts are finalized here (setupReadySocket may have appended to
	// both), then applied last so nothing is lost to slice capture.
	sort.Strings(envValues)
	specOpts = append(specOpts, oci.WithEnv(envValues), oci.WithMounts(mountSpecs))

	containerLabels := map[string]string{
		managedLabelKey:   "true",
		sandboxIDLabelKey: sandboxID,
	}
	if leaseID, err := d.pinImageLease(ctx, client, image); err != nil {
		return nil, err
	} else if leaseID != "" {
		containerLabels[imageLeaseLabelKey] = leaseID
	}

	containerOpts := []cntr.NewContainerOpts{
		cntr.WithImage(image),
		cntr.WithNewSnapshot(sandboxID, image),
		cntr.WithNewSpec(specOpts...),
		cntr.WithContainerLabels(containerLabels),
	}
	if ociRuntime != "" {
		opt, err := d.runtimeContainerOpt(ociRuntime)
		if err != nil {
			return nil, err
		}
		if opt != nil {
			containerOpts = append(containerOpts, opt)
		}
	}

	createStart := time.Now()
	container, err = client.NewContainer(ctx, sandboxID, containerOpts...)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil, fmt.Errorf("%w: sandbox container already exists", dockerpkg.ErrSandboxContainerExists)
		}
		return nil, fmt.Errorf("create container: %w", err)
	}
	createdContainer = true

	logPath, err = d.taskLogPath(sandboxID)
	if err != nil {
		return nil, err
	}
	logIO, closeLog, err := taskLogIO(logPath)
	if err != nil {
		return nil, err
	}
	logCloser = closeLog

	task, err = container.NewTask(ctx, logIO)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	createtiming.From(ctx).RecordStage("containerd_create", time.Since(createStart))

	startStart := time.Now()
	if err := task.Start(ctx); err != nil {
		return nil, fmt.Errorf("start task: %w", err)
	}
	createtiming.From(ctx).RecordStage("containerd_start", time.Since(startStart))

	state, err := d.runtimeStateAfterStart(ctx, container, task, sandboxID, prepaidIP)
	if err != nil {
		return nil, err
	}

	if d.cfg.ReadyEnabled && readyListener != nil {
		if err := readyListener.Wait(ctx); err != nil {
			return nil, fmt.Errorf("ready socket: %w", err)
		}
		keepReadySocket = true
	} else if err := d.waitToolboxHTTP(ctx, state.ContainerIP, toolboxToken); err != nil {
		return nil, err
	}

	if req.NetworkBlockAll && state.ContainerIP != "" {
		netrulesStart := time.Now()
		if err := d.ApplyNetworkBlockAll(state.ContainerIP); err != nil {
			return nil, fmt.Errorf("apply network block: %w", err)
		}
		createtiming.From(ctx).RecordStage("containerd_netrules", time.Since(netrulesStart))
	}
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := d.ApplyEgressPolicy(state.ContainerIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			return nil, fmt.Errorf("apply egress policy: %w", err)
		}
	}

	committed = true
	return state, nil
}

func (d *Driver) Start(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	container, err := client.LoadContainer(ctx, containerRef)
	if err != nil {
		return nil, fmt.Errorf("load container: %w", err)
	}
	task, err := container.Task(ctx, nil)
	if err == nil {
		status, statusErr := task.Status(ctx)
		if statusErr == nil && status.Status == cntr.Running {
			return d.runtimeStateAfterStart(ctx, container, task, containerRef, "")
		}
		_, _ = task.Delete(ctx, cntr.WithProcessKill)
	}
	logPath, err := d.taskLogPath(containerRef)
	if err != nil {
		return nil, err
	}
	logIO := cio.LogFile(logPath)
	task, err = container.NewTask(ctx, logIO)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	if err := task.Start(ctx); err != nil {
		return nil, fmt.Errorf("start task: %w", err)
	}
	return d.runtimeStateAfterStart(ctx, container, task, containerRef, "")
}

func (d *Driver) Stop(ctx context.Context, containerRef string) error {
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	container, err := client.LoadContainer(ctx, containerRef)
	if err != nil {
		return fmt.Errorf("load container: %w", err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil
	}
	_ = task.Kill(ctx, syscall.SIGTERM)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, statusErr := task.Status(ctx)
		if statusErr == nil && status.Status != cntr.Running {
			_, err = task.Delete(ctx)
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	_ = task.Kill(ctx, syscall.SIGKILL)
	_, err = task.Delete(ctx, cntr.WithProcessKill)
	return err
}

func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox != nil {
		_ = d.ClearNetworkRules(sandbox.ContainerIP)
		_ = d.ClearEgressPolicy(sandbox.ContainerIP, sandbox.NetworkAllowOut, sandbox.NetworkDenyOut)
	}
	if sandbox == nil {
		return nil
	}
	if d.netns != nil {
		_ = d.netns.Release(ctx, sandbox.ID)
	}
	dockerpkg.RemoveReadySocketsForSandbox(d.cfg.ReadyDir, sandbox.ID)
	_ = d.removeHostFiles(sandbox.ID)
	_ = d.removeTaskLog(sandbox.ID)

	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	ref := strings.TrimSpace(sandbox.ContainerID)
	if ref == "" {
		ref = sandbox.ID
	}
	container, err := client.LoadContainer(ctx, ref)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	if labels, lerr := container.Labels(ctx); lerr == nil {
		d.releaseImageLease(ctx, client, labels)
	}
	if task, taskErr := container.Task(ctx, nil); taskErr == nil {
		_ = task.Kill(ctx, syscall.SIGKILL)
		_, _ = task.Delete(ctx, cntr.WithProcessKill)
	}
	return container.Delete(ctx, cntr.WithSnapshotCleanup)
}

func (d *Driver) Inspect(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	container, err := client.LoadContainer(ctx, containerRef)
	if err != nil {
		return nil, err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return &models.SandboxRuntimeState{
			SandboxID:   d.sandboxIDFromContainer(ctx, container),
			ContainerID: containerRef,
			Status:      models.SandboxStatusStopped,
		}, nil
	}
	sandboxID := d.sandboxIDFromContainer(ctx, container)
	return d.runtimeStateAfterStart(ctx, container, task, sandboxID, "")
}

func (d *Driver) sandboxIDFromContainer(ctx context.Context, container cntr.Container) string {
	if container == nil {
		return ""
	}
	id := container.ID()
	labels, err := container.Labels(ctx)
	if err == nil {
		if sid := strings.TrimSpace(labels[sandboxIDLabelKey]); sid != "" {
			return sid
		}
	}
	return id
}

func (d *Driver) ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	containers, err := client.ListContainers(ctx, "labels."+managedLabelKey)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*models.SandboxRuntimeState, len(containers))
	for _, container := range containers {
		labels, lerr := container.Labels(ctx)
		if lerr != nil || IsParkedContainerLabels(labels) {
			continue
		}
		id := container.ID()
		state, err := d.Inspect(ctx, id)
		if err != nil {
			continue
		}
		if state.SandboxID == "" || IsParkedSandboxID(state.SandboxID) {
			continue
		}
		out[state.SandboxID] = state
	}
	return out, nil
}

func (d *Driver) Resize(ctx context.Context, containerRef string, req models.ResizeSandboxRequest) error {
	return fmt.Errorf("containerd live resize is not implemented yet")
}

func (d *Driver) RemoveImage(ctx context.Context, imageRef string) error {
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return nil
	}
	return removeImageFn(ctx, client, imageRef)
}

// removeImageFn deletes an image from the containerd image store. Tests stub it.
var removeImageFn = func(ctx context.Context, client *Client, imageRef string) error {
	raw := client.Raw()
	if raw == nil {
		return errors.New("containerd RemoveImage requires live containerd")
	}
	ctx = client.withNS(ctx)
	if err := raw.ImageService().Delete(ctx, imageRef); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	return nil
}

func buildEnv(req models.CreateSandboxRequest, sandboxID, toolboxToken string, toolboxPort int) []string {
	envValues := []string{
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", toolboxPort),
		"SB_TOOLBOX_TOKEN=" + toolboxToken,
		"SB_SANDBOX_ID=" + sandboxID,
	}
	for key, value := range req.Env {
		envValues = append(envValues, key+"="+value)
	}
	sort.Strings(envValues)
	return envValues
}

func buildMounts(cfg Config, hostFiles *sandboxHostFiles, hostMounts []mounts.ContainerBind) []specs.Mount {
	mountsOut := []specs.Mount{
		{Type: "bind", Source: cfg.ToolboxBinaryPath, Destination: cfg.ToolboxMountPath, Options: []string{"rbind", "ro"}},
		{Type: "bind", Source: hostFiles.ResolvConf, Destination: "/etc/resolv.conf", Options: []string{"rbind", "ro"}},
		{Type: "bind", Source: hostFiles.Hosts, Destination: "/etc/hosts", Options: []string{"rbind", "ro"}},
		{Type: "bind", Source: hostFiles.Hostname, Destination: "/etc/hostname", Options: []string{"rbind", "ro"}},
	}
	for _, m := range hostMounts {
		opt := []string{"rbind"}
		if m.ReadOnly {
			opt = append(opt, "ro")
		}
		mountsOut = append(mountsOut, specs.Mount{
			Type:        "bind",
			Source:      m.HostPath,
			Destination: m.ContainerPath,
			Options:     opt,
		})
	}
	return mountsOut
}

func (d *Driver) ensureImage(ctx context.Context, client *Client, ref string, auth *models.RegistryAuth) (cntr.Image, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("image reference is required")
	}
	if image, err := client.GetImage(ctx, ref); err == nil {
		return image, nil
	}
	// Recent-failure backoff: don't hammer a registry that just rejected us on
	// a burst of cold creates for the same missing/erroring ref.
	if backoff := d.cfg.PullFailureBackoff; backoff > 0 {
		d.pullFailMu.Lock()
		until, ok := d.pullFailUntil[ref]
		d.pullFailMu.Unlock()
		if ok && time.Now().Before(until) {
			return nil, fmt.Errorf("image pull for %q backing off after recent failure", ref)
		}
	}
	// Single-flight: N concurrent cold creates of the same missing image
	// collapse to one registry pull. Concurrency across distinct refs is
	// capped by the pull semaphore.
	res, err, _ := d.pullGroup.Do(ref, func() (any, error) {
		if d.pullSem != nil {
			select {
			case d.pullSem <- struct{}{}:
				defer func() { <-d.pullSem }()
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// Re-check inside the flight: a sibling create may have unpacked it.
		if image, getErr := client.GetImage(ctx, ref); getErr == nil {
			return image, nil
		}
		// WithPullUnpack is mandatory: cntr.WithNewSnapshot expects the image
		// layers unpacked into the snapshotter, and a bare Pull does not unpack.
		opts := []cntr.RemoteOpt{cntr.WithPullUnpack}
		if a := auth; a != nil && a.Username != "" {
			refHost := registryHost(ref)
			opts = append(opts, cntr.WithResolver(docker.NewResolver(docker.ResolverOptions{
				// Scope creds to the ref's own registry host. Returning creds
				// for every host would leak them to foreign-layer / redirect
				// hosts the manifest resolution touches.
				Authorizer: docker.NewDockerAuthorizer(docker.WithAuthCreds(func(host string) (string, string, error) {
					if refHost != "" && host != refHost {
						return "", "", nil
					}
					return a.Username, a.Password, nil
				})),
			})))
		}
		return client.PullImage(ctx, ref, opts...)
	})
	if err != nil {
		if backoff := d.cfg.PullFailureBackoff; backoff > 0 {
			d.pullFailMu.Lock()
			d.pullFailUntil[ref] = time.Now().Add(backoff)
			d.pullFailMu.Unlock()
		}
		return nil, err
	}
	return res.(cntr.Image), nil
}

// registryHost extracts the registry hostname from an image ref. Docker Hub
// short refs (no host component) return "" so the authorizer matches the
// resolver's own default-registry canonicalization.
func registryHost(ref string) string {
	slash := strings.IndexByte(ref, '/')
	if slash < 0 {
		return ""
	}
	first := ref[:slash]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return ""
}

func (d *Driver) ensureToolboxBinary() error {
	if strings.TrimSpace(d.cfg.ToolboxBinaryPath) == "" {
		return errors.New("SB_TOOLBOX_BINARY_PATH is required")
	}
	if _, err := os.Stat(d.cfg.ToolboxBinaryPath); err != nil {
		return fmt.Errorf("toolbox binary: %w", err)
	}
	return nil
}

// setupReadySocket mints the per-create readiness listener and appends its env
// vars and the guest bind mount to the caller's slices. Both are applied to
// the OCI spec by the caller AFTER this returns, so nothing is lost to slice
// capture.
func (d *Driver) setupReadySocket(env *[]string, mountSpecs *[]specs.Mount, sandboxID, toolboxToken string) (*dockerpkg.ReadyListener, error) {
	if err := dockerpkg.EnsureReadyDir(d.cfg.ReadyDir); err != nil {
		return nil, err
	}
	nonce, err := dockerpkg.MintReadyNonce()
	if err != nil {
		return nil, err
	}
	readyListener, err := dockerpkg.NewReadyListener(d.cfg.ReadyDir, sandboxID, toolboxToken, nonce)
	if err != nil {
		return nil, err
	}
	*env = append(*env, readyListener.EnvVars()...)
	*mountSpecs = append(*mountSpecs, specs.Mount{
		Type: "bind", Source: readyListener.HostSocketPath(), Destination: dockerpkg.GuestReadySocketPath, Options: []string{"rbind"},
	})
	return readyListener, nil
}

func (d *Driver) lifoTeardown(ctx context.Context, client *Client, container cntr.Container, task cntr.Task, logPath string, hostFiles *sandboxHostFiles) {
	if task != nil {
		_ = task.Kill(ctx, syscall.SIGKILL)
		_, _ = task.Delete(ctx, cntr.WithProcessKill)
	}
	if container != nil {
		_ = container.Delete(ctx, cntr.WithSnapshotCleanup)
	}
	if logPath != "" {
		_ = os.Remove(logPath)
	}
	if hostFiles != nil {
		_ = os.RemoveAll(hostFiles.Dir)
	}
}

func (d *Driver) runtimeStateAfterStart(ctx context.Context, container cntr.Container, task cntr.Task, sandboxID, ipHint string) (*models.SandboxRuntimeState, error) {
	ip, err := containerIPv4FromTaskFn(ctx, task)
	if err != nil && strings.TrimSpace(ipHint) != "" {
		ip = ipHint
		err = nil
	}
	if err != nil {
		return nil, err
	}
	containerID := sandboxID
	if container != nil {
		containerID = container.ID()
	}
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: containerID,
		ContainerIP: ip,
		Status:      models.SandboxStatusStarted,
	}, nil
}

func (d *Driver) waitToolboxHTTP(ctx context.Context, containerIP, toolboxToken string) error {
	_ = toolboxToken
	if containerIP == "" {
		return errors.New("container IP is not available for toolbox probe")
	}
	deadline := time.Now().Add(d.cfg.ToolboxWaitTimeout)
	interval := d.cfg.ReadinessPollInit
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}
	maxInterval := d.cfg.ReadinessPollMax
	if maxInterval <= 0 {
		maxInterval = time.Second
	}
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Health poll is implemented in pkg/docker; containerd reuses the same toolbox port contract.
		if err := pollToolboxHealthFn(ctx, containerIP, d.cfg.ToolboxPort); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
		if interval < maxInterval {
			interval *= 2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
	return fmt.Errorf("toolbox did not become ready within %s", d.cfg.ToolboxWaitTimeout)
}

func (d *Driver) taskLogPath(sandboxID string) (string, error) {
	dir := strings.TrimSpace(d.cfg.LogDir)
	if dir == "" {
		return "", errors.New("containerd log dir is not configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, sandboxID+".log"), nil
}

func (d *Driver) removeTaskLog(sandboxID string) error {
	path, err := d.taskLogPath(sandboxID)
	if err != nil {
		return nil
	}
	return os.Remove(path)
}

func (d *Driver) removeHostFiles(sandboxID string) error {
	dir := filepath.Join(d.cfg.RunDir, "hosts", sandboxID)
	return os.RemoveAll(dir)
}

func resourceSpecOpts(req models.CreateSandboxRequest) []oci.SpecOpts {
	var out []oci.SpecOpts
	if req.MemoryMB > 0 {
		out = append(out, oci.WithMemoryLimit(uint64(req.MemoryMB)*1024*1024))
	}
	if req.CPU > 0 {
		// Fractional CPU is a CFS quota/period, NOT a cpuset. oci.WithCPUs sets
		// Linux.Resources.CPU.Cpus (cpuset pinning), so "0.500" would be an
		// invalid cpuset and runc would reject it. Mirror dockerd's --cpus:
		// quota = cpus * period, period = 100ms.
		const cpuPeriod uint64 = 100000
		quota := int64(req.CPU * float64(cpuPeriod))
		if quota < 1000 {
			quota = 1000
		}
		out = append(out, oci.WithCPUCFS(quota, cpuPeriod))
	}
	return out
}
