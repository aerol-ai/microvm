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

	"github.com/aerol-ai/microvm/pkg/createtiming"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Create provisions and starts a managed task in the aerolvm namespace.
func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("sandbox ID is required")
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

	committed := false
	var (
		container cntr.Container
		task      cntr.Task
		logPath   string
		hostFiles *sandboxHostFiles
	)
	defer func() {
		if committed {
			return
		}
		d.lifoTeardown(ctx, client, container, task, logPath, hostFiles)
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
		if readySocketCreated && !keepReadySocket {
			dockerpkg.RemoveReadySocketsForSandbox(d.cfg.ReadyDir, sandboxID)
		}
	}()

	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(image),
		oci.WithProcessArgs(append([]string{d.cfg.ToolboxMountPath}, userCommand...)...),
		oci.WithEnv(envValues),
		oci.WithHostname(sandboxID),
		oci.WithMounts(buildMounts(d.cfg, hostFiles, hostMounts)),
	}
	containerOpts := []cntr.NewContainerOpts{
		cntr.WithImage(image),
		cntr.WithNewSnapshot(sandboxID, image),
		cntr.WithNewSpec(specOpts...),
		cntr.WithContainerLabels(map[string]string{managedLabelKey: "true"}),
	}
	if ociRuntime != "" {
		containerOpts = append(containerOpts, cntr.WithRuntime(ociRuntime, nil))
	}
	if !d.cfg.Privileged {
		specOpts = append(specOpts, securitySpecOpts()...)
	}
	if !d.cfg.ResourceLimitsOff {
		specOpts = append(specOpts, resourceSpecOpts(req)...)
	}

	if d.cfg.ReadyEnabled {
		readyListener, err = d.setupReadySocket(&envValues, sandboxID, toolboxToken, &specOpts)
		if err != nil {
			return nil, err
		}
		readySocketCreated = true
	}

	createStart := time.Now()
	container, err = client.NewContainer(ctx, sandboxID, containerOpts...)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil, fmt.Errorf("%w: sandbox container already exists", dockerpkg.ErrSandboxContainerExists)
		}
		return nil, fmt.Errorf("create container: %w", err)
	}

	logPath, err = d.taskLogPath(sandboxID)
	if err != nil {
		return nil, err
	}

	task, err = container.NewTask(ctx, cio.LogFile(logPath))
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	createtiming.From(ctx).RecordStage("containerd_create", time.Since(createStart))

	startStart := time.Now()
	if err := task.Start(ctx); err != nil {
		return nil, fmt.Errorf("start task: %w", err)
	}
	createtiming.From(ctx).RecordStage("containerd_start", time.Since(startStart))

	state, err := d.runtimeStateAfterStart(ctx, container, task, sandboxID)
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
			return d.runtimeStateAfterStart(ctx, container, task, containerRef)
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
	return d.runtimeStateAfterStart(ctx, container, task, containerRef)
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
			SandboxID:   containerRef,
			ContainerID: containerRef,
			Status:      models.SandboxStatusStopped,
		}, nil
	}
	return d.runtimeStateAfterStart(ctx, container, task, containerRef)
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
		id := container.ID()
		state, err := d.Inspect(ctx, id)
		if err != nil {
			continue
		}
		out[state.SandboxID] = state
	}
	return out, nil
}

func (d *Driver) CreateSnapshot(ctx context.Context, containerRef, imageRef string) (string, error) {
	return "", fmt.Errorf("containerd snapshot commit is not implemented yet (plans/containerd-engine.md Phase 3)")
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
	ctx = client.withNS(ctx)
	if err := client.Raw().ImageService().Delete(ctx, imageRef); err != nil && !errdefs.IsNotFound(err) {
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
	image, err := client.GetImage(ctx, ref)
	if err == nil {
		return image, nil
	}
	opts := []cntr.RemoteOpt{}
	if auth != nil && auth.Username != "" {
		opts = append(opts, cntr.WithResolver(docker.NewResolver(docker.ResolverOptions{
			Authorizer: docker.NewDockerAuthorizer(docker.WithAuthCreds(func(host string) (string, string, error) {
				return auth.Username, auth.Password, nil
			})),
		})))
	}
	return client.PullImage(ctx, ref, opts...)
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

func (d *Driver) setupReadySocket(env *[]string, sandboxID, toolboxToken string, specOpts *[]oci.SpecOpts) (*dockerpkg.ReadyListener, error) {
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
	sort.Strings(*env)
	*specOpts = append(*specOpts, oci.WithMounts([]specs.Mount{
		{Type: "bind", Source: readyListener.HostSocketPath(), Destination: dockerpkg.GuestReadySocketPath, Options: []string{"rbind"}},
	}))
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

func (d *Driver) runtimeStateAfterStart(ctx context.Context, container cntr.Container, task cntr.Task, sandboxID string) (*models.SandboxRuntimeState, error) {
	ip, err := containerIPv4FromTask(ctx, task)
	if err != nil {
		return nil, err
	}
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: container.ID(),
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
		if err := pollToolboxHealth(ctx, containerIP, d.cfg.ToolboxPort); err == nil {
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
		out = append(out, oci.WithCPUs(fmt.Sprintf("%.3f", req.CPU)))
	}
	return out
}
