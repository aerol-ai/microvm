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

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	refdocker "github.com/distribution/reference"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
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
	// DiskGB: dockerd may enforce via StorageOpt; containerd overlayfs does not
	// (plans/containerd-engine-phase0-decisions.md DiskGB row). Soft-ignore.
	if req.DiskGB > 0 && !models.DiskGBEnforced(models.ContainerEngineContainerd, effectiveRuntime) {
		logf("ignoring disk quota: containerd overlayfs DiskGB not enforced yet", "disk_gb", req.DiskGB)
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
		// earlyRules: the request's network rules may be on prepaidIP, put
		// there before the workload started; addressReported: the create
		// was told prepaidIP (runtime.AddressObserver). Both drive the
		// failure cleanup below.
		earlyRules, addressReported bool
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
	// lostRace is set only when NewContainer returns AlreadyExists — i.e. this
	// call lost a concurrent-duplicate/retry race to a winner that already owns
	// the container. The winner owns the shared, sandboxID-keyed artifacts (host
	// files, ready socket, netns slot, image lease), so the loser must NOT tear
	// any of them down. A genuine solo failure (lostRace stays false) DOES clean
	// up its own artifacts — leaning on boot reconcile for routine cleanup is the
	// pr-review §4 anti-pattern. (The prior gate keyed teardown on
	// createdContainer, which wrongly leaked host files / ready socket / netns
	// slot / lease on any failure BEFORE NewContainer.)
	lostRace := false
	var (
		container cntr.Container
		task      cntr.Task
		logPath   string
		logCloser func()
		hostFiles *sandboxHostFiles
		leaseID   string
	)
	defer func() {
		if logCloser != nil {
			logCloser()
		}
		if committed || lostRace {
			return
		}
		// Undo in the order that keeps the sandbox shut and its address
		// clean: the workload dies first; then whatever the create keyed by
		// the address (the egress gateway attach) is told and lets go; then
		// the address's rules go, while this call still holds the slot (a
		// rule cleared after the slot is free could be the next owner's);
		// and the slot goes back to the pool last.
		d.lifoTeardown(ctx, client, container, task, logPath, hostFiles)
		if !netnsProvisioned || d.netns == nil {
			return
		}
		if addressReported {
			sbruntime.NotifyReleasingAddress(ctx, prepaidIP)
		}
		if earlyRules {
			d.clearCreateNetRules(prepaidIP, req)
		}
		_ = d.netns.Release(ctx, sandboxID)
	}()
	defer func() {
		// The image lease is created (with a random id) before NewContainer; on
		// success it rides on the container labels and Destroy releases it. On any
		// non-committed exit — including the AlreadyExists loser, whose lease id
		// differs from the winner's — it is an orphan this call must delete, or GC
		// can never reclaim the pinned layers.
		if committed || leaseID == "" {
			return
		}
		d.releaseImageLease(ctx, client, map[string]string{imageLeaseLabelKey: leaseID})
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
		// it, and on the AlreadyExists loser path (lostRace) it belongs to the
		// winner — RemoveReadySocketsForSandbox is keyed by sandboxID and would
		// nuke the winner's socket too. A genuine solo failure still reaps.
		if readySocketCreated && !keepReadySocket && !lostRace {
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
		hostPids, pidsEnv := gvisorpids.ForRuntime(ociRuntime, d.cfg.PidsLimit, req.MemoryMB)
		envValues = append(envValues, pidsEnv...)
		specOpts = append(specOpts, resourceSpecOpts(req, hostPids)...)
	}
	if netnsPath != "" {
		specOpts = append(specOpts, withNetworkNamespace(netnsPath))
	}
	specOpts = append(specOpts, withSandboxIPv6Off())
	mountSpecs := buildMounts(d.cfg, hostFiles, hostMounts)
	if ociRuntime == "runsc" {
		specOpts = append(specOpts, runscSandboxAnnotationOpt())
		mountSpecs = append(mountSpecs, runscCgroupMount())
	}

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
	if ip := strings.TrimSpace(prepaidIP); ip != "" {
		containerLabels[containerIPLabelKey] = ip
	}
	leaseID, err = d.pinImageLease(ctx, client, image)
	if err != nil {
		return nil, err
	}
	if leaseID != "" {
		containerLabels[imageLeaseLabelKey] = leaseID
	}

	containerOpts := []cntr.NewContainerOpts{
		cntr.WithImage(image),
		cntr.WithNewSnapshot(sandboxID, image),
		withNewSpec(specOpts...),
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
			lostRace = true
			return nil, fmt.Errorf("%w: sandbox container already exists", dockerpkg.ErrSandboxContainerExists)
		}
		return nil, fmt.Errorf("create container: %w", err)
	}
	// The prepaid address is this sandbox's from here (a duplicate create
	// stopped at NewContainer above), and the workload hasn't started: put
	// the request's rules on it now, so the workload never runs without
	// them (a hostname-filtered create's block-all included), and report
	// it, so the create's egress gateway attach overlaps the task start and
	// the readiness wait. The container exists, so a crash from here leaves
	// an orphan whose Destroy clears these rules.
	if ip := strings.TrimSpace(prepaidIP); ip != "" {
		earlyRules = true
		netrulesStart := time.Now()
		if err := d.applyCreateNetRules(ip, req); err != nil {
			return nil, err
		}
		if hasCreateNetRules(req) {
			createtiming.From(ctx).RecordStage("containerd_netrules", time.Since(netrulesStart))
		}
		addressReported = true
		sbruntime.NotifyAddressKnown(ctx, ip)
	}

	logPath, err = d.taskLogPath(sandboxID)
	if err != nil {
		return nil, err
	}
	logIO, closeLog, err := d.taskLogIO(logPath)
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

	// Attribute the readiness wait for Server-Timing (parity with the docker
	// driver): the ready socket is the fast path ("socket"); the HTTP health
	// poll is the fallback ("health"). Without this the create Server-Timing
	// header carries no readiness source on containerd hosts (UC-11).
	readyStart := time.Now()
	readinessSource := "health"
	if d.cfg.ReadyEnabled && readyListener != nil {
		readinessSource = "socket"
		if err := createReadyWaitFn(ctx, readyListener); err != nil {
			return nil, fmt.Errorf("ready socket: %w", err)
		}
		keepReadySocket = true
	} else if err := d.waitToolboxHTTP(ctx, state.ContainerIP, toolboxToken); err != nil {
		return nil, err
	}
	createtiming.From(ctx).RecordReadinessWaits(0, time.Since(readyStart), readinessSource)

	switch {
	case earlyRules && state.ContainerIP != strings.TrimSpace(prepaidIP):
		// The rules, and any attach the create started, are on the prepaid
		// address: a sandbox at another one would run without them.
		return nil, fmt.Errorf("containerd: sandbox came up at %q, not at its prepaid address %q", state.ContainerIP, prepaidIP)
	case earlyRules:
	default:
		// No address before the workload (no netns pool): the rules go on
		// the one the started task reports.
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
	}

	committed = true
	return state, nil
}

// Start starts a stopped sandbox's container again. A container adopted from
// the warm pool cannot be started this way: its spec still carries the
// pool's env, so its toolboxd would boot parked and serve nothing; the
// service starts every containerd sandbox through StartWithIdentity.
func (d *Driver) Start(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	return d.startTask(ctx, containerRef, "", "")
}

// StartWithIdentity implements runtime.IdentityStarter. A container adopted
// from the warm pool keeps the pool's env for life (SB_POOL_PARKED=1, its
// slot's bootstrap token and park nonce, the bind of its slot's park socket)
// because adoption relabels the container and leaves its spec alone. Every
// start re-creates the task from that spec, so its toolboxd boots parked,
// holds the user's command back and answers only /health until it is
// adopted again. This listens on the slot's socket before the task starts,
// takes the parked hello and adopts it with the sandbox's own ID and token,
// exactly as the create did. Any other container starts as Start does.
func (d *Driver) StartWithIdentity(ctx context.Context, containerRef, sandboxID, toolboxToken string) (*models.SandboxRuntimeState, error) {
	return d.startTask(ctx, containerRef, sandboxID, toolboxToken)
}

// readoptParkedFn waits for a restarted pool container's parked hello and
// adopts it. Tests stub it to drive the handshake without a guest toolbox.
var readoptParkedFn = func(ctx context.Context, pl *dockerpkg.ParkedListener, sandboxID, toolboxToken string) error {
	if err := pl.WaitParked(ctx); err != nil {
		return err
	}
	nonce, err := dockerpkg.MintReadyNonce()
	if err != nil {
		return err
	}
	return pl.Adopt(ctx, sandboxID, toolboxToken, nonce)
}

func (d *Driver) startTask(ctx context.Context, containerRef, sandboxID, toolboxToken string) (*models.SandboxRuntimeState, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	// A duplicate concurrent start waits here, then finds the task running
	// and returns its state.
	unlock := d.lockStart(containerRef)
	defer unlock()
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
	spec, err := container.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("load container spec: %w", err)
	}
	// The task about to be created bind-mounts every host file the spec
	// names; one that went missing would fail it in runc.
	if err := d.ensureSpecHostFiles(spec, sandboxID); err != nil {
		return nil, fmt.Errorf("container host files: %w", err)
	}
	parked, err := d.parkedRestartListener(spec, sandboxID, toolboxToken)
	if err != nil {
		return nil, err
	}
	if parked != nil {
		defer func() { _ = parked.Close() }()
	}
	logPath, err := d.taskLogPath(containerRef)
	if err != nil {
		return nil, err
	}
	// Use the size-capped writer, not cio.LogFile: containerd never rotates task
	// IO, so an uncapped resume log grows for the life of the task and can fill
	// the host disk — the exact hazard Create's taskLogIO guards against.
	// Released on return like Create's: once the task's IO exists, its copy
	// goroutines keep the file and close it when the task goes.
	logIO, closeLog, err := d.taskLogIO(logPath)
	if err != nil {
		return nil, err
	}
	defer closeLog()
	// Resume re-creates the task from the stored spec, which bind-mounts the
	// create-time ready socket. That socket was closed+unlinked after Create, so
	// runc's mount fails ("open .../ready/<id>.<nonce>.sock: no such file"). Recreate
	// the exact socket (nonce from the spec mount path, token from the spec env)
	// so the mount succeeds and the restarted toolbox can re-signal readiness.
	// A pool container's park socket is the parked listener above.
	if d.cfg.ReadyEnabled && parked == nil {
		if rl := d.recreateResumeReadySocket(spec); rl != nil {
			defer func() { _ = rl.Close() }()
		}
	}
	task, err = container.NewTask(ctx, logIO)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	if err := task.Start(ctx); err != nil {
		return nil, fmt.Errorf("start task: %w", err)
	}
	if parked != nil {
		waitCtx, cancel := context.WithTimeout(ctx, d.cfg.ToolboxWaitTimeout)
		err := readoptParkedFn(waitCtx, parked, sandboxID, toolboxToken)
		cancel()
		if err != nil {
			// A container that was not adopted serves nothing: don't leave it
			// running parked behind a start that reports failure.
			_ = task.Kill(ctx, syscall.SIGKILL)
			_, _ = task.Delete(ctx, cntr.WithProcessKill)
			return nil, fmt.Errorf("re-adopt warm-pool container: %w", err)
		}
	}
	return d.runtimeStateAfterStart(ctx, container, task, containerRef, "")
}

// parkedRestartListener returns the listener a start of a warm-pool
// container must adopt its toolboxd over, or nil for any other container.
// The hello must carry the bootstrap token and park nonce in the spec's env,
// and it arrives on the host socket the spec's ready mount names, which must
// be a park socket directly in the ready dir: the listener unlinks whatever
// is at that path before it binds.
func (d *Driver) parkedRestartListener(spec *specs.Spec, sandboxID, toolboxToken string) (*dockerpkg.ParkedListener, error) {
	if spec == nil || spec.Process == nil {
		return nil, nil
	}
	bootstrapToken, parkNonce, parked := dockerpkg.ParkedEnvCredentials(spec.Process.Env)
	if !parked {
		return nil, nil
	}
	if strings.TrimSpace(sandboxID) == "" || strings.TrimSpace(toolboxToken) == "" {
		return nil, errors.New("warm-pool container: a start needs the sandbox's identity to adopt it again")
	}
	var source string
	for _, m := range spec.Mounts {
		if m.Destination == dockerpkg.GuestReadySocketPath {
			source = filepath.Clean(m.Source)
			break
		}
	}
	readyDir := filepath.Clean(strings.TrimSpace(d.cfg.ReadyDir))
	slotID := strings.TrimSuffix(filepath.Base(source), ".sock")
	if source == "" || source == "." || strings.TrimSpace(d.cfg.ReadyDir) == "" || filepath.Dir(source) != readyDir ||
		!IsParkedSandboxID(slotID) || validateSandboxID(slotID) != nil {
		return nil, fmt.Errorf("warm-pool container has no park socket under %s to be adopted over (mount %q)", d.cfg.ReadyDir, source)
	}
	return dockerpkg.NewParkedListener(readyDir, slotID, bootstrapToken, parkNonce)
}

// stopGraceTimeout and stopPollInterval are test seams for Stop's SIGTERM→SIGKILL path.
var (
	stopGraceTimeout = 10 * time.Second
	stopPollInterval = 100 * time.Millisecond
)

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
	deadline := time.Now().Add(stopGraceTimeout)
	for time.Now().Before(deadline) {
		status, statusErr := task.Status(ctx)
		if statusErr == nil && status.Status != cntr.Running {
			_, err = task.Delete(ctx)
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(stopPollInterval):
		}
	}
	_ = task.Kill(ctx, syscall.SIGKILL)
	_, err = task.Delete(ctx, cntr.WithProcessKill)
	return err
}

// Destroy removes the sandbox in the order that keeps it shut and its
// address clean: the workload is killed first; then the destroy's
// runtime.AddressObserver (the egress gateway detach) is told; then the
// address's rules are cleared, while the netns slot is still held (a rule
// cleared after the slot is free could be the next owner's); and the slot
// goes back to the pool last. It used to clear the rules and free the slot
// first and kill the task last, so a destroyed sandbox briefly ran without
// its rules and its address could be handed on while the gateway still held
// state for it. A failed container removal still lets the address go (the
// netns teardown cuts the workload's network) and is returned.
func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	destroyErr := d.destroyContainer(ctx, sandbox)
	sbruntime.NotifyReleasingAddress(ctx, sandbox.ContainerIP)
	_ = d.ClearNetworkRules(sandbox.ContainerIP)
	_ = d.ClearEgressPolicy(sandbox.ContainerIP, sandbox.NetworkAllowOut, sandbox.NetworkDenyOut)
	if d.netns != nil {
		_ = d.netns.Release(ctx, sandbox.ID)
	}
	dockerpkg.RemoveReadySocketsForSandbox(d.cfg.ReadyDir, sandbox.ID)
	// A warm-adopted sandbox's container keeps its park id, and so do its
	// host files, task log and park socket; a cold one's container id is
	// the sandbox id. Both keys are cleared: the sandbox id also covers
	// host files an older build renamed to it on adopt.
	d.removeContainerFiles(sandbox.ID)
	if ref := strings.TrimSpace(sandbox.ContainerID); ref != "" && ref != sandbox.ID {
		d.removeContainerFiles(ref)
	}
	return destroyErr
}

// destroyContainer kills the sandbox's task and deletes its container; a
// container containerd doesn't have is already gone.
func (d *Driver) destroyContainer(ctx context.Context, sandbox *models.Sandbox) error {
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

// Inspect reports what containerd knows about one container. An error
// wrapping sbruntime.ErrInstanceNotFound means containerd answered NotFound
// for the container; reconcile deletes the sandbox's row on that and only
// that. Any other error means containerd could not answer, and says nothing
// about the sandbox.
//
// A container that exists always yields a state. Stopped when it has no task
// or its task has exited — a task that died and is still there (runsc crashed
// under a fork bomb: exit status unavailable) is a stopped sandbox, not a
// missing one. Started when its task runs, with the address sandboxAddress
// finds: the netns probe, else the address recorded at create. A running
// gVisor sandbox always needs the record (its probe can't succeed), and one
// created before the record existed, or whose netns is gone, has neither:
// it is still Started, with ContainerIP empty. An unreadable address used to
// fail Inspect, ListManaged then skipped the container, and reconcile deleted
// the live sandbox's row and cluster placement. Callers that need the
// address check for an empty one: Create and Start keep requiring it
// (runtimeStateAfterStart), the start event and runningAt treat empty as
// "no change", and reconcile keeps the row's address.
func (d *Driver) Inspect(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	// By id, then by sandbox-id label: a warm-adopted sandbox keeps its park
	// container's id, so a sandbox id alone misses it. Gone means neither.
	container, err := d.loadContainerForRef(ctx, client, containerRef)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("load container %q: %w: %w", containerRef, sbruntime.ErrInstanceNotFound, err)
		}
		return nil, fmt.Errorf("load container %q: %w", containerRef, err)
	}
	sandboxID := d.sandboxIDFromContainer(ctx, container)
	stopped := &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: container.ID(),
		Status:      models.SandboxStatusStopped,
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return stopped, nil
		}
		return nil, fmt.Errorf("load task of %q: %w", containerRef, err)
	}
	status, err := task.Status(ctx)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return stopped, nil
		}
		return nil, fmt.Errorf("task status of %q: %w", containerRef, err)
	}
	switch status.Status {
	case cntr.Running, cntr.Paused, cntr.Pausing:
		// Paused is a snapshot commit in progress: the sandbox still owns
		// its address and must not be reported stopped.
	case cntr.Stopped, cntr.Created:
		// Created is a task that never started (an interrupted create or
		// start); Start deletes and recreates it, as it does a stopped one.
		return stopped, nil
	default:
		return nil, fmt.Errorf("task of %q is in state %q", containerRef, status.Status)
	}
	state := &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: container.ID(),
		Status:      models.SandboxStatusStarted,
	}
	ip, err := d.sandboxAddress(ctx, container, task, "")
	if err != nil {
		inspectIPUnavailableTotal.Add(1)
		if d.logger != nil {
			d.logger.Warn("containerd inspect: running task's address unreadable; reporting it started without one",
				"sandbox_id", sandboxID, "container_id", container.ID(), "error", err)
		}
		return state, nil
	}
	state.ContainerIP = ip
	return state, nil
}

// sandboxAddress resolves a running task's IPv4. The netns probe answers for
// runc. It cannot answer for a running gVisor sandbox: runsc takes eth0's
// address out of the pinned netns when the sentry starts, and the task's pid
// sits in the host netns, which the probe refuses to report. So when the
// probe fails, the address the netns slot was given stands in: hint (the
// create path's prepaid address), then the container's containerIPLabelKey
// label. The slot keeps that address for the sandbox's life. The label is
// read only after a failed probe, so a runc sandbox pays nothing extra.
func (d *Driver) sandboxAddress(ctx context.Context, container cntr.Container, task cntr.Task, hint string) (string, error) {
	ip, err := containerIPv4FromTaskFn(ctx, task)
	if err == nil {
		return ip, nil
	}
	if h := strings.TrimSpace(hint); h != "" {
		return h, nil
	}
	if container != nil {
		if labels, lerr := container.Labels(ctx); lerr == nil {
			if recorded := strings.TrimSpace(labels[containerIPLabelKey]); recorded != "" {
				return recorded, nil
			}
		}
	}
	return "", err
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
		if state.Status == models.SandboxStatusStarted {
			// The boot reconcile lists every sandbox, so after a restart
			// this is where a running task gets a reader again.
			d.ensureTaskDrain(ctx, container)
		}
		out[state.SandboxID] = state
	}
	return out, nil
}

func (d *Driver) Resize(ctx context.Context, containerRef string, req models.ResizeSandboxRequest) error {
	if d.cfg.ResourceLimitsOff {
		return nil
	}
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
		// Stopped sandbox: the store holds the new size and it takes effect via
		// the spec on next start; there is no live cgroup to update.
		if errdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("resize task: %w", err)
	}
	res := &specs.LinuxResources{}
	if req.MemoryMB > 0 {
		limit := int64(req.MemoryMB) * 1024 * 1024
		res.Memory = &specs.LinuxMemory{Limit: &limit}
	}
	if req.CPU > 0 {
		// Fractional CPU is a CFS quota/period (mirrors resourceSpecOpts + dockerd
		// --cpus), not a cpuset.
		const cpuPeriod uint64 = 100000
		quota := int64(req.CPU * float64(cpuPeriod))
		if quota < 1000 {
			quota = 1000
		}
		period := cpuPeriod
		res.CPU = &specs.LinuxCPU{Quota: &quota, Period: &period}
	}
	if res.Memory == nil && res.CPU == nil {
		return nil
	}
	// DiskGB is soft-ignored (containerd overlayfs has no live quota; same as
	// create — plans/containerd-engine-phase0-decisions.md DiskGB row).
	return task.Update(ctx, cntr.WithResources(res))
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

// ImageExists reports whether imageRef resolves to a local image in the
// containerd store WITHOUT pulling. Used by the build handlers' cache
// short-circuit (a freshly built tag) and mirrors ensureImage's local-ref
// resolution (exact ref first, then :latest for a tagless local ref) so a
// tag committed as "name:latest" is recognised when referenced as "name".
func (d *Driver) ImageExists(ctx context.Context, imageRef string) (bool, error) {
	client, err := d.ensureClient()
	if err != nil {
		return false, err
	}
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return false, nil
	}
	if _, err := client.GetImage(ctx, imageRef); err == nil {
		return true, nil
	}
	if !refHasTag(imageRef) {
		if _, err := client.GetImage(ctx, imageRef+":latest"); err == nil {
			return true, nil
		}
	}
	return false, nil
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
		// A snapshot taken of a Docker warm-pool container carries its parked
		// flag in the image config; without this a sandbox created from it
		// boots parked and never serves.
		"SB_POOL_PARKED=",
	}
	for key, value := range req.Env {
		if key == gvisorpids.EnvVar {
			// The driver sets the gVisor task cap; a create's env must not
			// shadow it (toolboxd reads the first value of a key).
			continue
		}
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
		if m.Tmpfs {
			mountsOut = append(mountsOut, specs.Mount{Type: "tmpfs", Source: "tmpfs", Destination: m.ContainerPath, Options: m.TmpfsOptions()})
			continue
		}
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
	// Local images (committed snapshots, custom-named builds) are stored under
	// the EXACT ref given — look that up FIRST. Normalizing a bare local name
	// like "myapp-snap:latest" to docker.io/library/myapp-snap:latest would miss
	// the local image and try to pull it from Docker Hub (the UC-21
	// create-from-snapshot failure).
	if image, err := client.GetImage(ctx, ref); err == nil {
		return image, nil
	}
	// A tagless local ref (e.g. a committed snapshot "myapp-snap", stored by the
	// driver as "myapp-snap:latest") needs an exact tag for containerd's
	// GetImage. Try :latest locally before the registry-normalized pull, or a
	// snapshot referenced without a tag is mistaken for a Docker Hub image.
	if !refHasTag(ref) {
		if image, err := client.GetImage(ctx, ref+":latest"); err == nil {
			return image, nil
		}
	}
	// Normalize for the registry pull path, exactly as `ctr` does: containerd's
	// resolver cannot parse a bare "alpine:3.20" — it reads it as host "alpine"
	// with an invalid port ":3.20" ("dummy://alpine:3.20"). ParseDockerRef →
	// docker.io/library/alpine:3.20.
	if named, nerr := refdocker.ParseDockerRef(ref); nerr == nil {
		ref = named.String()
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
		// Resolved inside the flight, after the local re-check, so a warm
		// image never reads the PAT file and N concurrent cold creates of
		// one cross-node snapshot read it once.
		pullAuth, patErr := d.pullAuthFor(ref, auth)
		if a := pullAuth; a != nil && a.Username != "" {
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
		image, pullErr := client.PullImage(ctx, ref, opts...)
		if pullErr != nil && patErr != nil {
			// The anonymous fallback against a `cluster/` ref fails with an
			// opaque "failed to fetch anonymous token: 401"; name the real
			// cause (the unreadable PAT file) in the error the create returns.
			return nil, fmt.Errorf("%w (AOCR cluster pull auth unavailable, pulled anonymously: %w)", pullErr, patErr)
		}
		return image, pullErr
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

// refHasTag reports whether the ref's final path component carries a :tag or
// @digest (a host:port prefix does not count as a tag).
func refHasTag(ref string) bool {
	last := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		last = ref[i+1:]
	}
	return strings.ContainsAny(last, ":@")
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

// recreateResumeReadySocket recreates the create-time ready socket that a
// stored spec bind-mounts, so a resumed task's runc mount does not fail on the
// unlinked socket. The socket path encodes <sandboxID>.<nonce>; the token comes
// from the spec env. Returns nil (caller proceeds without it) when the spec has
// no ready mount or the token/nonce can't be recovered.
func (d *Driver) recreateResumeReadySocket(spec *specs.Spec) *dockerpkg.ReadyListener {
	if spec == nil || spec.Process == nil {
		return nil
	}
	var source string
	for _, m := range spec.Mounts {
		if m.Destination == dockerpkg.GuestReadySocketPath {
			source = m.Source
			break
		}
	}
	if source == "" {
		return nil
	}
	// source is <ReadyDir>/<sandboxID>.<nonce>.sock
	name := strings.TrimSuffix(filepath.Base(source), ".sock")
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return nil
	}
	sandboxID, nonce := name[:dot], name[dot+1:]
	var token string
	for _, e := range spec.Process.Env {
		if v, ok := strings.CutPrefix(e, "SB_TOOLBOX_TOKEN="); ok {
			token = v
			break
		}
	}
	if token == "" || nonce == "" {
		return nil
	}
	rl, err := dockerpkg.NewReadyListener(d.cfg.ReadyDir, sandboxID, token, nonce)
	if err != nil {
		return nil
	}
	return rl
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
	ip, err := d.sandboxAddress(ctx, container, task, ipHint)
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

// defaultCreateReadyWait waits for toolbox readiness on the create-time socket.
func defaultCreateReadyWait(ctx context.Context, rl *dockerpkg.ReadyListener) error {
	if rl == nil {
		return nil
	}
	return rl.Wait(ctx)
}

// createReadyWaitFn waits for toolbox readiness on the create-time socket.
// Tests stub it to avoid a live handshake (mirrors parkReadyWaitFn).
var createReadyWaitFn = defaultCreateReadyWait

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
	return os.RemoveAll(hostFilesDir(d.cfg.RunDir, sandboxID))
}

// removeContainerFiles removes the files a container's spec and task keep on
// the host under its id: host files, task log, and (for a pool container)
// its park socket. A key that isn't a valid id builds no path, so a
// malformed store row can't point the RemoveAll anywhere else.
func (d *Driver) removeContainerFiles(key string) {
	key = strings.TrimSpace(key)
	if validateSandboxID(key) != nil {
		return
	}
	_ = d.removeHostFiles(key)
	_ = d.removeTaskLog(key)
	if IsParkedSandboxID(key) && strings.TrimSpace(d.cfg.ReadyDir) != "" {
		dockerpkg.RemoveParkSocket(filepath.Join(d.cfg.ReadyDir, key+".sock"))
	}
}

func resourceSpecOpts(req models.CreateSandboxRequest, pidsLimit int64) []oci.SpecOpts {
	var out []oci.SpecOpts
	if pidsLimit > 0 {
		// A fork bomb stops here instead of exhausting the node.
		out = append(out, oci.WithPidsLimit(pidsLimit))
	}
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

// WritableLayerBytes implements runtime.WritableLayerSizer: the size of the
// container's active snapshot (its writable layer) as the snapshotter
// reports it.
func (d *Driver) WritableLayerBytes(ctx context.Context, containerRef string) (int64, error) {
	if d.client == nil || d.client.Raw() == nil {
		return 0, errors.New("containerd: client not connected")
	}
	container, err := d.client.LoadContainer(ctx, containerRef)
	if err != nil {
		return 0, err
	}
	ctx = d.client.withNS(ctx)
	info, err := container.Info(ctx)
	if err != nil {
		return 0, err
	}
	if info.SnapshotKey == "" {
		return 0, nil
	}
	usage, err := d.client.Raw().SnapshotService(info.Snapshotter).Usage(ctx, info.SnapshotKey)
	if err != nil {
		return 0, err
	}
	return usage.Size, nil
}
