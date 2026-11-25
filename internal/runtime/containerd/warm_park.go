package containerd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	refdocker "github.com/distribution/reference"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/models"
)

const adoptReadyTimeout = 2 * time.Second

// defaultParkReadyWait waits for the parked hello on the ready socket.
func defaultParkReadyWait(ctx context.Context, pl *dockerpkg.ParkedListener) error {
	return pl.WaitParked(ctx)
}

// parkReadyWaitFn waits for the parked hello on the ready socket. Tests stub
// it so the park path can complete offline without a guest toolbox.
var parkReadyWaitFn = defaultParkReadyWait

// PoolSpawner implements containerdpool.Spawner against the containerd driver.
type PoolSpawner struct {
	Driver *Driver
}

func (p *PoolSpawner) Park(ctx context.Context, slotID string, key containerdpool.Key) (*containerdpool.ParkedSlot, error) {
	if p == nil || p.Driver == nil {
		return nil, errors.New("containerd pool spawner not configured")
	}
	return p.Driver.parkContainer(ctx, slotID, key)
}

func (p *PoolSpawner) DestroyParked(ctx context.Context, slot *containerdpool.ParkedSlot) error {
	if p == nil || p.Driver == nil {
		return nil
	}
	return p.Driver.destroyParked(ctx, slot)
}

// PurgeParkedContainers destroys park-labeled containers left from a prior run.
func (d *Driver) PurgeParkedContainers(ctx context.Context) (int, error) {
	client, err := d.ensureClient()
	if err != nil {
		return 0, err
	}
	containers, err := client.ListContainers(ctx)
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, c := range containers {
		labels, lerr := c.Labels(ctx)
		if lerr != nil || !IsParkedContainerLabels(labels) {
			continue
		}
		id := c.ID()
		if err := d.destroyParked(ctx, &containerdpool.ParkedSlot{ContainerID: id}); err == nil {
			purged++
		}
	}
	return purged, nil
}

func (d *Driver) parkContainer(ctx context.Context, slotID string, key containerdpool.Key) (*containerdpool.ParkedSlot, error) {
	if !d.cfg.ReadyEnabled {
		return nil, errors.New("containerd warm pool requires ready socket")
	}
	if err := validateSandboxID(slotID); err != nil {
		return nil, err
	}
	if err := d.ensureToolboxBinary(); err != nil {
		return nil, err
	}
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}

	bootstrapToken, err := mintBootstrapToken()
	if err != nil {
		return nil, err
	}
	parkNonce, err := dockerpkg.MintReadyNonce()
	if err != nil {
		return nil, err
	}
	pl, err := dockerpkg.NewParkedListener(d.cfg.ReadyDir, slotID, bootstrapToken, parkNonce)
	if err != nil {
		return nil, err
	}

	effectiveRuntime := strings.TrimSpace(key.Runtime)
	if effectiveRuntime == "" {
		effectiveRuntime = d.cfg.DefaultRuntime
	}
	ociRuntime, err := models.ResolveOCIRuntime(effectiveRuntime)
	if err != nil {
		_ = pl.Close()
		return nil, err
	}

	image, err := d.ensureImage(ctx, client, key.Image, nil)
	if err != nil {
		_ = pl.Close()
		return nil, fmt.Errorf("park image: %w", err)
	}
	// In privilege mode split the command comes from the image config the
	// split create reads once (prepareSplitCreate).
	var userCommand []string
	if d.helper == nil {
		if userCommand, err = imageDefaultCommand(ctx, client, image); err != nil {
			_ = pl.Close()
			return nil, fmt.Errorf("park image command: %w", err)
		}
	}

	var (
		netnsPath        string
		prepaidIP        string
		netnsProvisioned bool
	)
	if d.cfg.NativeNetnsPool && d.netns != nil {
		netnsPath, prepaidIP, err = d.netns.Provision(ctx, slotID)
		if err != nil {
			_ = pl.Close()
			return nil, fmt.Errorf("park netns: %w", err)
		}
		netnsProvisioned = true
	}

	var (
		container cntr.Container
		task      cntr.Task
		logCloser func()
		leaseID   string
		// split is what the park's one helper call made in privilege mode
		// split (split_park.go); nil in single mode. snapshotLeft: the
		// snapshot it prepared has no container to hold it yet.
		split        *splitCreate
		snapshotLeft bool
	)
	committed := false
	defer func() {
		if committed {
			return
		}
		if logCloser != nil {
			logCloser()
		}
		if task != nil || container != nil {
			d.lifoTeardown(ctx, client, container, task, "", nil)
		}
		if split != nil {
			uctx, cancel := undoContext(ctx)
			defer cancel()
			if snapshotLeft {
				_ = removeSnapshot(uctx, client, slotID)
			}
			split.release(uctx)
			d.releaseHelperFiles(uctx, slotID)
		}
		_ = pl.Close()
		if netnsProvisioned && d.netns != nil {
			// The park block may be on the address already.
			_, _ = d.giveBack(ctx, giveBackReq{owner: slotID, known: prepaidIP, clear: d.wholeAddress})
		}
		// The park pins an image lease before NewContainer; release it on any
		// non-committed exit or the pinned layers never GC (same orphan class the
		// cold path's lease defer fixes).
		if leaseID != "" {
			d.releaseImageLease(ctx, client, map[string]string{imageLeaseLabelKey: leaseID})
		}
	}()

	// Parked containers resolve DNS exactly like cold creates: a generated
	// resolv.conf with the host's upstream resolvers, keyed by slot. Without
	// it an adopted sandbox keeps the image's resolver (often 127.0.0.1) and
	// gateway-mode DNS never reaches the filter's redirect (plans/
	// egress-domain-filtering.md D14). Built at park time, off the create path.
	// In privilege mode split the helper makes them, with the slot's other
	// files, its snapshot's image user and its park socket's name, in a
	// create's one call (split_park.go).
	var hostFiles *sandboxHostFiles
	if d.helper != nil {
		split, err = d.prepareSplitCreate(ctx, client, image, slotID, bootstrapToken, createParts{OCIRuntime: ociRuntime, Park: true})
		if err != nil {
			return nil, fmt.Errorf("park: %w", err)
		}
		snapshotLeft = true
		userCommand = imageCommandOf(split.config)
		hostFiles = helperHostFiles(split.files)
	} else {
		hostFiles, err = prepareSandboxHostFiles(d.cfg.RunDir, slotID)
		if err != nil {
			return nil, fmt.Errorf("park resolv.conf: %w", err)
		}
		defer func() {
			if !committed {
				_ = os.RemoveAll(hostFiles.Dir)
			}
		}()
	}

	envValues := []string{
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", d.cfg.ToolboxPort),
		"SB_TOOLBOX_TOKEN=" + bootstrapToken,
	}
	envValues = append(envValues, pl.EnvVars()...)
	parkReq := parkDefaultCreateRequest()
	// A parked toolboxd caps a gVisor sentry at park time, sized for the
	// park's default memory: the adopt handshake does not restart it.
	hostPids, pidsEnv := gvisorpids.ForRuntime(ociRuntime, d.cfg.PidsLimit, parkReq.MemoryMB)
	if !d.cfg.ResourceLimitsOff {
		envValues = append(envValues, pidsEnv...)
	}
	sort.Strings(envValues)

	toolbox, park, parkOptions := d.cfg.ToolboxBinaryPath, pl.HostSocketPath(), []string{"rbind"}
	imageConfig := oci.WithImageConfig(image)
	if split != nil {
		// The helper's toolbox and its name for the park socket, read only
		// as the gate requires of every file in its folders (readyMount);
		// a socket still takes connections through a read-only bind.
		toolbox, park, parkOptions = split.files.GetToolboxPath(), split.parkSocket, []string{"rbind", "ro"}
		imageConfig = withImageConfigAnswer(split.config, split.user)
	}
	parkMounts := []specs.Mount{
		{Type: "bind", Source: toolbox, Destination: d.cfg.ToolboxMountPath, Options: []string{"rbind", "ro"}},
		{Type: "bind", Source: park, Destination: dockerpkg.GuestReadySocketPath, Options: parkOptions},
		{Type: "bind", Source: hostFiles.ResolvConf, Destination: "/etc/resolv.conf", Options: []string{"rbind", "ro"}},
	}
	if ociRuntime == "runsc" {
		parkMounts = append(parkMounts, runscCgroupMount())
	}
	specOpts := []oci.SpecOpts{
		imageConfig,
		oci.WithProcessArgs(append([]string{d.cfg.ToolboxMountPath}, userCommand...)...),
		oci.WithHostname(slotID),
		oci.WithEnv(envValues),
		oci.WithMounts(parkMounts),
	}
	if !d.cfg.Privileged {
		specOpts = append(specOpts, securitySpecOpts()...)
	}
	if !d.cfg.ResourceLimitsOff {
		specOpts = append(specOpts, resourceSpecOpts(parkReq, hostPids)...)
	}
	if netnsPath != "" {
		specOpts = append(specOpts, withNetworkNamespace(netnsPath))
	}
	specOpts = append(specOpts, withSandboxIPv6Off())
	specOpts = append(specOpts, d.cgroupSpecOpts(slotID)...)
	if ociRuntime == "runsc" {
		specOpts = append(specOpts, runscSandboxAnnotationOpt())
	}

	labels := map[string]string{
		managedLabelKey:  "true",
		poolParkLabelKey: poolParkLabelValue,
	}
	if ip := strings.TrimSpace(prepaidIP); ip != "" {
		labels[containerIPLabelKey] = ip
	}
	leaseID, err = d.pinImageLease(ctx, client, image)
	if err != nil {
		return nil, err
	}
	if leaseID != "" {
		labels[imageLeaseLabelKey] = leaseID
	}
	snapshotOpt, createCtx := cntr.WithNewSnapshot(slotID, image), ctx
	if split != nil {
		// The snapshot is there, under the split create's own lease.
		snapshotOpt, createCtx = withPreparedSnapshot(slotID), split.leaseCtx
	}
	containerOpts := []cntr.NewContainerOpts{
		cntr.WithImage(image),
		snapshotOpt,
		withNewSpec(specOpts...),
		cntr.WithContainerLabels(labels),
	}
	if ociRuntime != "" && split != nil {
		if opt := runtimeContainerOptAt(ociRuntime, split.files.GetRunscConfigPath()); opt != nil {
			containerOpts = append(containerOpts, opt)
		}
	} else if ociRuntime != "" {
		opt, err := d.runtimeContainerOpt(ociRuntime)
		if err != nil {
			return nil, err
		}
		if opt != nil {
			containerOpts = append(containerOpts, opt)
		}
	}

	container, err = client.NewContainer(createCtx, slotID, containerOpts...)
	if err != nil {
		return nil, fmt.Errorf("park create: %w", err)
	}
	// The container holds the snapshot now.
	snapshotLeft = false
	split.release(ctx)

	logPath, err := d.taskLogPath(slotID)
	if err != nil {
		return nil, err
	}
	var (
		logCreator cio.Creator
		closeLog   func()
	)
	if split != nil {
		logCreator, closeLog, err = d.taskLogIOAt(logPath, split.files)
	} else {
		logCreator, closeLog, err = d.taskLogIO(logPath)
	}
	if err != nil {
		return nil, err
	}
	logCloser = closeLog

	task, err = container.NewTask(ctx, logCreator)
	if err != nil {
		return nil, fmt.Errorf("park task: %w", err)
	}
	if err := task.Start(ctx); err != nil {
		return nil, fmt.Errorf("park start: %w", err)
	}
	if d.cfg.CgroupParent != "" {
		if err := d.MarkOOMVictim(ctx, d.sandboxCgroupPath(slotID)); err != nil {
			return nil, fmt.Errorf("park: %w", err)
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, d.cfg.ToolboxWaitTimeout)
	defer cancel()
	if err := parkReadyWaitFn(waitCtx, pl); err != nil {
		return nil, fmt.Errorf("park ready: %w", err)
	}
	// Again, for processes gVisor started after task.Start returned.
	if d.cfg.CgroupParent != "" {
		if err := d.MarkOOMVictim(ctx, d.sandboxCgroupPath(slotID)); err != nil {
			return nil, fmt.Errorf("park: %w", err)
		}
	}

	containerIP := strings.TrimSpace(prepaidIP)
	if containerIP == "" {
		containerIP, err = d.taskAddress(ctx, task)
		if err != nil {
			return nil, err
		}
	}
	if d.networkRules != nil {
		if err := d.networkRules.BlockAllEgress(containerIP); err != nil {
			return nil, fmt.Errorf("park egress block: %w", err)
		}
	}

	imageID, err := imageDigestString(image)
	if err != nil {
		return nil, err
	}

	committed = true
	return &containerdpool.ParkedSlot{
		ID:             slotID,
		ContainerID:    slotID,
		ContainerIP:    containerIP,
		ImageID:        imageID,
		Key:            key,
		BootstrapToken: bootstrapToken,
		Handle:         pl,
	}, nil
}

func parkDefaultCreateRequest() models.CreateSandboxRequest {
	return models.CreateSandboxRequest{
		CPU:      models.DefaultCPU,
		MemoryMB: models.DefaultMemoryMB,
	}
}

// PoolImageID is the digest a ref names in containerd's image store now,
// for the warm pool's image-change check (plans/agent-sandbox-feature-
// parity.md W3). It tries the same local names ensureImage tries before it
// pulls (the exact ref, ":latest" for a tagless one, the registry-normalized
// form) and never pulls: a missing image is an error, so the pool keeps
// what it had. The answer is in the form parkContainer records.
func (d *Driver) PoolImageID(ctx context.Context, ref string) (string, error) {
	client, err := d.ensureClient()
	if err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	candidates := []string{ref}
	if !refHasTag(ref) {
		candidates = append(candidates, ref+":latest")
	}
	if named, nerr := refdocker.ParseDockerRef(ref); nerr == nil {
		candidates = append(candidates, named.String())
	}
	var lastErr error
	for _, c := range candidates {
		image, err := client.GetImage(ctx, c)
		if err == nil {
			return imageDigestString(image)
		}
		lastErr = err
	}
	return "", fmt.Errorf("pool image %s: %w", ref, lastErr)
}

func imageDigestString(image cntr.Image) (string, error) {
	if image == nil {
		return "", errors.New("image is nil")
	}
	if digest := strings.TrimSpace(image.Target().Digest.String()); digest != "" {
		return digest, nil
	}
	if name := strings.TrimSpace(image.Name()); name != "" {
		return name, nil
	}
	return "", errors.New("image has no digest or name")
}

func mintBootstrapToken() (string, error) {
	b := make([]byte, 32)
	// Reuse randReadFn so tests can simulate entropy failure without stubbing crypto/rand.
	if _, err := randReadFn(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
