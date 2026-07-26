package containerd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
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
	userCommand, err := imageDefaultCommand(ctx, client, image)
	if err != nil {
		_ = pl.Close()
		return nil, fmt.Errorf("park image command: %w", err)
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
		_ = pl.Close()
		if netnsProvisioned && d.netns != nil {
			_ = d.netns.Release(ctx, slotID)
		}
		// The park pins an image lease before NewContainer; release it on any
		// non-committed exit or the pinned layers never GC (same orphan class the
		// cold path's lease defer fixes).
		if leaseID != "" {
			d.releaseImageLease(ctx, client, map[string]string{imageLeaseLabelKey: leaseID})
		}
	}()

	envValues := []string{
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", d.cfg.ToolboxPort),
		"SB_TOOLBOX_TOKEN=" + bootstrapToken,
	}
	envValues = append(envValues, pl.EnvVars()...)
	sort.Strings(envValues)

	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(image),
		oci.WithProcessArgs(append([]string{d.cfg.ToolboxMountPath}, userCommand...)...),
		oci.WithHostname(slotID),
		oci.WithEnv(envValues),
		oci.WithMounts([]specs.Mount{
			{Type: "bind", Source: d.cfg.ToolboxBinaryPath, Destination: d.cfg.ToolboxMountPath, Options: []string{"rbind", "ro"}},
			{Type: "bind", Source: pl.HostSocketPath(), Destination: dockerpkg.GuestReadySocketPath, Options: []string{"rbind"}},
		}),
	}
	if !d.cfg.Privileged {
		specOpts = append(specOpts, securitySpecOpts()...)
	}
	if !d.cfg.ResourceLimitsOff {
		specOpts = append(specOpts, resourceSpecOpts(parkDefaultCreateRequest())...)
	}
	if netnsPath != "" {
		specOpts = append(specOpts, withNetworkNamespace(netnsPath))
	}
	if ociRuntime == "runsc" {
		specOpts = append(specOpts, runscSandboxAnnotationOpt())
	}

	labels := map[string]string{
		managedLabelKey:  "true",
		poolParkLabelKey: poolParkLabelValue,
	}
	leaseID, err = d.pinImageLease(ctx, client, image)
	if err != nil {
		return nil, err
	}
	if leaseID != "" {
		labels[imageLeaseLabelKey] = leaseID
	}
	containerOpts := []cntr.NewContainerOpts{
		cntr.WithImage(image),
		cntr.WithNewSnapshot(slotID, image),
		cntr.WithNewSpec(specOpts...),
		cntr.WithContainerLabels(labels),
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

	container, err = client.NewContainer(ctx, slotID, containerOpts...)
	if err != nil {
		return nil, fmt.Errorf("park create: %w", err)
	}

	logPath, err := d.taskLogPath(slotID)
	if err != nil {
		return nil, err
	}
	logCreator, closeLog, err := taskLogIO(logPath)
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

	waitCtx, cancel := context.WithTimeout(ctx, d.cfg.ToolboxWaitTimeout)
	defer cancel()
	if err := parkReadyWaitFn(waitCtx, pl); err != nil {
		return nil, fmt.Errorf("park ready: %w", err)
	}

	containerIP := strings.TrimSpace(prepaidIP)
	if containerIP == "" {
		containerIP, err = containerIPv4FromTaskFn(ctx, task)
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
