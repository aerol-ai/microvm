package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

const poolParkLabelKey = "aerol.pool"
const poolParkLabelValue = "park"

// ErrSandboxContainerExists is returned when adopt-time rename finds the
// sandbox name already taken — signals the §6 duplicate-create protocol.
var ErrSandboxContainerExists = errors.New("docker: sandbox container name already exists")

// SetWarmPool wires the docker warm pool. Nil disables the fast path.
func (c *Client) SetWarmPool(p *dockerpool.Pool) {
	c.warmPool = p
}

// PoolSpawner implements dockerpool.Spawner against this client.
type PoolSpawner struct {
	Client *Client
}

func (p *PoolSpawner) Park(ctx context.Context, slotID string, key dockerpool.Key) (*dockerpool.ParkedSlot, error) {
	if p == nil || p.Client == nil {
		return nil, errors.New("docker pool spawner not configured")
	}
	return p.Client.parkContainer(ctx, slotID, key)
}

func (p *PoolSpawner) DestroyParked(ctx context.Context, slot *dockerpool.ParkedSlot) error {
	if p == nil || p.Client == nil || slot == nil {
		return nil
	}
	return p.Client.destroyParked(ctx, slot)
}

func poolEligible(req models.CreateSandboxRequest, hostMounts []mounts.ContainerBind, parkDiskGB int) bool {
	if len(req.Env) > 0 {
		return false
	}
	if len(req.Mounts) > 0 || len(req.PlatformVolumes) > 0 || len(hostMounts) > 0 {
		return false
	}
	if strings.TrimSpace(req.OSUser) != "" {
		return false
	}
	if len(req.ContainerCommand) > 0 {
		return false
	}
	if req.Registry != nil {
		return false
	}
	if req.GPUs != nil {
		return false
	}
	if parkDiskGB > 0 && req.DiskGB != parkDiskGB {
		return false
	}
	return req.Image != ""
}

func (c *Client) tryWarmAdopt(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind, effectiveRuntime string) (*SandboxRuntime, error) {
	if c.warmPool == nil || !c.readyEnabled {
		return nil, dockerpool.ErrNoSlot
	}
	if !poolEligible(req, hostMounts, c.parkDiskGB) {
		return nil, dockerpool.ErrNoSlot
	}

	// Guaranteed miss: skip the image-inspect engine call so the miss path
	// adds no boot-path work beyond a map lookup. Only a potential hit pays
	// the inspect (needed to re-validate the parked slot's image identity).
	key := dockerpool.KeyFromRequest(req, effectiveRuntime)
	if !c.warmPool.HasReady(key) {
		c.warmPool.NoteMiss(key)
		if timing := CreateTimingFrom(ctx); timing != nil {
			timing.RecordStageDesc("docker_pool", 0, "miss")
		}
		return nil, dockerpool.ErrNoSlot
	}

	imageInspect, err := c.inspectImage(ctx, req.Image)
	if err != nil {
		return nil, dockerpool.ErrNoSlot
	}
	imageID := strings.TrimSpace(imageInspect.ID)
	slot, err := c.warmPool.Acquire(ctx, key, imageID)
	if err != nil {
		if timing := CreateTimingFrom(ctx); timing != nil && errors.Is(err, dockerpool.ErrNoSlot) {
			timing.RecordStageDesc("docker_pool", 0, "miss")
		}
		return nil, err
	}

	start := time.Now()
	runtime, err := c.adoptParked(ctx, req, sandboxID, toolboxToken, slot)
	if timing := CreateTimingFrom(ctx); timing != nil {
		if err == nil {
			timing.RecordStageDesc("docker_pool", time.Since(start), "hit")
		} else {
			timing.RecordStageDesc("docker_pool", 0, "miss")
		}
	}
	if err != nil {
		if errors.Is(err, ErrSandboxContainerExists) {
			// Rename conflicted before the slot was touched: a concurrent
			// duplicate create owns this sandbox ID. The parked container is
			// still pristine — return it to the pool instead of burning it.
			c.warmPool.ReturnSlot(slot)
			return nil, err
		}
		// The slot left the pool at Acquire, so nothing else will free its
		// park:<slot-id> capacity reservation — destroy AND release here, or
		// every failed adopt permanently shrinks the node's admittable
		// capacity.
		_ = c.destroyParked(ctx, slot)
		c.warmPool.ReleasePark(slot.ID)
		return nil, fmt.Errorf("warm adopt failed: %w", err)
	}
	if createtiming.From(ctx) != nil {
		timing := createtiming.From(ctx)
		timing.RecordDockerWaits(0, 0, "socket")
	}
	return runtime, nil
}

func (c *Client) parkContainer(ctx context.Context, slotID string, key dockerpool.Key) (*dockerpool.ParkedSlot, error) {
	if err := c.ensureToolboxBinary(); err != nil {
		return nil, err
	}
	bootstrapToken, err := mintBootstrapToken()
	if err != nil {
		return nil, err
	}
	parkNonce, err := mintReadyNonce()
	if err != nil {
		return nil, err
	}

	pl, err := NewParkedListener(c.readyDir, slotID, bootstrapToken, parkNonce)
	if err != nil {
		return nil, err
	}

	effectiveRuntime := strings.TrimSpace(key.Runtime)
	if effectiveRuntime == "" {
		effectiveRuntime = c.defaultRuntime
	}
	ociRuntime, err := models.ResolveOCIRuntime(effectiveRuntime)
	if err != nil {
		_ = pl.Close()
		return nil, err
	}

	imageInspect, err := c.inspectImage(ctx, key.Image)
	if err != nil {
		_ = pl.Close()
		return nil, fmt.Errorf("inspect image: %w", err)
	}

	workingDir := strings.TrimSpace(imageInspect.Config.WorkingDir)
	if workingDir == "" {
		workingDir = "/"
	}
	userCommand := append(append([]string{}, imageInspect.Config.Entrypoint...), imageInspect.Config.Cmd...)

	envValues := []string{
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", c.toolboxPort),
		"SB_TOOLBOX_TOKEN=" + bootstrapToken,
	}
	envValues = append(envValues, pl.EnvVars()...)

	labels := map[string]string{
		managedLabelKey:  "true",
		poolParkLabelKey: poolParkLabelValue,
	}

	createRequest := map[string]any{
		"Image":      key.Image,
		"WorkingDir": workingDir,
		"Entrypoint": []string{c.toolboxMountPath},
		"Cmd":        userCommand,
		"Env":        envValues,
		"Labels":     labels,
	}

	binds := []string{
		fmt.Sprintf("%s:%s:ro", c.toolboxBinaryPath, c.toolboxMountPath),
		pl.BindSpec(),
	}

	hostConfig := map[string]any{
		"Privileged": c.privileged,
		"Binds":      binds,
	}
	if c.network != "" && c.network != "bridge" {
		hostConfig["NetworkMode"] = c.network
	}
	if ociRuntime != "" {
		hostConfig["Runtime"] = ociRuntime
	}
	if !c.resourceLimitsOff {
		hostConfig["Resources"] = parkDefaultResources(c)
	}
	if c.parkDiskGB > 0 && effectiveRuntime != models.RuntimeGvisor {
		hostConfig["StorageOpt"] = map[string]string{"size": fmt.Sprintf("%dG", c.parkDiskGB)}
	}
	createRequest["HostConfig"] = hostConfig

	var created struct {
		ID string `json:"Id"`
	}
	createQuery := url.Values{}
	createQuery.Set("name", slotID)
	if err := c.doJSON(ctx, http.MethodPost, "/containers/create", createQuery, createRequest, nil, &created); err != nil {
		_ = pl.Close()
		return nil, fmt.Errorf("park create: %w", err)
	}
	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil, nil, nil); err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		_ = pl.Close()
		return nil, fmt.Errorf("park start: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, c.toolboxWaitTimeout)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		_ = pl.Close()
		return nil, fmt.Errorf("park ready: %w", err)
	}

	containerIP, _, err := c.waitForContainerRunning(ctx, created.ID)
	if err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		_ = pl.Close()
		return nil, err
	}
	if err := c.networkRules.BlockAllEgress(containerIP); err != nil {
		_ = c.networkRules.ClearBlockAllEgress(containerIP)
		_ = c.removeContainer(ctx, created.ID, true)
		_ = pl.Close()
		return nil, fmt.Errorf("park egress block: %w", err)
	}

	return &dockerpool.ParkedSlot{
		ID:             slotID,
		ContainerID:    created.ID,
		ContainerIP:    containerIP,
		ImageID:        strings.TrimSpace(imageInspect.ID),
		Key:            key,
		BootstrapToken: bootstrapToken,
		Handle:         pl,
	}, nil
}

func parkDefaultResources(c *Client) map[string]any {
	cpu := models.DefaultCPU
	mem := models.DefaultMemoryMB
	resources := map[string]any{}
	if cpu > 0 {
		resources["CpuPeriod"] = int64(100000)
		resources["CpuQuota"] = int64(cpu * 100000)
	}
	if mem > 0 {
		resources["Memory"] = int64(mem) * 1024 * 1024
		resources["MemorySwap"] = int64(mem) * 1024 * 1024
	}
	return resources
}

func (c *Client) adoptParked(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, slot *dockerpool.ParkedSlot) (*SandboxRuntime, error) {
	if slot == nil || slot.Handle == nil {
		return nil, errors.New("parked slot is incomplete")
	}
	pl, ok := slot.Handle.(*ParkedListener)
	if !ok {
		return nil, errors.New("parked slot handle type mismatch")
	}

	if err := c.renameContainer(ctx, slot.ContainerID, sandboxID); err != nil {
		if isDockerNameConflict(err) {
			return nil, ErrSandboxContainerExists
		}
		return nil, err
	}

	if err := c.updateContainerResources(ctx, slot.ContainerID, req.CPU, req.MemoryMB); err != nil {
		return nil, err
	}

	adoptNonce, err := mintReadyNonce()
	if err != nil {
		return nil, err
	}
	adoptCtx, cancel := context.WithTimeout(ctx, readyConnReadTimeout)
	defer cancel()
	if err := pl.Adopt(adoptCtx, sandboxID, toolboxToken, adoptNonce); err != nil {
		return nil, err
	}

	containerIP := slot.ContainerIP
	if err := c.applyAdoptNetworkPolicy(containerIP, req); err != nil {
		return nil, err
	}

	inspect, err := c.inspectContainer(ctx, slot.ContainerID)
	if err != nil {
		return nil, err
	}
	if ip := getContainerIP(inspect, c.network); ip != "" {
		containerIP = ip
	}

	return &SandboxRuntime{
		SandboxID:     sandboxID,
		ContainerID:   slot.ContainerID,
		ContainerIP:   containerIP,
		Status:        models.SandboxStatusStarted,
		AdoptedParkID: slot.ID,
	}, nil
}

// applyAdoptNetworkPolicy converts the park-time egress DROP into the adopted
// sandbox's requested policy. Order matters: the requested rules go in first
// so there is never a window where the container has unrestricted egress, and
// the park DROP is removed last — but only when the request did NOT ask for
// block-all, because the park DROP and the NetworkBlockAll rule are the SAME
// iptables rule (-s <ip> -j DROP). Clearing it unconditionally would hand a
// block-all sandbox open egress.
func (c *Client) applyAdoptNetworkPolicy(containerIP string, req models.CreateSandboxRequest) error {
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := c.networkRules.ApplyEgressPolicy(containerIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			_ = c.networkRules.ClearEgressPolicy(containerIP, req.NetworkAllowOut, req.NetworkDenyOut)
			return err
		}
	}
	if req.NetworkBlockAll {
		// The park DROP already is the block-all rule; BlockAllEgress is
		// idempotent and re-asserts it in case it was lost.
		return c.networkRules.BlockAllEgress(containerIP)
	}
	return c.networkRules.ClearBlockAllEgress(containerIP)
}

func (c *Client) destroyParked(ctx context.Context, slot *dockerpool.ParkedSlot) error {
	if slot == nil {
		return nil
	}
	if slot.ContainerIP != "" {
		_ = c.ClearNetworkRules(slot.ContainerIP)
	}
	if slot.Handle != nil {
		_ = slot.Handle.Close()
	}
	if pl, ok := slot.Handle.(*ParkedListener); ok {
		RemoveParkSocket(pl.HostSocketPath())
	}
	if slot.ContainerID != "" {
		return c.removeContainer(ctx, slot.ContainerID, true)
	}
	return nil
}

func (c *Client) renameContainer(ctx context.Context, containerID, name string) error {
	query := url.Values{}
	query.Set("name", name)
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/rename", query, nil, nil, nil)
}

func isDockerNameConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already in use") || strings.Contains(msg, "409")
}

func (c *Client) updateContainerResources(ctx context.Context, containerID string, cpu float64, memoryMB int) error {
	if c.resourceLimitsOff {
		return nil
	}
	resources := map[string]any{}
	if cpu > 0 {
		resources["CpuPeriod"] = int64(100000)
		resources["CpuQuota"] = int64(cpu * 100000)
	}
	if memoryMB > 0 {
		resources["Memory"] = int64(memoryMB) * 1024 * 1024
		resources["MemorySwap"] = int64(memoryMB) * 1024 * 1024
	}
	if len(resources) == 0 {
		return nil
	}
	body := map[string]any{"Resources": resources}
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/update", nil, body, nil, nil)
}

func mintBootstrapToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ListParkedContainers returns all park-labeled containers for boot purge.
// all=1 matters: a parked container that crashed or exited still has its
// container object and, worse, its IP-keyed DROP rule — listing only running
// containers would leave both behind forever.
func (c *Client) ListParkedContainers(ctx context.Context) ([]containerSummary, error) {
	query := queryValues(map[string]string{
		"all":     "1",
		"filters": fmt.Sprintf(`{"label":["%s=%s"]}`, poolParkLabelKey, poolParkLabelValue),
	})
	var containers []containerSummary
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json", query, nil, nil, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// PurgeParkedContainers destroys all park-labeled containers and clears rules.
func (c *Client) PurgeParkedContainers(ctx context.Context) (int, error) {
	containers, err := c.ListParkedContainers(ctx)
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, summary := range containers {
		inspect, ierr := c.inspectContainer(ctx, summary.ID)
		if ierr == nil {
			if ip := getContainerIP(inspect, c.network); ip != "" {
				_ = c.ClearNetworkRules(ip)
			}
		}
		if err := c.removeContainer(ctx, summary.ID, true); err == nil {
			purged++
		}
	}
	return purged, nil
}
