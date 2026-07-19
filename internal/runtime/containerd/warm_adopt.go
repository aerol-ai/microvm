package containerd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

const (
	poolParkLabelKey   = "aerol.pool"
	poolParkLabelValue = "park"
)

// poolEligible mirrors docker's warm-pool gate: only default-shaped creates can
// adopt a parked slot without post-create mutation.
func poolEligible(req models.CreateSandboxRequest, hostMounts []mounts.ContainerBind) bool {
	if len(req.Env) > 0 {
		return false
	}
	if len(req.Mounts) > 0 || len(req.PlatformVolumes) > 0 || len(hostMounts) > 0 {
		return false
	}
	if user := strings.TrimSpace(req.OSUser); user != "" && !strings.EqualFold(user, "root") {
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
	return req.Image != ""
}

func (d *Driver) tryWarmAdopt(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind, effectiveRuntime string) (*models.SandboxRuntimeState, error) {
	if d.warmPool == nil || !d.cfg.ReadyEnabled {
		return nil, containerdpool.ErrNoSlot
	}
	if !poolEligible(req, hostMounts) {
		return nil, containerdpool.ErrNoSlot
	}
	key := containerdpool.KeyFromRequest(req, effectiveRuntime)
	if !d.warmPool.HasReady(key) {
		d.warmPool.NoteMiss(key)
		if timing := createtiming.From(ctx); timing != nil {
			timing.RecordStageDesc("containerd_pool", 0, "miss")
		}
		return nil, containerdpool.ErrNoSlot
	}
	slot, err := d.warmPool.Acquire(ctx, key, "")
	if err != nil {
		if timing := createtiming.From(ctx); timing != nil && errors.Is(err, containerdpool.ErrNoSlot) {
			timing.RecordStageDesc("containerd_pool", 0, "miss")
		}
		return nil, err
	}
	start := time.Now()
	state, err := d.adoptParked(ctx, req, sandboxID, toolboxToken, slot)
	if timing := createtiming.From(ctx); timing != nil {
		if err == nil {
			timing.RecordStageDesc("containerd_pool", time.Since(start), "hit")
			// Parity with the docker driver (pkg/docker/docker_pool.go): a warm
			// adopt proves readiness through the same unix-socket ready-ack
			// handshake — ParkedListener.Adopt sends the adopt frame and waits for
			// the toolbox to ack under the new sandbox identity — so the create's
			// Server-Timing must attribute readiness to "socket", not leave it
			// blank. Without this, the pool-hit path carried no readiness source
			// and UC-96/96c/96d read source="" (the docker driver already guards
			// this; containerd was missing it). Waits stay 0: the adopt elapsed
			// time is already in the containerd_pool stage above, so recording it
			// again as a readiness wait would double-count.
			timing.RecordReadinessWaits(0, 0, "socket")
		} else {
			timing.RecordStageDesc("containerd_pool", time.Since(start), "adopt_failed")
		}
	}
	if err != nil {
		if errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
			if p, ok := d.warmPool.(interface {
				ReturnSlot(*containerdpool.ParkedSlot)
			}); ok {
				p.ReturnSlot(slot)
			}
			return nil, err
		}
		_ = d.destroyParked(ctx, slot)
		if d.netns != nil {
			// adoptParked may have already reassigned the netns slot from the park
			// id to sandboxID before failing (ReassignOwner runs before the network
			// policy apply). destroyParked only releases the park id, so release
			// under sandboxID too or the slot is stranded adopted with no container.
			_ = d.netns.Release(ctx, sandboxID)
		}
		d.warmPool.ReleasePark(slot.ID)
		return nil, fmt.Errorf("warm adopt failed: %w", err)
	}
	return state, nil
}

// adoptParked binds a parked container to sandboxID without renaming the
// containerd object — store mapping + aerolvm.sandbox_id label (Phase 3).
func (d *Driver) adoptParked(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, slot *containerdpool.ParkedSlot) (*models.SandboxRuntimeState, error) {
	if slot == nil || slot.Handle == nil {
		return nil, errors.New("parked slot is incomplete")
	}
	pl, ok := slot.Handle.(interface {
		Adopt(context.Context, string, string, string) error
	})
	if !ok {
		return nil, errors.New("parked slot handle type mismatch")
	}
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}

	container, err := client.LoadContainer(ctx, slot.ContainerID)
	if err != nil {
		return nil, err
	}
	labels, err := container.Labels(ctx)
	if err != nil {
		return nil, err
	}
	if sid := strings.TrimSpace(labels[sandboxIDLabelKey]); sid == sandboxID {
		return d.adoptedRuntimeState(slot, sandboxID), nil
	}
	if err := d.assertSandboxNotExists(ctx, client, sandboxID, slot.ContainerID); err != nil {
		return nil, err
	}

	adoptNonce, err := dockerpkg.MintReadyNonce()
	if err != nil {
		return nil, err
	}
	adoptCtx, cancel := context.WithTimeout(ctx, adoptReadyTimeout)
	defer cancel()
	if err := pl.Adopt(adoptCtx, sandboxID, toolboxToken, adoptNonce); err != nil {
		return nil, err
	}

	delete(labels, poolParkLabelKey)
	labels[sandboxIDLabelKey] = sandboxID
	if _, err := container.SetLabels(ctx, labels); err != nil {
		return nil, err
	}

	if d.netns != nil && slot.ID != "" && slot.ID != sandboxID {
		_ = d.netns.ReassignOwner(ctx, slot.ID, sandboxID)
	}

	if err := d.applyAdoptNetworkPolicy(slot.ContainerIP, req); err != nil {
		return nil, err
	}

	return d.adoptedRuntimeState(slot, sandboxID), nil
}

func (d *Driver) adoptedRuntimeState(slot *containerdpool.ParkedSlot, sandboxID string) *models.SandboxRuntimeState {
	return &models.SandboxRuntimeState{
		SandboxID:     sandboxID,
		ContainerID:   slot.ContainerID,
		ContainerIP:   slot.ContainerIP,
		Status:        models.SandboxStatusStarted,
		AdoptedParkID: slot.ID,
	}
}

func (d *Driver) assertSandboxNotExists(ctx context.Context, client *Client, sandboxID, adoptContainerID string) error {
	if c, err := client.LoadContainer(ctx, sandboxID); err == nil {
		labels, _ := c.Labels(ctx)
		if !IsParkedContainerLabels(labels) {
			return dockerpkg.ErrSandboxContainerExists
		}
	} else if !errdefs.IsNotFound(err) {
		return err
	}
	existing, err := d.findContainerBySandboxID(ctx, client, sandboxID)
	if err != nil {
		return err
	}
	if existing != nil && existing.ID() != adoptContainerID {
		return dockerpkg.ErrSandboxContainerExists
	}
	return nil
}

func (d *Driver) findContainerBySandboxID(ctx context.Context, client *Client, sandboxID string) (cntr.Container, error) {
	containers, err := client.ListContainers(ctx, "labels."+sandboxIDLabelKey+"=="+sandboxID)
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, nil
	}
	return containers[0], nil
}

func (d *Driver) destroyParked(ctx context.Context, slot *containerdpool.ParkedSlot) error {
	if slot == nil {
		return nil
	}
	if slot.ContainerIP != "" {
		_ = d.ClearNetworkRules(slot.ContainerIP)
	}
	if slot.Handle != nil {
		_ = slot.Handle.Close()
	}
	if pl, ok := slot.Handle.(*dockerpkg.ParkedListener); ok {
		dockerpkg.RemoveParkSocket(pl.HostSocketPath())
	}
	// Release the prepaid netns slot the park held (keyed by the park slot id,
	// which equals ContainerID for a parked container). Without this, every park
	// teardown — LRU/stale-image evict, idle-TTL reap, shutdown drain, boot
	// PurgeParkedContainers — permanently leaks a netns slot (row stays adopted
	// under the dead park id, plus its veth/IPAM lease/conntrack) until the pool
	// exhausts and cold creates fail with "provision netns: no free slot".
	// Release is idempotent and a no-op if the slot was already reassigned to an
	// adopting sandbox.
	if d.netns != nil {
		parkKey := strings.TrimSpace(slot.ID)
		if parkKey == "" {
			parkKey = strings.TrimSpace(slot.ContainerID)
		}
		if parkKey != "" {
			_ = d.netns.Release(ctx, parkKey)
		}
	}
	if slot.ContainerID != "" {
		client, err := d.ensureClient()
		if err != nil {
			return err
		}
		container, err := client.LoadContainer(ctx, slot.ContainerID)
		if err != nil {
			return err
		}
		// Release the image lease the park pinned, or GC can never reclaim the
		// pinned layers (mirror Destroy's release).
		if labels, lerr := container.Labels(ctx); lerr == nil {
			d.releaseImageLease(ctx, client, labels)
		}
		if task, taskErr := container.Task(ctx, nil); taskErr == nil {
			_ = task.Kill(ctx, syscall.SIGKILL)
			_, _ = task.Delete(ctx)
		}
		return container.Delete(ctx)
	}
	return nil
}

func (d *Driver) applyAdoptNetworkPolicy(containerIP string, req models.CreateSandboxRequest) error {
	if d.networkRules == nil || containerIP == "" {
		return nil
	}
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := d.ApplyEgressPolicy(containerIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			_ = d.ClearEgressPolicy(containerIP, req.NetworkAllowOut, req.NetworkDenyOut)
			return err
		}
	}
	if req.NetworkBlockAll {
		return d.ApplyNetworkBlockAll(containerIP)
	}
	return d.ClearNetworkBlockEgress(containerIP)
}

// IsParkedContainerLabels reports warm-pool park inventory for ListManaged.
func IsParkedContainerLabels(labels map[string]string) bool {
	return labels != nil && labels[poolParkLabelKey] == poolParkLabelValue
}

// IsParkedSandboxID reports park-<hex> slot ids.
func IsParkedSandboxID(id string) bool {
	return strings.HasPrefix(strings.TrimSpace(id), "park-")
}
