package containerd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

const (
	poolParkLabelKey   = "aerol.pool"
	poolParkLabelValue = "park"
	// adoptEnvLabelKey marks a container adopted from the warm pool with a
	// non-empty env. That env went to the toolbox in the adopt frame and
	// lives only in its memory: the spec a start re-creates the task from
	// never had it. So every start must send it again, and a start that
	// cannot (no loader, or a sealed row that comes back empty) refuses
	// rather than bring the sandbox back without its env. The value is
	// always "1", never anything derived from the env.
	adoptEnvLabelKey   = "aerolvm.adopt_env"
	adoptEnvLabelValue = "1"
)

// poolEligible is docker's warm-pool gate (pkg/docker/docker_pool.go) minus
// env: a parked slot can be adopted only by a create it serves unchanged.
// Env can ride the adopt frame on this engine (adoptEnvEligible) because
// every way into a containerd sandbox runs through toolboxd's children,
// SSH included (a toolbox session); docker keeps env off its pool because
// its SSH exec path is `docker exec`, which reads the engine's env.
func poolEligible(req models.CreateSandboxRequest, hostMounts []mounts.ContainerBind) bool {
	if len(req.Mounts) > 0 || len(req.PlatformVolumes) > 0 || len(hostMounts) > 0 {
		return false
	}
	if user := strings.TrimSpace(req.OSUser); user != "" && !strings.EqualFold(user, "root") {
		return false
	}
	// A parked container's image user was never checked against the create
	// policy's require_non_root rule; the cold path checks it first.
	if req.RequireNonRootUser {
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
	// Env last: it is the one check that encodes (ValidateAdoptEnv), and
	// only a create that passes everything else gets that far.
	return req.Image != "" && adoptEnvEligible(req.Env)
}

// adoptEnvEligible reports whether env can reach a parked container in its
// adopt frame and mean what it means on a cold create. The frame puts env
// in toolboxd's store for its children; a cold create puts it in toolboxd's
// own environment too. So a key toolboxd reads for itself at boot would be
// honoured cold and ignored warm, and keeps the create cold: SB_* (its
// settings, the gVisor task cap among them), AEROLVM_EGRESS_CA* (the
// inspect CA bundle it writes at boot), and USER and LOGNAME (the envd user
// check). An env the frame cannot carry (ValidateAdoptEnv: a bad entry, or
// over readyproto.MaxAdoptEnvBytes encoded) goes cold too, before a slot is
// spent on it. Env with mounts or binds (egress inspect rules) is already
// off the pool through hostMounts.
func adoptEnvEligible(env map[string]string) bool {
	if len(env) == 0 {
		return true
	}
	for k := range env {
		if adoptEnvReservedKey(k) {
			return false
		}
	}
	return readyproto.ValidateAdoptEnv(env) == nil
}

func adoptEnvReservedKey(k string) bool {
	return strings.HasPrefix(k, "SB_") || k == gvisorpids.EnvVar ||
		strings.HasPrefix(k, "AEROLVM_EGRESS_CA") || k == "USER" || k == "LOGNAME"
}

// envAdopter is a parked slot's handle that can carry the sandbox's env in
// its adopt frame (dockerpkg.ParkedListener).
type envAdopter interface {
	AdoptWithEnv(ctx context.Context, sandboxID, token, adoptNonce string, env map[string]string) error
}

// adoptHandle adopts over h with env, refusing a handle that cannot carry a
// non-empty env rather than adopting without it.
func adoptHandle(ctx context.Context, h any, sandboxID, token, nonce string, env map[string]string) error {
	if ea, ok := h.(envAdopter); ok {
		return ea.AdoptWithEnv(ctx, sandboxID, token, nonce, env)
	}
	if len(env) > 0 {
		return errors.New("parked slot handle cannot carry the sandbox env")
	}
	a, ok := h.(interface {
		Adopt(context.Context, string, string, string) error
	})
	if !ok {
		return errors.New("parked slot handle type mismatch")
	}
	return a.Adopt(ctx, sandboxID, token, nonce)
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
	// The env rides the frame, not the spec or the labels: the spec stays
	// the pool's, so `ctr containers info`, a commit or a snapshot of this
	// container holds none of it. A missing or wrong env digest in the ack
	// fails here, and tryWarmAdopt destroys the slot and goes cold.
	if err := adoptHandle(adoptCtx, slot.Handle, sandboxID, toolboxToken, adoptNonce, req.Env); err != nil {
		return nil, err
	}
	// The park's listener has done its one job: the toolbox holds the
	// sandbox's identity and has hung up. Closing it unlinks the park socket
	// and frees its fd; each later start listens on that path afresh
	// (startTask), and the old listener can no longer unlink the new one's
	// socket out from under a start.
	_ = slot.Handle.Close()

	// containerd's SetLabels updates only the keys it is given and leaves
	// every other label alone, so deleting the park key from this map kept
	// it on the container. The adopted sandbox then still read as park
	// inventory, and sandboxd's next shutdown drained it like a parked slot:
	// its task was stopped while the store still said started (live UC-212,
	// 2026-11-08). An empty value is how containerd deletes a label.
	labels[poolParkLabelKey] = ""
	labels[sandboxIDLabelKey] = sandboxID
	if len(req.Env) > 0 {
		labels[adoptEnvLabelKey] = adoptEnvLabelValue
	}
	if ip := strings.TrimSpace(slot.ContainerIP); ip != "" {
		labels[containerIPLabelKey] = ip
	}
	if _, err := container.SetLabels(ctx, labels); err != nil {
		return nil, err
	}

	if d.netns != nil && slot.ID != "" && slot.ID != sandboxID {
		_ = d.netns.ReassignOwner(ctx, slot.ID, sandboxID)
	}
	// The park's host files stay where they are: the container's spec
	// mounts them from the slot id's path, and the container keeps that id
	// (see sandboxHostFiles). Destroy removes them by the container id.

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

// destroyParked tears a parked container down in Destroy's order: the
// container first; then, only once it is confirmed gone, the address's rules
// (while the netns slot still holds the address, so they cannot be the next
// owner's), the netns slot, and the host files. A failed delete returns
// before any of those, so the container keeps its slot, its park block and
// its files: no other sandbox can be handed the slot while it still runs.
// The warm pool keeps that slot and retries until this returns nil
// (dockerpool pending_destroy.go), so the slot is released exactly once, on
// confirmed absence.
func (d *Driver) destroyParked(ctx context.Context, slot *containerdpool.ParkedSlot) error {
	if slot == nil {
		return nil
	}
	// The slot id and the container id are the same string (parkContainer);
	// the boot purge knows only the container id. Every file the park keyed
	// by it goes with the container: host files, task log, park socket.
	parkKey := strings.TrimSpace(slot.ID)
	if parkKey == "" {
		parkKey = strings.TrimSpace(slot.ContainerID)
	}
	// The host-side listener is this process's alone.
	if slot.Handle != nil {
		_ = slot.Handle.Close()
	}
	if pl, ok := slot.Handle.(*dockerpkg.ParkedListener); ok {
		dockerpkg.RemoveParkSocket(pl.HostSocketPath())
	}
	if err := d.deleteParkedContainer(ctx, slot.ContainerID); err != nil {
		return err
	}
	if slot.ContainerIP != "" {
		_ = d.ClearNetworkRules(slot.ContainerIP)
	}
	// Release the prepaid netns slot the park held (keyed by the park slot id,
	// which equals ContainerID for a parked container). Without this, every park
	// teardown — LRU/stale-image evict, idle-TTL reap, shutdown drain, boot
	// PurgeParkedContainers — permanently leaks a netns slot (row stays adopted
	// under the dead park id, plus its veth/IPAM lease/conntrack) until the pool
	// exhausts and cold creates fail with "provision netns: no free slot".
	// Release is idempotent and a no-op if the slot was already reassigned to an
	// adopting sandbox.
	if d.netns != nil && parkKey != "" {
		_ = d.netns.Release(ctx, parkKey)
	}
	d.removeContainerFiles(parkKey)
	return nil
}

// deleteParkedContainer kills a parked container's task and deletes the
// container. A container containerd does not have is already gone, which
// counts as done (like docker's 404 on remove).
func (d *Driver) deleteParkedContainer(ctx context.Context, containerID string) error {
	if strings.TrimSpace(containerID) == "" {
		return nil
	}
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	container, err := client.LoadContainer(ctx, containerID)
	if errdefs.IsNotFound(err) {
		return nil
	}
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
	if err := container.Delete(ctx); err != nil && !errdefs.IsNotFound(err) {
		return err
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
// A park never carries a sandbox id; an adopt sets one. Requiring its absence
// keeps a sandbox adopted by an older build, whose adopt left the park label
// on (see adoptParked), from being drained or listed as park inventory.
func IsParkedContainerLabels(labels map[string]string) bool {
	return labels != nil && labels[poolParkLabelKey] == poolParkLabelValue &&
		strings.TrimSpace(labels[sandboxIDLabelKey]) == ""
}

// IsParkedSandboxID reports park-<hex> slot ids.
func IsParkedSandboxID(id string) bool {
	return strings.HasPrefix(strings.TrimSpace(id), "park-")
}
