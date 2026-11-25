package containerd

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"syscall"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/capacity"
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
		if derr := d.discardClaimedSlot(ctx, slot, sandboxID, err); derr != nil {
			return nil, derr
		}
		return nil, fmt.Errorf("warm adopt failed: %w", err)
	}
	return state, nil
}

// errClaimLeftover refuses a create whose failed claim left its container
// running in a network namespace the sandbox id still holds: the owner
// could not be moved back to the park, and the container could not be
// removed. The create must not go cold (createContainer returns it): its
// netns step would hand it that namespace, the one the claim's container
// still runs in. It is a capacity refusal, which every API surface answers
// 503 with Retry-After (apihttp Classify), so the caller retries, and in a
// cluster the retry can go to another node. A retry here that takes a
// warm slot meets the container by its sandbox label and has it removed as
// the sandbox's leftover first (service create_leftover.go). One that finds
// no free slot and would go cold is refused the same way until the pool's
// retry has removed the container (claim_leftovers.go).
var errClaimLeftover = fmt.Errorf("an earlier attempt to create this sandbox on this node is still being cleaned up; retry shortly (%w)", capacity.ErrCapacityExceeded)

// claimOwnerBackTimeout bounds moving a failed claim's netns owner back to
// the park, a local store write. It has its own bound so a hung write does
// not use up the teardown's: the container is removed either way. A var for
// tests.
var claimOwnerBackTimeout = 5 * time.Second

// discardClaimedSlot tears down a slot whose claim failed (cause). The slot
// left the pool at Acquire, so this is the only path that removes it. It
// returns errClaimLeftover when the create must not go cold, else nil.
//
// It does not run on ctx: a client that hangs up mid-claim cancels ctx,
// and a teardown on it failed at its first containerd call and left the
// container behind, as a failed cold create's undo once did (UC-450).
//
// A claim moves the slot's netns owner from the park id to the sandbox
// once the relabel is in: in single mode before the rules, in split mode
// while the rules trip is in flight (splitClaimFinish). So the owner may
// or may not have moved, whichever step failed. It is moved back first:
// then the slot is wholly the park's again, destroyParked (and the
// pool's retries of it) frees it under the park id once the container is
// gone, and the cold create this one falls back to gets a namespace of
// its own instead of being handed the park's under the sandbox id. The
// store moves a row only while the park id holds none, so this is a
// no-op when the claim never moved it.
//
// A teardown that fails goes to the pool's retry list, still charged
// (RetainFailedDestroy logs and counts it): the container keeps its
// netns slot and its block until it is confirmed gone. Releasing the
// reservation here would leave it with nothing to remove it but a
// restart's boot purge.
//
// When moving the owner back failed too, the namespace and its address
// may be the sandbox id's, not the park's. The retry then gets the slot
// without its address: it removes the container and the park's files
// only, and clears no rules, since by then the address may carry the
// sandbox's own rules, or another sandbox's. The slot and its rules are
// left to the sandbox id's own release: its leftover removal on a retry of
// the create (Destroy), or, once the retry has removed the container and
// no container of the sandbox is left, the driver's own
// (finishClaimLeftover).
func (d *Driver) discardClaimedSlot(ctx context.Context, slot *containerdpool.ParkedSlot, sandboxID string, cause error) error {
	var ownerErr error
	if d.netns != nil && slot.ID != "" && slot.ID != sandboxID {
		octx, ocancel := context.WithTimeout(context.WithoutCancel(ctx), claimOwnerBackTimeout)
		ownerErr = d.netns.ReassignOwner(octx, sandboxID, slot.ID)
		ocancel()
	}
	uctx, cancel := undoContext(ctx)
	defer cancel()
	if err := d.destroyParked(uctx, slot); err != nil {
		if ownerErr == nil {
			d.warmPool.RetainFailedDestroy(slot, err)
			return nil
		}
		kept := *slot
		kept.ContainerIP = ""
		// Before the retry list gets it: the retry may run at once.
		d.claimLeftovers.remember(slot.ID, sandboxID, slot.ContainerIP)
		d.warmPool.RetainFailedDestroy(&kept, err)
		d.logger.Warn("containerd warm claim: the failed claim's container could not be removed and its network namespace stays under the sandbox id; refusing the create instead of going cold",
			"sandbox_id", sandboxID, "slot_id", slot.ID, "claim_error", cause, "error", err, "owner_error", ownerErr)
		return errClaimLeftover
	}
	// The container is gone, so a slot the sandbox id still holds (the
	// park's, when moving the owner back failed) goes too, with whatever
	// rules the claim put on its address.
	_, _ = d.giveBack(uctx, giveBackReq{owner: sandboxID, clear: d.wholeAddress})
	d.warmPool.ReleasePark(slot.ID)
	return nil
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

	// In privilege mode split every read of containerd is one more trip
	// through the root helper's gate, on the warm create's path, so a split
	// claim reads once (splitClaimRead): the slot's record and the check
	// that the sandbox is not there yet, in one list.
	var read claimRead
	if d.helper != nil {
		read, err = splitClaimRead(ctx, client, sandboxID, slot.ContainerID)
	} else {
		read, err = loadClaimedSlot(ctx, client, slot.ContainerID)
	}
	if err != nil {
		return nil, err
	}
	container, info := read.container, read.info
	labels := maps.Clone(info.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	if sid := strings.TrimSpace(labels[sandboxIDLabelKey]); sid == sandboxID {
		return d.adoptedRuntimeState(slot, sandboxID), nil
	}
	if d.helper == nil {
		read.exists = d.assertSandboxNotExists(ctx, client, sandboxID, slot.ContainerID)
	}
	if read.exists != nil {
		return nil, read.exists
	}
	// The slot's writable layer gets the request's disk limit before the
	// toolbox takes the sandbox's identity; a failure destroys the slot and
	// the create goes cold (tryWarmAdopt), where the same limit applies.
	// In privilege mode split the helper sets it, as for a resize.
	if d.cfg.DiskQuota && req.DiskGB > 0 {
		if d.helper != nil {
			err = d.splitResizeDisk(ctx, container, info.SnapshotKey, req.DiskGB)
		} else {
			err = d.limitWritableLayer(ctx, client, info.SnapshotKey, req.DiskGB)
		}
		if err != nil {
			return nil, err
		}
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
	// In privilege mode split the relabel and the slot's rules are two
	// trips to the root helper; they go at once (splitClaimFinish).
	if d.helper != nil {
		if err := d.splitClaimFinish(ctx, container, labels, slot, sandboxID, req); err != nil {
			return nil, err
		}
		return d.adoptedRuntimeState(slot, sandboxID), nil
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

// claimRead is what a warm claim reads of containerd: the claimed slot's
// container and record, and exists, the answer to whether a container of
// the sandbox is there already (assertSandboxNotExists's), which the claim
// weighs once it has seen whether the slot is this sandbox's already.
type claimRead struct {
	container cntr.Container
	info      containers.Container
	exists    error
}

// loadClaimedSlot is single mode's read of the claimed slot: its labels
// and snapshot key come from the load's own read (Labels and Info would
// each read it again). The existence check is the claim's own reads.
func loadClaimedSlot(ctx context.Context, client *Client, slotID string) (claimRead, error) {
	container, err := client.LoadContainer(ctx, slotID)
	if err != nil {
		return claimRead{}, err
	}
	info, err := container.Info(ctx, cntr.WithoutRefreshedMetadata)
	if err != nil {
		return claimRead{}, err
	}
	return claimRead{container: container, info: info}, nil
}

// splitClaimRead is a split claim's one read of containerd, in place of
// single mode's three (loadClaimedSlot and assertSandboxNotExists's two):
// containerd answers a list with several filters with what matches any of
// them, and the records come with the list. So one list gives the claimed
// slot, a container named after the sandbox and any that carries its ID
// as a label. A slot containerd no longer has is NotFound, as
// LoadContainer answers.
func splitClaimRead(ctx context.Context, client *Client, sandboxID, slotID string) (claimRead, error) {
	found, err := client.ListContainers(ctx, "id=="+slotID, "id=="+sandboxID, "labels."+sandboxIDLabelKey+"=="+sandboxID)
	if err != nil {
		return claimRead{}, err
	}
	var read claimRead
	for _, c := range found {
		info, err := c.Info(ctx, cntr.WithoutRefreshedMetadata)
		if err != nil {
			return claimRead{}, err
		}
		switch {
		case c.ID() == slotID:
			read.container, read.info = c, info
		case c.ID() == sandboxID && IsParkedContainerLabels(info.Labels):
			// A parked slot named after the sandbox carries no sandbox
			// ID: as assertSandboxNotExists, it is no sandbox.
		default:
			read.exists = dockerpkg.ErrSandboxContainerExists
		}
	}
	if read.container == nil {
		return claimRead{}, fmt.Errorf("container %q: %w", slotID, errdefs.ErrNotFound)
	}
	return read, nil
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
	// Give back the prepaid netns slot the park held (keyed by the park slot
	// id, which equals ContainerID for a parked container), with every rule
	// of its address, not only the park block: a claim that failed half way
	// may have put the request's lists there. Without this, every park
	// teardown — LRU/stale-image evict, idle-TTL reap, shutdown drain, boot
	// PurgeParkedContainers — permanently leaks a netns slot (row stays
	// adopted under the dead park id, plus its veth/IPAM lease/conntrack)
	// until the pool exhausts and cold creates fail with "provision netns:
	// no free slot". A slot the park no longer holds (reassigned to an
	// adopting sandbox) is not touched (giveBack).
	_, _ = d.giveBack(ctx, giveBackReq{owner: parkKey, known: slot.ContainerIP, clear: d.wholeAddress})
	d.removeContainerFiles(parkKey)
	// Privilege mode split: the helper's files for the slot (its host
	// files, FIFOs and its name for the park socket) go too. A no-op in
	// single mode.
	d.releaseHelperFiles(ctx, parkKey)
	// A failed claim's leftover: the namespace its sandbox id still holds
	// goes too, once it is empty (claim_leftovers.go). An error keeps the
	// slot on the pool's retry list.
	return d.finishClaimLeftover(ctx, parkKey)
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
