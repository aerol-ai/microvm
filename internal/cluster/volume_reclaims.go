package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client side of the replicated volume-reclaim ledger
// (fsm_volume_reclaims.go).

// volumeReclaimAdoptAfter is how old an entry must be before a node other
// than its own may take it over from a node that is dead or unknown. Three
// default reclaim intervals: a live owner drains its entries well before, so
// a gossip blip does not move them.
const volumeReclaimAdoptAfter = 15 * time.Minute

// VolumeReclaimClient is implemented by the cluster clients that replicate
// delete_with_sandbox volume reclaims. Optional (type-asserted) so the
// single-node Noop and test doubles need not grow it.
type VolumeReclaimClient interface {
	// VolumeReclaimsReplicated reports whether a placement delete records
	// the reclaims: every server applies the ops.
	VolumeReclaimsReplicated() bool
	// VolumeReclaimsFor lists up to limit entries nodeID should drain: its
	// own, then ones whose node is gone or never drains.
	VolumeReclaimsFor(ctx context.Context, nodeID string, limit int) ([]VolumeReclaim, error)
	// ClaimVolumeReclaim moves r to nodeID if it is still r, held by
	// r.NodeID; ErrVolumeReclaimMoved otherwise.
	ClaimVolumeReclaim(ctx context.Context, r VolumeReclaim, nodeID string) error
	// AckVolumeReclaim drops r once its bytes are deleted. Idempotent.
	AckVolumeReclaim(ctx context.Context, r VolumeReclaim) error
	// VolumeDeleteOwingBytes deletes an unattached volume row and records
	// its reclaim (source when the row has none) in the same apply, drained
	// by a worker. The caller checks VolumeReclaimsReplicated first.
	// ErrUnknownVolume / ErrVolumeInUse as VolumeDelete.
	VolumeDeleteOwingBytes(ctx context.Context, tenant, id, source string) error
}

var (
	_ VolumeReclaimClient = (*Cluster)(nil)
	_ VolumeReclaimClient = (*Agent)(nil)
)

// VolumeReclaimsReplicated: every Raft server applies the reclaim ops.
func (c *Cluster) VolumeReclaimsReplicated() bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	return c.raftServersSupport(volumeReclaimFSMOpsVersion, "volume reclaims") == nil
}

// VolumeReclaimsFor answers from this server's replica.
func (c *Cluster) VolumeReclaimsFor(_ context.Context, nodeID string, limit int) ([]VolumeReclaim, error) {
	if c == nil || c.fsm == nil {
		return []VolumeReclaim{}, nil
	}
	out := c.fsm.volumeReclaimsFor(nodeID, gossipReclaimNodeState(c.gossip), time.Now(), limit)
	if out == nil {
		out = []VolumeReclaim{}
	}
	return out, nil
}

// gossipReclaimNodeState answers from this server's membership view: a live
// member whose role cannot own sandboxes never runs the reclaim sweep.
func gossipReclaimNodeState(g *gossipNode) reclaimNodeState {
	return func(nodeID string) (alive, drains bool) {
		m, ok := g.lookupMember(nodeID)
		if !ok || !m.Alive {
			return false, false
		}
		return true, CanOwnSandboxRole(m.Role)
	}
}

func (c *Cluster) ClaimVolumeReclaim(ctx context.Context, r VolumeReclaim, nodeID string) error {
	cmd, err := claimVolumeReclaimCommand(r, nodeID)
	if err != nil {
		return err
	}
	return c.applyCommand(ctx, cmd)
}

func (c *Cluster) AckVolumeReclaim(ctx context.Context, r VolumeReclaim) error {
	return c.applyCommand(ctx, command{Op: opAckVolumeReclaim, VolumeReclaim: &r})
}

// VolumeReclaimsReplicated on a worker or ingress node: every live member,
// any role, runs a build with the ops (the agent cannot read the Raft
// configuration, so it asks the stricter question).
func (a *Agent) VolumeReclaimsReplicated() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(volumeReclaimFSMOpsVersion)
}

// VolumeReclaimsFor asks a server, which answers from its replica.
func (a *Agent) VolumeReclaimsFor(ctx context.Context, nodeID string, limit int) ([]VolumeReclaim, error) {
	q := url.Values{"kind": {"reclaims"}, "node_id": {nodeID}, "limit": {strconv.Itoa(limit)}}
	resp, err := a.queryVolumes(ctx, q)
	if err != nil {
		return nil, err
	}
	if resp.Reclaims == nil {
		return []VolumeReclaim{}, nil
	}
	return resp.Reclaims, nil
}

func (a *Agent) ClaimVolumeReclaim(ctx context.Context, r VolumeReclaim, nodeID string) error {
	cmd, err := claimVolumeReclaimCommand(r, nodeID)
	if err != nil {
		return err
	}
	return a.applyCommand(ctx, cmd)
}

func (a *Agent) AckVolumeReclaim(ctx context.Context, r VolumeReclaim) error {
	return a.applyCommand(ctx, command{Op: opAckVolumeReclaim, VolumeReclaim: &r})
}

func (c *Cluster) VolumeDeleteOwingBytes(ctx context.Context, tenant, id, source string) error {
	cmd, err := volumeDeleteOwingBytesCommand(tenant, id, source, c.nodeID)
	if err != nil {
		return err
	}
	err = c.applyCommand(ctx, cmd)
	if errors.Is(err, ErrUnknownVolume) {
		return ErrUnknownVolume
	}
	return err
}

func (a *Agent) VolumeDeleteOwingBytes(ctx context.Context, tenant, id, source string) error {
	cmd, err := volumeDeleteOwingBytesCommand(tenant, id, source, a.nodeID)
	if err != nil {
		return err
	}
	err = a.applyCommand(ctx, cmd)
	if errors.Is(err, ErrUnknownVolume) {
		return ErrUnknownVolume
	}
	return err
}

// volumeDeleteOwingBytesCommand is opDeleteVolume asking for the record,
// drained by nodeID: a worker drains its own; any worker takes over one
// recorded by an ingress or server node at once (volumeReclaimsFor).
func volumeDeleteOwingBytesCommand(tenant, id, source, nodeID string) (command, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if tenant == "" || id == "" {
		return command{}, fmt.Errorf("cluster: VolumeDeleteOwingBytes requires tenant and id")
	}
	cmd := command{Op: opDeleteVolume, VolumeTenant: tenant, VolumeID: id, VolumeReclaimSource: strings.TrimSpace(source)}
	stampVolumeReclaims(&cmd, true, nodeID)
	return cmd, nil
}

func claimVolumeReclaimCommand(r VolumeReclaim, nodeID string) (command, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return command{}, fmt.Errorf("cluster: claim volume reclaim requires a node id")
	}
	return command{Op: opClaimVolumeReclaim, VolumeReclaim: &r, NodeID: nodeID}, nil
}

// stampVolumeReclaims asks an opDelete to record the reclaims of the
// sandbox's delete_with_sandbox volumes, drained by nodeID, when every
// replica applies them.
func stampVolumeReclaims(cmd *command, replicated bool, nodeID string) {
	if !replicated || strings.TrimSpace(nodeID) == "" {
		return
	}
	cmd.VolumeReclaimNodeID = strings.TrimSpace(nodeID)
	cmd.StampUnixNano = time.Now().UnixNano()
}
