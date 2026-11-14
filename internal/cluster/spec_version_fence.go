package cluster

import (
	"context"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The spec version fence: opUpsertSpec as a compare-and-set.
//
// A spec write replaces the whole replicated spec, so every caller reads the
// spec, changes one field and writes all of it back. On a worker the read
// goes to a random server (Agent.doControlPlaneBytes), and a follower
// answers from its own FSM, which learns that an entry committed only with
// the leader's next message, up to a heartbeat (~100 ms) later. So the read
// right after this node's own spec write can return the spec from before it,
// and the next write puts the old field back: a resize followed at once by a
// tags or lifecycle change brought back the old size, which the team quota
// and a failover recreate then used. The spec lock (Service.lockSpec) orders
// one node's writes; it cannot make a read fresh. UC-704 saw the same stale
// read as a second Raft entry for one keep-alive.
//
// So a writer sends the Placement.Version of the spec it read
// (command.ExpectedPlacementVersion), and the write lands only while the
// placement is still at that version. Every op that changes a spec moves the
// version (it is the Raft index of the placement's last change), so a write
// based on an old copy is refused with ErrSpecVersionConflict, and the writer
// reads again and redoes its change (service.writeReplicatedSpec). An op
// that leaves the spec alone (a port, a domain) moves the version too; that
// costs the writer one more read, never a wrong spec.
//
// The leader checks first (admitSpecVersion): a version older than the
// leader's own copy is refused before it reaches the log, so the usual
// stale read costs no Raft entry. The FSM check is the one that counts; it
// also refuses a write that raced an entry still in flight.
//
// Rolling upgrade: an older server ignores ExpectedPlacementVersion and would
// apply a write a newer one refuses, splitting the replicas. A proposer sets
// it only once every Raft server (Cluster) or every live member (Agent) runs
// specVersionFenceFSMOpsVersion, and the leader drops it again while any
// server in its Raft configuration does not (the Agent sees only the live
// members). Until then a spec write works as it always did.

// specVersionFenceFSMOpsVersion: opUpsertSpec honours
// ExpectedPlacementVersion.
const specVersionFenceFSMOpsVersion = 17

// ErrSpecVersionConflict is a spec write based on a copy of the spec that
// changed after it was read. Re-sending the same write cannot succeed; the
// writer reads the spec again and redoes its change.
var ErrSpecVersionConflict = errors.New("cluster: sandbox spec changed since it was read")

// VersionedSpecClient is implemented by the cluster clients whose spec
// writes can carry the version check: Cluster and Agent. Noop has no
// replicated spec, and a caller holding any other Client writes as before.
type VersionedSpecClient interface {
	// SpecAndVersionOf is SpecOf plus the Placement.Version the spec was
	// read at; (nil, 0) when there is no spec.
	SpecAndVersionOf(sandboxID string) (*models.CreateSandboxRequest, uint64)
	// UpsertSpecIfVersion is UpsertSpec with an empty secrets handle that
	// lands only while the placement is still at version, and otherwise
	// fails with ErrSpecVersionConflict. With version 0, or while some
	// server predates the check, it writes without one.
	UpsertSpecIfVersion(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, version uint64) error
}

// specVersionFence is the FSM's check for one opUpsertSpec against the
// version the placement has now. It reads no clock and no node config, so
// every replica gives the same answer.
func specVersionFence(cmd command, have uint64) error {
	if cmd.ExpectedPlacementVersion == 0 || cmd.ExpectedPlacementVersion == have {
		return nil
	}
	return fmt.Errorf("%w: %s is at version %d, the write was based on %d", ErrSpecVersionConflict, cmd.SandboxID, have, cmd.ExpectedPlacementVersion)
}

func (c *Cluster) specVersionFenceReplicated() bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	return c.raftServersSupport(specVersionFenceFSMOpsVersion, "the spec version check") == nil
}

func (a *Agent) specVersionFenceReplicated() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(specVersionFenceFSMOpsVersion)
}

// SpecAndVersionOf implements VersionedSpecClient from this server's FSM.
func (c *Cluster) SpecAndVersionOf(sandboxID string) (*models.CreateSandboxRequest, uint64) {
	if c == nil || c.fsm == nil {
		return nil, 0
	}
	p, ok := c.fsm.get(sandboxID)
	if !ok || p.Spec == nil {
		return nil, 0
	}
	return p.Spec, p.Version // get returns a deep copy
}

// UpsertSpecIfVersion implements VersionedSpecClient.
func (c *Cluster) UpsertSpecIfVersion(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, version uint64) error {
	if !c.specVersionFenceReplicated() {
		version = 0
	}
	return c.upsertSpec(ctx, sandboxID, spec, PlacementSecrets{}, version)
}

// SpecAndVersionOf implements VersionedSpecClient with one control-plane
// read, the same one SpecOf makes.
func (a *Agent) SpecAndVersionOf(sandboxID string) (*models.CreateSandboxRequest, uint64) {
	lookup, ok, err := a.lookupPlacement(context.Background(), sandboxID)
	if err != nil {
		a.logger.Warn("cluster agent: SpecAndVersionOf control-plane lookup failed", "sandbox_id", sandboxID, "err", err)
		return nil, 0
	}
	if !ok || lookup.Placement.Spec == nil {
		return nil, 0
	}
	return cloneCreateSandboxRequest(lookup.Placement.Spec), lookup.Placement.Version
}

// UpsertSpecIfVersion implements VersionedSpecClient.
func (a *Agent) UpsertSpecIfVersion(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, version uint64) error {
	if !a.specVersionFenceReplicated() {
		version = 0
	}
	return a.upsertSpec(ctx, sandboxID, spec, PlacementSecrets{}, version)
}

// admitSpecVersion is the leader's step for a spec write that carries a
// version, before the write is proposed. It drops the version while some
// Raft server predates the check (an Agent's gate sees only live members),
// and refuses a write whose version is older than this leader's copy of the
// placement: that writer read a stale copy, and its entry would only be
// refused at apply. A version newer than the leader's copy (this leader has
// not applied an entry a follower already has) goes on to the FSM check.
// It returns the payload to propose.
func (c *Cluster) admitSpecVersion(payload []byte, cmd command) ([]byte, command, error) {
	if cmd.Op != opUpsertSpec || cmd.ExpectedPlacementVersion == 0 {
		return payload, cmd, nil
	}
	if !c.specVersionFenceReplicated() {
		cmd.ExpectedPlacementVersion = 0
		out, err := encodeCommand(cmd)
		if err != nil {
			return nil, cmd, fmt.Errorf("cluster: encode command: %w", err)
		}
		return out, cmd, nil
	}
	if have, ok := c.fsm.placementVersion(cmd.SandboxID); ok && have > cmd.ExpectedPlacementVersion {
		return nil, cmd, specVersionFence(cmd, have)
	}
	return payload, cmd, nil
}

// placementVersion reads one placement's version from the hot row map
// without cloning it.
func (f *placementFSM) placementVersion(id string) (uint64, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, ok := f.placements[id]
	return p.Version, ok
}
