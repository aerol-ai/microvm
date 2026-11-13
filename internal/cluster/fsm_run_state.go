package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

// Sandbox run state in the Raft FSM (plans/kubernetes-v2-architecture.md
// §16, C17). A sandbox's started/stopped status lives in its owner's local
// row, which no other node sees change; the Kubernetes agent-sandbox API on
// the gateways must show it, and its watch must report each change with a
// resourceVersion every gateway agrees on. So an owner reports real
// transitions here, batched, and the entry's Raft index becomes the row's
// RunStateIndex: global, ordered, and carried by the placement change feed
// the gateways already follow.
//
// It never moves Placement.Version. A stop or start is not a spec change:
// moving the version would fail every spec compare-and-set read before it
// (spec_version_fence.go) and every cache keyed by (id, Version). Readers
// that merge rows compare (Version, RunStateIndex) instead
// (placementAtLeast).

const opSetRunStates opCode = 51 // record owners' reported run states, batched

// runStateFSMOpsVersion: opSetRunStates and the Placement.RunState fields.
const runStateFSMOpsVersion = 18

// maxRunStateReports bounds one entry, so one busy owner's batch stays a
// small log entry.
const maxRunStateReports = 500

// PublicInternalRunStatesPath is where an owner sends its batch; any server
// takes it and forwards it to the leader.
const PublicInternalRunStatesPath = "/v1/cluster/internal/run-states"

// RunState is a sandbox's run state as its owner reports it.
type RunState string

const (
	RunStateRunning   RunState = "running"
	RunStateSuspended RunState = "suspended"
	RunStateFailed    RunState = "failed"
)

func (s RunState) valid() bool {
	return s == RunStateRunning || s == RunStateSuspended || s == RunStateFailed
}

// RunStateReport is one sandbox's state. IncarnationID and OwnerNodeID
// fence it: a report from a node that no longer owns this lifetime of the
// sandbox (a failover, or a re-create under the same ID) changes nothing.
type RunStateReport struct {
	SandboxID     string   `json:"sandbox_id"`
	IncarnationID string   `json:"incarnation_id"`
	OwnerNodeID   string   `json:"owner_node_id"`
	State         RunState `json:"state"`
	Reason        string   `json:"reason,omitempty"`
}

// RunStateWriteRequest is one owner's batch.
type RunStateWriteRequest struct {
	Reports []RunStateReport `json:"reports"`
}

// RunStateWriteResponse counts the reports that changed a row.
type RunStateWriteResponse struct {
	Applied int `json:"applied"`
}

// RunStatePublisher is implemented by the cluster clients an owner can
// report through: Cluster and Agent. Noop has nothing to report to.
type RunStatePublisher interface {
	SetRunStates(ctx context.Context, reports []RunStateReport) (int, error)
}

// ErrBadRunStateBatch is a batch that is empty, too large, or holds a
// report without a sandbox, an owner or a known state. Sending it again
// cannot succeed.
var ErrBadRunStateBatch = errors.New("cluster: bad run-state batch")

func validateRunStateReports(reports []RunStateReport) error {
	if len(reports) == 0 || len(reports) > maxRunStateReports {
		return fmt.Errorf("%w: it holds 1 to %d reports, not %d", ErrBadRunStateBatch, maxRunStateReports, len(reports))
	}
	for _, r := range reports {
		if strings.TrimSpace(r.SandboxID) == "" || strings.TrimSpace(r.OwnerNodeID) == "" || !r.State.valid() {
			return fmt.Errorf("%w: report %+v needs a sandbox, an owner and a state", ErrBadRunStateBatch, r)
		}
	}
	return nil
}

// applySetRunStatesLocked records each report that names the row's current
// owner and lifetime and changes it. It edits the hot row in place: the
// recovery payload, the indexes and Version stay as they are. The proposer
// validated the batch; a row that moved or went away since is skipped, the
// same way on every replica.
func (f *placementFSM) applySetRunStatesLocked(cmd command) (any, error) {
	if err := validateRunStateReports(cmd.RunStates); err != nil {
		return nil, err
	}
	applied := 0
	for _, r := range cmd.RunStates {
		p, ok := f.placements[r.SandboxID]
		if !ok || p.State != "" || p.IncarnationID != r.IncarnationID || p.OwnerNodeID != r.OwnerNodeID {
			continue
		}
		if p.RunState == r.State && p.RunStateReason == r.Reason {
			continue
		}
		p.RunState, p.RunStateReason, p.RunStateIndex = r.State, r.Reason, f.version
		f.placements[r.SandboxID] = p
		f.recordPlacementChangeLocked(r.SandboxID, false)
		applied++
	}
	return RunStateWriteResponse{Applied: applied}, nil
}

// placementAtLeast is the merge rule for two copies of one row: the higher
// Version wins, and at the same Version the later run state.
func placementAtLeast(p, cur Placement) bool {
	if p.Version != cur.Version {
		return p.Version > cur.Version
	}
	return p.RunStateIndex >= cur.RunStateIndex
}

// SetRunStates records an owner's batch. The leader checks the upgrade gate
// and applies; a follower forwards one hop to the leader.
func (c *Cluster) SetRunStates(ctx context.Context, reports []RunStateReport) (int, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return 0, fmt.Errorf("cluster: node holds no placement state")
	}
	if err := validateRunStateReports(reports); err != nil {
		return 0, err
	}
	if c.raft.raft.State() != raft.Leader {
		var out RunStateWriteResponse
		if err := c.forwardToLeaderJSON(ctx, "run states", PublicInternalRunStatesPath, RunStateWriteRequest{Reports: reports}, &out); err != nil {
			return 0, err
		}
		return out.Applied, nil
	}
	if err := c.raftServersSupport(runStateFSMOpsVersion, "sandbox run states"); err != nil {
		return 0, err
	}
	payload, err := encodeCommand(command{Op: opSetRunStates, RunStates: reports, StampUnixNano: time.Now().UnixNano()})
	if err != nil {
		return 0, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return 0, err
	}
	if out, ok := result.(RunStateWriteResponse); ok {
		return out.Applied, nil
	}
	return 0, nil
}

// SetRunStates sends an owner's batch to the server tier.
func (a *Agent) SetRunStates(ctx context.Context, reports []RunStateReport) (int, error) {
	if a == nil {
		return 0, fmt.Errorf("cluster: agent is not configured")
	}
	if err := validateRunStateReports(reports); err != nil {
		return 0, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out RunStateWriteResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalRunStatesPath, PublicInternalRunStatesPath, RunStateWriteRequest{Reports: reports}, &out); err != nil {
		return 0, fmt.Errorf("cluster: run states: %w", err)
	}
	return out.Applied, nil
}
