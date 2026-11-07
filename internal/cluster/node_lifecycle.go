package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Node lifecycle for `aerolvm get/describe/delete node`
// (plans/kubectl-style-cluster-ops.md §5).
//
//	DELETE /v1/cluster/nodes/{id} ─► any node ─► leader ─┬─ Raft server: RemoveMember (unchanged)
//	                                                    └─ worker/ingress: deny ─► drain ─► reassign/orphan
//	GET    /v1/cluster/nodes/{id} ─► server: member + FSM owner count + heartbeat running count
//
// The old DELETE /v1/cluster/members/{id} keeps its answers, 404 for a
// worker included: /v1 is soft-frozen, so the any-role delete is a new path.
//
// Order on a worker: the deny record is written FIRST. From that commit the
// node's internal calls are refused, so it cannot claim back the orphans the
// next steps create (AssertOwnership reclaims "orphaned from self") or apply
// anything else; only then are its placements moved. Every step is
// idempotent, so a delete that fails part way is finished by the retry, and
// the dead-owner loop also evicts a denied node that still owns placements.

// PublicNodesPath prefixes the per-node operator routes.
const PublicNodesPath = "/v1/cluster/nodes/"

// maxNodeDetailSandboxIDs caps the sandbox IDs one node read returns.
const maxNodeDetailSandboxIDs = 1000

var (
	// ErrUnknownNode is a delete or read of a node this cluster has no trace
	// of: not in gossip, not denied, owning nothing, never drained.
	ErrUnknownNode = errors.New("cluster: unknown node")
	// ErrNodeStillServing refuses to delete a live node that still owns
	// sandboxes unless the caller forces it: drain it first.
	ErrNodeStillServing = errors.New("cluster: node is alive and still owns sandboxes; drain it first or force the delete")
)

// NodeDeleteResult is the answer to a node delete.
type NodeDeleteResult struct {
	NodeID string `json:"node_id"`
	Role   string `json:"role,omitempty"`
	// RaftRemoved: the node was a Raft server and left the configuration
	// (RemoveMember). Denied: a deny record now refuses the ID.
	RaftRemoved bool `json:"raft_removed,omitempty"`
	Denied      bool `json:"denied,omitempty"`
	// AlreadyDeleted: a deny record already existed, so this call only
	// finished whatever an earlier one left undone.
	AlreadyDeleted bool `json:"already_deleted,omitempty"`
	Reassigned     int  `json:"reassigned"`
	Orphaned       int  `json:"orphaned"`
}

// NodeDetail answers GET /v1/cluster/nodes/{id}: the member record plus the
// counts `aerolvm drain` waits on, so it never pages the sandbox index.
type NodeDetail struct {
	Member
	Drained bool              `json:"drained,omitempty"`
	Zone    string            `json:"zone,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	// SandboxesOwned is the FSM's count of placements the node owns.
	SandboxesOwned int `json:"sandboxes_owned"`
	// SandboxesRunning is the node's last capacity heartbeat: admitted
	// sandboxes, not counting warm-pool slots. Without a fresh heartbeat
	// RunningKnown is false and it falls back to SandboxesOwned, the most
	// that could be running.
	SandboxesRunning int  `json:"sandboxes_running"`
	RunningKnown     bool `json:"running_known"`
	// SandboxIDs lists owned sandboxes, in ID order, up to the read's limit.
	SandboxIDs []string `json:"sandbox_ids,omitempty"`
}

// NodeDeleter and NodeDetailer are implemented by Cluster and Agent. Like
// DrainedNodesReader they are deliberately NOT part of Client: Noop has no
// other nodes, and no test double should grow methods it never exercises.
type NodeDeleter interface {
	DeleteNode(ctx context.Context, nodeID string, force bool) (NodeDeleteResult, error)
}

type NodeDetailer interface {
	NodeDetail(ctx context.Context, nodeID string, sandboxIDLimit int) (NodeDetail, error)
}

// DeniedNodeChecker reports deleted node IDs from local state.
type DeniedNodeChecker interface {
	IsNodeDenied(nodeID string) bool
}

// IsDeniedPeer reports whether nodeID was deleted, counting the refusal. The
// public API's internal routes ask it before the membership check.
func IsDeniedPeer(c Client, nodeID string) bool {
	checker, ok := c.(DeniedNodeChecker)
	if !ok || !checker.IsNodeDenied(strings.TrimSpace(nodeID)) {
		return false
	}
	denyHits.Add(denyHitPeer, 1)
	return true
}

// DeleteNode removes nodeID from the cluster, whatever its role. A follower
// forwards one hop to the leader.
func (c *Cluster) DeleteNode(ctx context.Context, nodeID string, force bool) (NodeDeleteResult, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeDeleteResult{}, fmt.Errorf("cluster: DeleteNode requires a node id")
	}
	if c.raft == nil || c.raft.raft == nil {
		return NodeDeleteResult{}, fmt.Errorf("cluster: node holds no placement state")
	}
	if c.raft.raft.State() != raft.Leader {
		return c.forwardDeleteNodeToLeader(ctx, nodeID, force)
	}
	return c.deleteNodeLocal(ctx, nodeID, force)
}

func (c *Cluster) deleteNodeLocal(ctx context.Context, nodeID string, force bool) (NodeDeleteResult, error) {
	if _, ok := c.configuredServer(nodeID); ok {
		owned := c.fsm.ownedCount(nodeID)
		if err := c.removeMemberLocal(ctx, nodeID, force); err != nil {
			return NodeDeleteResult{}, err
		}
		role := ""
		if m, ok := c.gossip.memberlistMember(nodeID); ok {
			role = m.Role
		}
		return NodeDeleteResult{NodeID: nodeID, Role: role, RaftRemoved: true, Orphaned: owned}, nil
	}
	member, known := c.gossip.memberlistMember(nodeID)
	denied := c.fsm.isNodeDenied(nodeID)
	owned := c.fsm.ownedCount(nodeID)
	if !known && !denied && owned == 0 && !c.fsm.isNodeDrained(nodeID) {
		return NodeDeleteResult{}, ErrUnknownNode
	}
	if !denied && !force && member.Alive && owned > 0 {
		return NodeDeleteResult{}, fmt.Errorf("%w: %s owns %d", ErrNodeStillServing, nodeID, owned)
	}
	deny, err := c.writeNodeDeny(ctx, nodeID, member.Role)
	if err != nil {
		return NodeDeleteResult{}, err
	}
	if !c.fsm.isNodeDrained(nodeID) {
		if err := c.SetNodeDrainState(ctx, nodeID, true); err != nil {
			return NodeDeleteResult{}, err
		}
	}
	reassigned, orphaned, err := c.evictOwnerPlacements(ctx, nodeID)
	if err != nil {
		return NodeDeleteResult{}, err
	}
	if c.deadOwners != nil {
		c.deadOwners.clear(nodeID)
	}
	c.invalidatePeerClient(nodeID)
	c.gossip.applyDenySet()
	c.logger.Info("cluster: deleted node", "node_id", nodeID, "role", deny.Record.Role,
		"already_deleted", !deny.Changed, "reassigned", reassigned, "orphaned", orphaned, "force", force)
	return NodeDeleteResult{
		NodeID: nodeID, Role: deny.Record.Role, Denied: true, AlreadyDeleted: !deny.Changed,
		Reassigned: reassigned, Orphaned: orphaned,
	}, nil
}

func (c *Cluster) forwardDeleteNodeToLeader(ctx context.Context, nodeID string, force bool) (NodeDeleteResult, error) {
	leader := c.Leader()
	if leader == "" {
		return NodeDeleteResult{}, ErrNotLeader
	}
	if c.currentInternalClient() == nil || c.gossip == nil {
		return NodeDeleteResult{}, ErrPeerInternalURLRequired
	}
	peerInternal := c.gossip.peerInternalURL(leader)
	if peerInternal == "" {
		return NodeDeleteResult{}, ErrPeerInternalURLRequired
	}
	var out NodeDeleteResult
	err := c.doNodeLifecycleJSON(ctx, c.ClientForPeer(leader), strings.TrimRight(peerInternal, "/")+nodeDeletePath(nodeID, force), http.MethodDelete, &out)
	return out, err
}

func nodeDeletePath(nodeID string, force bool) string {
	path := PublicNodesPath + url.PathEscape(nodeID)
	if force {
		path += "?force=true"
	}
	return path
}

// doNodeLifecycleJSON is one leader hop with this node's PAT over mTLS.
func (c *Cluster) doNodeLifecycleJSON(ctx context.Context, client *http.Client, endpoint, method string, out any) error {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlanePlacementRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, nil)
	if err != nil {
		return fmt.Errorf("cluster: build node request: %w", err)
	}
	SetPeerNodeIDHeader(req, c.nodeID)
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cluster: node request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nodeLifecycleError(resp.StatusCode, string(msg))
	}
	return decodeControlPlaneJSON(resp.Body, out)
}

// nodeLifecycleError restores a node route's sentinel from its status and
// message, so the verdict survives every forwarding hop.
func nodeLifecycleError(status int, message string) error {
	message = strings.TrimSpace(message)
	// The v1 routes answer {"error": "..."}; match on the text inside.
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(message), &body) == nil && body.Error != "" {
		message = body.Error
	}
	for _, sentinel := range []error{ErrUnknownNode, ErrUnknownMember, ErrNodeStillServing, ErrMemberStillAlive, ErrLastVoter, ErrClusterVersion, ErrNotCaughtUp} {
		if strings.Contains(message, sentinel.Error()) {
			return fmt.Errorf("%w (%s)", sentinel, message)
		}
	}
	if status == http.StatusServiceUnavailable {
		return ErrNotLeader
	}
	return statusError{status: status, message: message}
}

// NodeDetail reads one node from this server's gossip view and FSM.
func (c *Cluster) NodeDetail(_ context.Context, nodeID string, sandboxIDLimit int) (NodeDetail, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !c.PlacementViewCaughtUp() {
		// A count from a view still catching up is short of rows the
		// cluster holds, and drain would read it as "empty".
		return NodeDetail{}, ErrNotCaughtUp
	}
	var member Member
	found := false
	for _, m := range c.Members() {
		if m.NodeID == nodeID {
			member, found = m, true
			break
		}
	}
	if !found || nodeID == "" {
		return NodeDetail{}, ErrUnknownNode
	}
	member = AnnotateRaftRoles(c, []Member{member})[0]
	return c.fsm.nodeDetail(member, sandboxIDLimit), nil
}

func (f *placementFSM) nodeDetail(member Member, sandboxIDLimit int) NodeDetail {
	sandboxIDLimit = min(sandboxIDLimit, maxNodeDetailSandboxIDs)
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := NodeDetail{
		Member:  member,
		Drained: f.drainedNodes[member.NodeID],
		Zone:    member.Capacity.Labels[models.PlacementZoneLabel],
		Labels:  member.Capacity.Labels,
	}
	if ids := f.ownerIndex[member.NodeID]; ids != nil {
		out.SandboxesOwned = ids.Len()
		if sandboxIDLimit > 0 {
			ids.Ascend(func(id string) bool {
				out.SandboxIDs = append(out.SandboxIDs, id)
				return len(out.SandboxIDs) < sandboxIDLimit
			})
		}
	}
	out.SandboxesRunning, out.RunningKnown = out.SandboxesOwned, false
	if !member.CapacityStale && hasCapacitySnapshot(member.Capacity) {
		out.SandboxesRunning = max(member.Capacity.SandboxesActive-member.Capacity.ParkedSlots, 0)
		out.RunningKnown = true
	}
	return out
}

// ownedCount is the number of materialized placements nodeID owns: O(1).
func (f *placementFSM) ownedCount(nodeID string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if ids := f.ownerIndex[nodeID]; ids != nil {
		return ids.Len()
	}
	return 0
}

// deniedNodeSet copies the deny set for one placement sweep: one lock for
// the sweep rather than one per candidate.
func (f *placementFSM) deniedNodeSet() map[string]bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.deniedNodes) == 0 {
		return nil
	}
	out := make(map[string]bool, len(f.deniedNodes))
	for id := range f.deniedNodes {
		out[id] = true
	}
	return out
}

// DeleteNode sends the delete to the server tier; any server takes it and
// forwards it to the leader.
func (a *Agent) DeleteNode(ctx context.Context, nodeID string, force bool) (NodeDeleteResult, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeDeleteResult{}, fmt.Errorf("cluster: DeleteNode requires a node id")
	}
	path := nodeDeletePath(nodeID, force)
	var out NodeDeleteResult
	if err := a.doControlPlaneJSON(ctx, http.MethodDelete, path, path, nil, &out); err != nil {
		return NodeDeleteResult{}, agentNodeError(err)
	}
	return out, nil
}

// NodeDetail asks the server tier, which holds the FSM counts.
func (a *Agent) NodeDetail(ctx context.Context, nodeID string, sandboxIDLimit int) (NodeDetail, error) {
	nodeID = strings.TrimSpace(nodeID)
	path := PublicNodesPath + url.PathEscape(nodeID)
	if sandboxIDLimit > 0 {
		path += "?sandboxes=" + strconv.Itoa(sandboxIDLimit)
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out NodeDetail
	if err := a.doControlPlaneJSON(reqCtx, http.MethodGet, path, path, nil, &out); err != nil {
		return NodeDetail{}, agentNodeError(err)
	}
	return out, nil
}

// agentNodeError restores the sentinel a server's refusal carried; the
// agent's transport already restores ErrUnknownMember, ErrMemberStillAlive
// and ErrLastVoter.
func agentNodeError(err error) error {
	var se statusError
	if errors.As(err, &se) {
		return nodeLifecycleError(se.status, se.message)
	}
	return err
}

// refuseDeniedPeer is the internal listener's deny check on a server.
func (c *Cluster) refuseDeniedPeer(nodeID string) bool {
	if !c.fsm.isNodeDenied(nodeID) {
		return false
	}
	c.denyHits.hit(denyHitPeer, nodeID)
	return true
}

// DeniedNodesSource serves the deny set to workers; only a server holds it.
type DeniedNodesSource interface {
	DeniedNodes(since uint64) (DeniedNodesResponse, bool)
}
