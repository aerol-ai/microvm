package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// The leader's rollout loop (plans/kubectl-style-cluster-ops.md §6.2,
// §6.6, §6.7; CEO D6, D8, D10, D11; eng D6, D8).
//
// Every tick the leader reads the rollout from its FSM and takes the next
// step. Nothing lives in memory but the calls in flight, so a new leader
// resumes a half-done rollout from the record alone:
//
//	staging      stage every node, servers first (workers copy from them);
//	             a node down now is skipped (cordoned, caught up later);
//	             a node that can't stage fails the rollout before any restart
//	running      servers one at a time (quorum kept; this leader last, after
//	             handing off leadership), then ingress nodes one at a time,
//	             then worker batches; each node cordoned before its restart,
//	             marked upgrading with a deadline (the dead-owner loop skips
//	             it), health-checked, and given back its own cordon mark
//	paused/
//	stopped      finish the nodes in flight, start no new one
//	done         catch up nodes that come back; finalize unless held
//	finalizing   every node runs its one-way migrations
//	rolling-back the same walk in reverse, with the previous version
//
// The driver talks to nodes only through rolloutNodeClient (start a node
// step, read a node's state, hand off leadership) and to the cluster only
// through rolloutHost, so its tests run against fakes.

// rolloutTickEvery is the loop period. A rollout moves at node-restart
// speed; two seconds keeps it responsive without load at 2,000 nodes.
const rolloutTickEvery = 2 * time.Second

// defaultMaxNodeCalls bounds the node calls the leader has in flight
// (stage, apply, finalize) and the status reads of one tick. Staging 2,000
// nodes then never opens 2,000 connections at once (the rest go out on
// later ticks as calls end), and a few dead hosts cannot stall a tick for
// minutes: the reads run side by side, each bounded by statusTimeout.
const defaultMaxNodeCalls = 64

// statusTimeout bounds one read of a node's upgrade state.
const statusTimeout = 10 * time.Second

// rolloutNodeClient is the small interface §6.6 names.
type rolloutNodeClient interface {
	Step(ctx context.Context, node Member, req UpgradeStepRequest) (UpgradeStepResponse, error)
	Status(ctx context.Context, node Member, op string) (UpgradeNodeStatus, error)
	TransferLeadership(ctx context.Context, to Member) error
}

// rolloutHost is what the driver reads and writes on the leader.
type rolloutHost interface {
	selfID() string
	isLeader() bool
	term() uint64
	rollout() *RolloutRecord
	// members is the gossip view by node ID, dead members included, with
	// capacity freshness.
	members() map[string]Member
	voters() []string
	isRaftServer(nodeID string) bool
	drained() map[string]bool
	appliedIndex() uint64
	setDrain(ctx context.Context, nodeID string, drained bool) error
	nodeUpdate(ctx context.Context, u RolloutNodeUpdate) (rolloutApplyResult, error)
	event(ctx context.Context, rc RolloutCommand) (rolloutApplyResult, error)
	finalizeTarget(r *RolloutRecord) (ActiveVersion, error)
	// operatorStepsAllowed reports whether every Raft server keeps the
	// rollout node's operator flag (C13).
	operatorStepsAllowed() bool
	now() time.Time
}

type rolloutDriver struct {
	host   rolloutHost
	nodes  rolloutNodeClient
	logger *slog.Logger

	mu       sync.Mutex
	inflight map[string]bool
	wg       sync.WaitGroup
	// inline runs node calls on the tick's goroutine (tests).
	inline bool
	// stepTimeout bounds a stage or finalize call; applyTimeout an apply,
	// which only launches the upgrader.
	stepTimeout  time.Duration
	applyTimeout time.Duration
	// applyResendAfter is how long an upgrading node may show no op before
	// the leader sends its apply again (the old leader died between writing
	// the record and calling).
	applyResendAfter time.Duration
	// abandonAfter is how long an upgrading node whose op is no longer
	// wanted (a stop, a restage or a rollback came in) may show no trace of
	// it before the leader takes it as never started. It outlasts a node's
	// own apply work (materializeTimeout plus launchTimeout), so the node
	// cannot still be about to launch it.
	abandonAfter time.Duration
	// indexSlack is how far a server's applied index may trail the
	// leader's and still count as caught up.
	indexSlack uint64
	// finalizeRetry backs off nodes whose one-way migrations failed, by
	// node ID (under mu). A new leader starts with none: one more try each.
	finalizeRetry map[string]retryWait
	// maxCalls bounds the node calls in flight (stage, apply, finalize)
	// and the status reads of one tick (defaultMaxNodeCalls).
	maxCalls int
}

func newRolloutDriver(host rolloutHost, nodes rolloutNodeClient, logger *slog.Logger) *rolloutDriver {
	return &rolloutDriver{
		host: host, nodes: nodes, logger: logger, inflight: map[string]bool{}, finalizeRetry: map[string]retryWait{},
		stepTimeout: 15 * time.Minute, applyTimeout: time.Minute, applyResendAfter: 30 * time.Second, abandonAfter: 2 * time.Minute,
		indexSlack: 1000,
	}
}

func (d *rolloutDriver) logf(msg string, args ...any) {
	if d.logger != nil {
		d.logger.Info(msg, args...)
	}
}

func (d *rolloutDriver) warnf(msg string, args ...any) {
	if d.logger != nil {
		d.logger.Warn(msg, args...)
	}
}

// claim marks nodeID busy with a call; false when one is in flight, or
// when callLimit calls are (a later tick tries again).
func (d *rolloutDriver) claim(nodeID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inflight[nodeID] || len(d.inflight) >= d.callLimit() {
		return false
	}
	d.inflight[nodeID] = true
	return true
}

func (d *rolloutDriver) callLimit() int {
	if d.maxCalls > 0 {
		return d.maxCalls
	}
	return defaultMaxNodeCalls
}

func (d *rolloutDriver) release(nodeID string) {
	d.mu.Lock()
	delete(d.inflight, nodeID)
	d.mu.Unlock()
}

func (d *rolloutDriver) busy(nodeID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inflight[nodeID]
}

// run starts one node call for nodeID unless one is in flight or every
// call slot is taken.
func (d *rolloutDriver) run(nodeID string, fn func()) {
	if !d.claim(nodeID) {
		return
	}
	d.spawn(nodeID, fn)
}

// spawn runs fn for a node already claimed, then releases the claim.
func (d *rolloutDriver) spawn(nodeID string, fn func()) {
	if d.inline {
		defer d.release(nodeID)
		fn()
		return
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer d.release(nodeID)
		fn()
	}()
}

// targetOf is the version the rollout moves nodes to.
func targetOf(r *RolloutRecord) string {
	if r.Direction == upgradewire.DirectionRollback {
		return r.PreviousVersion
	}
	return r.TargetVersion
}

// filesOf is the file set the rollout installs.
func filesOf(r *RolloutRecord) map[string]string {
	if r.Direction == upgradewire.DirectionRollback {
		return r.PrevFiles
	}
	return r.Files
}

// tick takes the rollout's next step.
func (d *rolloutDriver) tick(ctx context.Context) {
	if !d.host.isLeader() {
		return
	}
	r := d.host.rollout()
	if r == nil {
		return
	}
	members := d.host.members()
	if d.adoptMembers(ctx, r, members) {
		r = d.host.rollout()
		if r == nil {
			return
		}
	}
	switch r.State {
	case upgradewire.StateStaging:
		d.tickStaging(ctx, r, members)
	case upgradewire.StateRunning, upgradewire.StateRollingBack, upgradewire.StateDone:
		d.tickMoving(ctx, r, members)
	case upgradewire.StatePaused, upgradewire.StateStopped, upgradewire.StateFailed:
		// Finish the nodes in flight; start none (§6.6: stop).
		d.watchUpgrading(ctx, r, members)
	case upgradewire.StateFinalizing:
		d.tickFinalizing(ctx, r, members)
	}
}

// adoptMembers puts every live member the rollout does not know into it: a
// node that joined during the rollout (§6.5). One already on the target is
// done; any other is pending and cordoned, so it is caught up before it
// takes work.
func (d *rolloutDriver) adoptMembers(ctx context.Context, r *RolloutRecord, members map[string]Member) bool {
	if rolloutTerminal(r) || r.State == upgradewire.StateFinalizing {
		return false
	}
	maxOrder, maxBatch := 0, 0
	for _, n := range r.Nodes {
		if n.Order > maxOrder {
			maxOrder = n.Order
		}
		if n.Batch > maxBatch {
			maxBatch = n.Batch
		}
	}
	added := false
	for _, id := range sortedMemberIDs(members) {
		m := members[id]
		if _, known := r.Nodes[id]; known || !m.Alive || m.NodeID == "" {
			continue
		}
		maxOrder++
		tier := rolloutTierOf(m, d.host.isRaftServer(id))
		arch := m.Arch
		if arch == "" {
			arch = "amd64"
		}
		n := &RolloutNodeRecord{NodeID: id, Role: m.Role, Tier: tier, Arch: arch, Version: m.Version, Order: maxOrder, State: upgradewire.NodePending}
		if tier == rolloutTierWorker {
			n.Batch = maxBatch + 1
		}
		if m.Version == targetOf(r) {
			n.State = upgradewire.NodeDone
		}
		n.WasCordoned = d.host.drained()[id]
		res, err := d.host.nodeUpdate(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: id, Add: n})
		if err != nil {
			d.warnf("cluster: rollout could not add a new member", "rollout_id", r.ID, "node_id", id, "err", err)
			continue
		}
		if !res.Changed {
			// Refused: deleted since gossip last saw it, or the rollout
			// changed. Nothing to cordon.
			continue
		}
		if n.State == upgradewire.NodePending && !n.WasCordoned {
			_ = d.host.setDrain(ctx, id, true)
		}
		d.logf("cluster: rollout added a member that joined", "rollout_id", r.ID, "node_id", id, "state", n.State, "version", m.Version)
		added = true
	}
	return added
}

// tickStaging stages every node, servers first (§6.7).
func (d *rolloutDriver) tickStaging(ctx context.Context, r *RolloutRecord, members map[string]Member) {
	now := d.host.now()
	// A restage keeps a node that was mid-restart upgrading (resetNode):
	// follow it to its end first. Staging waits for it (evAllStaged).
	d.watchUpgrading(ctx, r, members)
	if r = d.host.rollout(); r == nil || r.State != upgradewire.StateStaging {
		return
	}
	serversPending := false
	for _, n := range r.sortedNodes() {
		if n.State != upgradewire.NodePending {
			continue
		}
		m, ok := members[n.NodeID]
		if !ok || !m.Alive {
			d.skip(ctx, r, n, "down when staging started")
			continue
		}
		if n.Tier == rolloutTierServer {
			serversPending = true
		}
	}
	r = d.host.rollout()
	if r == nil || r.State != upgradewire.StateStaging {
		return
	}
	for _, n := range r.sortedNodes() {
		if n.State != upgradewire.NodePending || (serversPending && n.Tier != rolloutTierServer) {
			continue
		}
		d.stage(ctx, r, n, members[n.NodeID])
	}
	r = d.host.rollout()
	if r == nil || r.State != upgradewire.StateStaging {
		return
	}
	if len(r.nodesIn(upgradewire.NodeFailed)) > 0 {
		d.event(ctx, RolloutCommand{Event: evStageFailed, RolloutID: r.ID, Error: failedSummary(r, "failed to stage")})
		return
	}
	if r.progressBlocked(evAllStaged) == "" {
		d.event(ctx, RolloutCommand{Event: evAllStaged, RolloutID: r.ID})
		return
	}
	// A node that never answers holds staging for one node timeout at
	// most, then fails it: nothing has restarted yet.
	if timeout := time.Duration(r.NodeTimeoutNanos); timeout > 0 && now.Sub(time.Unix(0, r.StateUnixNano)) > timeout {
		for _, id := range r.nodesIn(upgradewire.NodePending) {
			d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: id, State: upgradewire.NodeFailed, ExpectState: upgradewire.NodePending,
				Error: fmt.Sprintf("did not stage within %s", timeout)})
		}
	}
}

// skip marks a down node skipped and cordons it, so it comes back
// cordoned and is caught up before it takes new work (CEO D11).
func (d *rolloutDriver) skip(ctx context.Context, r *RolloutRecord, n *RolloutNodeRecord, why string) {
	if !d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeSkipped, ExpectState: n.State, Error: why}) {
		return
	}
	if !n.WasCordoned {
		if err := d.host.setDrain(ctx, n.NodeID, true); err != nil {
			d.warnf("cluster: rollout could not cordon a skipped node", "node_id", n.NodeID, "err", err)
		}
	}
	d.logf("cluster: rollout skipped a down node", "rollout_id", r.ID, "node_id", n.NodeID, "why", why)
}

// stage starts one node's stage call.
func (d *rolloutDriver) stage(ctx context.Context, r *RolloutRecord, n *RolloutNodeRecord, m Member) {
	req := UpgradeStepRequest{
		RolloutID: r.ID, Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: r.TargetVersion,
		Files: nodeFiles(r.Files, n.Arch), Source: r.Source, Term: d.host.term(), AllowUnversioned: r.AllowUnversioned,
	}
	if n.Tier == rolloutTierServer {
		req.CacheFiles = cloneStringMap(r.Files)
	}
	rollout, node := r.ID, *n
	d.run(n.NodeID, func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.stepTimeout)
		defer cancel()
		resp, err := d.nodes.Step(cctx, m, req)
		d.afterStage(cctx, rollout, node, req, resp, err)
	})
}

func (d *rolloutDriver) afterStage(ctx context.Context, rolloutID string, n RolloutNodeRecord, req UpgradeStepRequest, resp UpgradeStepResponse, err error) {
	switch {
	case err == nil && resp.Version == req.Version:
		d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeDone, ExpectState: upgradewire.NodePending, Version: resp.Version, Arch: resp.Arch, ClearError: true})
	case err == nil:
		d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeStaged, ExpectState: upgradewire.NodePending,
			Version: resp.Version, Arch: resp.Arch, PrevFiles: prevFiles(resp.Installed, resp.Arch, req.Files), ClearError: true})
		d.logf("cluster: rollout node staged", "rollout_id", rolloutID, "node_id", n.NodeID, "fetched", len(resp.Fetched), "bytes", resp.Bytes)
	case stepCode(err) == upgradewire.ErrCodeOperatorDriven && d.host.operatorStepsAllowed():
		// Staged as far as the walk goes: the operator pulls the image and
		// swaps it when the node's turn comes (C13).
		d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeStaged, ExpectState: upgradewire.NodePending,
			Operator: true, ClearError: true})
		d.logf("cluster: rollout node is operator-driven", "rollout_id", rolloutID, "node_id", n.NodeID)
	case stepCode(err) == upgradewire.ErrCodeOperatorDriven:
		d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeManual, ExpectState: upgradewire.NodePending,
			Error: "the operator upgrades this node, but a Raft server is too old to wait for it in order: it is done once it reports the target version"})
	case stepCode(err) == upgradewire.ErrCodeRemoteUpgradeDisabled:
		d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeManual, ExpectState: upgradewire.NodePending,
			ManualCommand: manualCommand(req), Error: "SB_REMOTE_UPGRADE=false: run the command on the node"})
	case stepRetryable(err):
		d.warnf("cluster: rollout stage will retry", "rollout_id", rolloutID, "node_id", n.NodeID, "err", err)
	default:
		d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeFailed, ExpectState: upgradewire.NodePending, Error: err.Error()})
		d.warnf("cluster: rollout node failed to stage", "rollout_id", rolloutID, "node_id", n.NodeID, "err", err)
	}
}

// tickMoving walks the nodes in order (running, rolling-back) and catches
// up returning nodes (also done).
func (d *rolloutDriver) tickMoving(ctx context.Context, r *RolloutRecord, members map[string]Member) {
	if d.watchUpgrading(ctx, r, members) {
		return
	}
	// A failure written just now (a resend refused for quorum) ends the
	// walk for this tick, before anything is cordoned for nothing.
	if r = d.host.rollout(); r == nil || !rolloutStartsRestarts(r.State) {
		return
	}
	target := targetOf(r)
	for _, n := range r.sortedNodes() {
		m, ok := members[n.NodeID]
		switch n.State {
		case upgradewire.NodeSkipped:
			if !ok || !m.Alive {
				continue
			}
			if m.Version == target {
				if d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeDone, ExpectState: upgradewire.NodeSkipped, Version: m.Version, ClearError: true}) {
					d.restoreCordon(ctx, n)
				}
				continue
			}
			d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodePending, ExpectState: upgradewire.NodeSkipped, ClearError: true})
		case upgradewire.NodeManual:
			if ok && m.Alive && m.Version == target {
				d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeDone, ExpectState: upgradewire.NodeManual, Version: m.Version, ClearError: true})
			}
		}
	}
	r = d.host.rollout()
	if r == nil {
		return
	}
	if r.State == upgradewire.StateRunning && r.Direction == upgradewire.DirectionUpgrade && r.progressBlocked(evPause) == "" {
		d.event(ctx, RolloutCommand{Event: evPause, RolloutID: r.ID})
		return
	}
	voters := d.host.voters()
	tiers := []string{rolloutTierServer, rolloutTierIngress, rolloutTierWorker}
	switch {
	case r.Direction == upgradewire.DirectionRollback:
		tiers = []string{rolloutTierWorker, rolloutTierIngress, rolloutTierServer}
	case len(voters) == 1:
		tiers = []string{rolloutTierIngress, rolloutTierWorker, rolloutTierServer}
	}
	for _, tier := range tiers {
		left := remainingIn(r, tier)
		if len(left) == 0 {
			continue
		}
		d.stepTier(ctx, r, tier, left, members, voters)
		return
	}
	switch r.State {
	case upgradewire.StateRunning:
		d.event(ctx, RolloutCommand{Event: evAllDone, RolloutID: r.ID})
	case upgradewire.StateRollingBack:
		d.event(ctx, RolloutCommand{Event: evRolledBack, RolloutID: r.ID})
	case upgradewire.StateDone:
		if !r.Hold && len(r.nodesIn(upgradewire.NodeSkipped)) == 0 && decideRollout(r, rolloutEvent{Kind: evFinalize}).Outcome == outcomeMove {
			a, err := d.host.finalizeTarget(r)
			if err != nil {
				d.warnf("cluster: rollout cannot finalize yet", "rollout_id", r.ID, "err", err)
				return
			}
			d.event(ctx, RolloutCommand{Event: evFinalize, RolloutID: r.ID, Active: &a})
		}
	}
}

// remainingIn lists a tier's nodes that still need a step, in order:
// pending, staged or upgrading (done, skipped, manual and failed are
// settled for the walk).
func remainingIn(r *RolloutRecord, tier string) []*RolloutNodeRecord {
	var out []*RolloutNodeRecord
	for _, n := range r.sortedNodes() {
		if n.Tier != tier {
			continue
		}
		switch n.State {
		case upgradewire.NodePending, upgradewire.NodeStaged, upgradewire.NodeUpgrading:
			out = append(out, n)
		}
	}
	return out
}

// stepTier starts the tier's next group: one server or ingress node, or
// one worker batch. A tier with a node upgrading waits for it.
func (d *rolloutDriver) stepTier(ctx context.Context, r *RolloutRecord, tier string, left []*RolloutNodeRecord, members map[string]Member, voters []string) {
	for _, n := range left {
		if n.State == upgradewire.NodeUpgrading {
			return
		}
	}
	// A node that already runs the version (upgraded by hand, or never
	// upgraded before a rollback) needs no restart.
	target := targetOf(r)
	settled := false
	for _, n := range left {
		if m, ok := members[n.NodeID]; ok && m.Alive && m.Version == target {
			if d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeDone, ExpectState: n.State, Version: m.Version, ClearError: true}) {
				d.restoreCordon(ctx, n)
				settled = true
			}
		}
	}
	if settled {
		return
	}
	var group []*RolloutNodeRecord
	switch tier {
	case rolloutTierWorker:
		batch := left[0].Batch
		for _, n := range left {
			if n.Batch == batch {
				group = append(group, n)
			}
		}
	default:
		group = []*RolloutNodeRecord{left[0]}
		if tier == rolloutTierServer && left[0].NodeID == d.host.selfID() && len(left) > 1 {
			// This leader goes last among the servers (§6.2).
			group = []*RolloutNodeRecord{left[1]}
		}
	}
	if r.Direction == upgradewire.DirectionUpgrade {
		pending := false
		for _, n := range group {
			if n.State == upgradewire.NodePending {
				pending = true
				m, ok := members[n.NodeID]
				if !ok || !m.Alive {
					d.skip(ctx, r, n, "down when its turn came")
					continue
				}
				d.stage(ctx, r, n, m)
			}
		}
		if pending {
			return
		}
	}
	for _, n := range group {
		m, ok := members[n.NodeID]
		if !ok || !m.Alive {
			d.skip(ctx, r, n, "down when its turn came")
			continue
		}
		if !d.mayRestart(ctx, r, n, members, voters) {
			return
		}
		d.startUpgrade(ctx, r, n, m)
	}
}

// mayRestart is the gate every node restart passes, the first apply and a
// resend alike (§6.2). This leader never restarts itself while another
// voter can lead: it hands off leadership instead, and the next leader
// restarts it. A Raft voter restarts only if the voters left up still form
// a majority (quorumRefusal); a refused restart fails the node and the
// rollout, naming why.
func (d *rolloutDriver) mayRestart(ctx context.Context, r *RolloutRecord, n *RolloutNodeRecord, members map[string]Member, voters []string) bool {
	self := d.host.selfID()
	if n.NodeID == self && len(voters) > 1 {
		d.handOff(ctx, r, members, voters)
		return false
	}
	if !containsState(voters, n.NodeID) {
		return true
	}
	nodeWhy, rolloutWhy := quorumRefusal(r, n.NodeID, self, members, voters)
	if nodeWhy == "" {
		return true
	}
	d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeFailed, ExpectState: n.State, Error: nodeWhy})
	d.event(ctx, RolloutCommand{Event: evNodeFailed, RolloutID: r.ID, Error: rolloutWhy})
	return false
}

// quorumRefusal says why restarting voter target now would leave no Raft
// majority, for the node and for the rollout, or "" when it may restart.
// The rule is "voters up after this restart >= majority", checked every
// time. A voter that is down always blocks (§6.2: with three servers and
// one down, nothing restarts). A cluster that cannot keep a majority
// through any restart, one or two voters, restarts only when the rollout
// was applied with allow_downtime (eng D8).
func quorumRefusal(r *RolloutRecord, target, self string, members map[string]Member, voters []string) (node, rollout string) {
	if majorityUp(voters, target, self, members) {
		return "", ""
	}
	if down := quorumBlockers(voters, target, self, members); len(down) > 0 {
		list := strings.Join(down, ", ")
		return fmt.Sprintf("restarting it would leave no Raft majority: servers %s are down", list),
			fmt.Sprintf("servers %s are down; no server restarts without a majority", list)
	}
	if r.AllowDowntime {
		return "", ""
	}
	return fmt.Sprintf("restarting it leaves %d of %d voting servers up, and Raft needs %d; the rollout was applied without allow_downtime",
			votersUpAfter(voters, target, self, members), len(voters), len(voters)/2+1),
		fmt.Sprintf("%d voting servers cannot keep a majority through a restart; roll back, then apply with allow_downtime", len(voters))
}

// quorumBlockers lists the voters other than target that are down.
func quorumBlockers(voters []string, target, self string, members map[string]Member) []string {
	var down []string
	for _, v := range voters {
		if v == target || v == self {
			continue
		}
		if m, ok := members[v]; !ok || !m.Alive {
			down = append(down, v)
		}
	}
	return down
}

// majorityUp reports whether the voters still up while target restarts
// form a majority of all voters.
func majorityUp(voters []string, target, self string, members map[string]Member) bool {
	return votersUpAfter(voters, target, self, members) > len(voters)/2
}

// votersUpAfter counts the voters still up while target restarts.
func votersUpAfter(voters []string, target, self string, members map[string]Member) int {
	up := 0
	for _, v := range voters {
		if v == target {
			continue
		}
		if v == self {
			up++
			continue
		}
		if m, ok := members[v]; ok && m.Alive {
			up++
		}
	}
	return up
}

// handOff moves leadership to a voter that already runs the target, so
// the new leader upgrades this node last (§6.2). The next tick runs there.
func (d *rolloutDriver) handOff(ctx context.Context, r *RolloutRecord, members map[string]Member, voters []string) {
	target := targetOf(r)
	var to *Member
	for _, v := range voters {
		if v == d.host.selfID() {
			continue
		}
		m, ok := members[v]
		if !ok || !m.Alive {
			continue
		}
		if m.Version == target {
			mm := m
			to = &mm
			break
		}
		if to == nil {
			mm := m
			to = &mm
		}
	}
	if to == nil {
		d.warnf("cluster: rollout has no live voter to hand leadership to", "rollout_id", r.ID)
		return
	}
	d.logf("cluster: rollout hands off leadership before upgrading this node", "rollout_id", r.ID, "from", d.host.selfID(), "to", to.NodeID)
	if err := d.nodes.TransferLeadership(ctx, *to); err != nil {
		d.warnf("cluster: rollout leadership hand-off failed; will retry", "rollout_id", r.ID, "to", to.NodeID, "err", err)
	}
}

// rolloutOpID names a node's operation in this pass of the rollout, so a
// retried call or a new leader reuses it, and a later pass never does.
func rolloutOpID(r *RolloutRecord) string {
	dir := "u"
	if r.Direction == upgradewire.DirectionRollback {
		dir = "b"
	}
	return fmt.Sprintf("%s-%s%d", r.ID, dir, r.Attempt)
}

// startUpgrade cordons the node, records it upgrading with a deadline, and
// sends the apply step. It takes a call slot first, so a node is marked
// upgrading only when its call can go out now; with every slot taken it
// waits for a later tick instead of waiting for the resend.
func (d *rolloutDriver) startUpgrade(ctx context.Context, r *RolloutRecord, n *RolloutNodeRecord, m Member) {
	if !d.claim(n.NodeID) {
		return
	}
	sent := false
	defer func() {
		if !sent {
			d.release(n.NodeID)
		}
	}()
	cordoned := false
	if !d.host.drained()[n.NodeID] {
		if err := d.host.setDrain(ctx, n.NodeID, true); err != nil {
			d.warnf("cluster: rollout could not cordon a node before its restart; will retry", "node_id", n.NodeID, "err", err)
			return
		}
		cordoned = true
	}
	timeout := time.Duration(r.NodeTimeoutNanos)
	if timeout <= 0 {
		timeout = upgradewire.DefaultNodeTimeout
	}
	op := rolloutOpID(r)
	if !d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeUpgrading, ExpectState: n.State,
		Op: op, Term: d.host.term(), DeadlineUnixNano: d.host.now().Add(timeout).UnixNano(), ClearError: true}) {
		// Refused: a stop or a rollback landed after this tick read the
		// rollout (rolloutStartsRestarts). No restart follows, so the cordon
		// set just now goes back.
		if cordoned {
			if err := d.host.setDrain(ctx, n.NodeID, false); err != nil {
				d.warnf("cluster: rollout could not uncordon a node whose restart did not start", "node_id", n.NodeID, "err", err)
			}
		}
		return
	}
	if n.Operator {
		// Its turn is marked; the operator sees "upgrading" and swaps the
		// image. watchUpgrading finishes it when the node reports the
		// target, or fails it at the deadline (C13).
		d.logf("cluster: rollout waiting for the operator to upgrade node", "rollout_id", r.ID, "node_id", n.NodeID, "op", op, "to", targetOf(r))
		return
	}
	d.logf("cluster: rollout upgrading node", "rollout_id", r.ID, "node_id", n.NodeID, "op", op, "to", targetOf(r), "caller", r.Caller)
	sent = true
	d.spawn(n.NodeID, d.applyCall(ctx, r, *n, m, op))
}

// sendApply sends the apply step again (a resend), in a call slot of its
// own.
func (d *rolloutDriver) sendApply(ctx context.Context, r *RolloutRecord, n RolloutNodeRecord, m Member, op string) {
	d.run(n.NodeID, d.applyCall(ctx, r, n, m, op))
}

// applyCall is one apply step's call, to run in a claimed slot.
func (d *rolloutDriver) applyCall(ctx context.Context, r *RolloutRecord, n RolloutNodeRecord, m Member, op string) func() {
	timeout := time.Duration(r.NodeTimeoutNanos)
	health := nodeupgrade.DefaultHealthTimeout
	if timeout > 0 && timeout/2 < health {
		health = timeout / 2
	}
	req := UpgradeStepRequest{
		RolloutID: r.ID, Step: UpgradeStepApply, Direction: r.Direction, Version: targetOf(r),
		Files: nodeFiles(filesOf(r), n.Arch), Source: r.Source, Op: op, Term: d.host.term(),
		AllowUnversioned: r.AllowUnversioned, HealthTimeout: health.String(),
	}
	if len(req.Files) == 0 {
		req.Files = nil
	}
	rolloutID := r.ID
	return func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.applyTimeout)
		defer cancel()
		resp, err := d.nodes.Step(cctx, m, req)
		fail := func(why string) {
			// A stop, a restage or a rollback may have landed during the
			// call: then the node keeps upgrading under the record's rules
			// (followUpgrading), and this answer fails nothing.
			if cur := d.host.rollout(); cur == nil || cur.ID != rolloutID || rolloutOpID(cur) != op {
				return
			}
			d.failNode(cctx, rolloutID, n, why)
		}
		switch {
		case err == nil && resp.State == UpgradeNodeFailed:
			fail(resp.Error)
		case err == nil, stepRetryable(err), stepCode(err) == upgradewire.ErrCodeUpgradeRunning, stepCode(err) == upgradeCodeNotInRecord:
			// Started, worth another try, or refused because the record
			// moved on: watchUpgrading follows the node from the record.
		default:
			fail(err.Error())
		}
	}
}

func (d *rolloutDriver) failNode(ctx context.Context, rolloutID string, n RolloutNodeRecord, why string) {
	if d.update(ctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: n.NodeID, State: upgradewire.NodeFailed, ExpectState: upgradewire.NodeUpgrading, Error: why}) {
		d.restoreCordon(ctx, &n)
		d.warnf("cluster: rollout node failed", "rollout_id", rolloutID, "node_id", n.NodeID, "err", why)
	}
}

// watchUpgrading follows every upgrading node: done once healthy on the
// target, failed when its upgrader failed or its deadline passed. It
// reports whether the rollout failed.
func (d *rolloutDriver) watchUpgrading(ctx context.Context, r *RolloutRecord, members map[string]Member) bool {
	now := d.host.now()
	target := targetOf(r)
	var list []*RolloutNodeRecord
	for _, n := range r.sortedNodes() {
		if n.State == upgradewire.NodeUpgrading && !d.busy(n.NodeID) {
			list = append(list, n)
		}
	}
	reads := d.readStatuses(ctx, list, members)
	for i, n := range list {
		if reads[i].err == nil && d.followUpgrading(ctx, r, n, members[n.NodeID], reads[i].st, now) {
			continue
		}
		if n.DeadlineUnixNano > 0 && now.After(time.Unix(0, n.DeadlineUnixNano)) {
			d.failNode(ctx, r.ID, *n, fmt.Sprintf("did not come back healthy on %s within %s (--node-timeout)", target, time.Duration(r.NodeTimeoutNanos)))
		}
	}
	r = d.host.rollout()
	if r == nil || len(r.nodesIn(upgradewire.NodeFailed)) == 0 {
		return false
	}
	if r.State == upgradewire.StateRunning || r.State == upgradewire.StateRollingBack {
		d.event(ctx, RolloutCommand{Event: evNodeFailed, RolloutID: r.ID, Error: failedSummary(r, "failed")})
		return true
	}
	return false
}

// nodeRead is one node's answer to a status read.
type nodeRead struct {
	st  UpgradeNodeStatus
	err error
}

// readStatuses reads the nodes' upgrade state side by side, at most
// callLimit at a time, each bounded by statusTimeout: a tick waits for its
// slowest round, not for every dead host in turn.
func (d *rolloutDriver) readStatuses(ctx context.Context, nodes []*RolloutNodeRecord, members map[string]Member) []nodeRead {
	out := make([]nodeRead, len(nodes))
	slots := make(chan struct{}, d.callLimit())
	var wg sync.WaitGroup
	for i, n := range nodes {
		slots <- struct{}{}
		wg.Add(1)
		go func(i int, m Member, op string) {
			defer wg.Done()
			defer func() { <-slots }()
			sctx, cancel := context.WithTimeout(ctx, statusTimeout)
			defer cancel()
			out[i].st, out[i].err = d.nodes.Status(sctx, m, op)
		}(i, members[n.NodeID], n.Op)
	}
	wg.Wait()
	return out
}

// followUpgrading acts on one upgrading node's own report and says whether
// the node left upgrading.
//
// A node keeps state upgrading, its op and its deadline from the moment the
// leader marks it until it reports a result or the deadline passes, even
// across a stop, a restage or a rollback: until then it may be restarting,
// and only that state keeps the dead-owner loop from failing it over. Its op
// may then be an earlier pass's, or the rollout may start no restart now.
// Such an op is never sent again (the node's fence refuses it too), and once
// it has ended, or plainly never started, the node goes back to pending so
// this pass's walk decides what it still needs.
func (d *rolloutDriver) followUpgrading(ctx context.Context, r *RolloutRecord, n *RolloutNodeRecord, m Member, st UpgradeNodeStatus, now time.Time) bool {
	target := targetOf(r)
	current := n.Op == rolloutOpID(r)
	ended := st.OpFound && !st.OpRunning && (st.OpPhase == string(nodeupgrade.PhaseDone) || st.OpPhase == string(nodeupgrade.PhaseFailed))
	idle := !st.OpFound && !st.OpRunning
	since := now.Sub(time.Unix(0, n.UpdatedUnixNano))
	abandoned := idle && since > d.abandonAfter
	switch {
	case current && st.OpFound && st.OpPhase == string(nodeupgrade.PhaseFailed):
		d.failNode(ctx, r.ID, *n, "the node's upgrader failed and put the previous files back: "+st.OpError)
		return true
	case st.Version == target && d.healthy(n, m, st, target) && (current || ended || abandoned):
		// An earlier pass's op counts only once it has ended: until then the
		// node still answers on the version it is leaving, which is what a
		// rollback goes back to.
		if d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodeDone, ExpectState: upgradewire.NodeUpgrading, Version: st.Version, ClearError: true}) {
			d.restoreCordon(ctx, n)
			recordNodeUpgrade(since.Seconds())
			d.logf("cluster: rollout node done", "rollout_id", r.ID, "node_id", n.NodeID, "version", st.Version)
		}
		return true
	case !current || !rolloutStartsRestarts(r.State):
		if st.Version != target && (ended || abandoned) {
			d.requeue(ctx, r, n)
			return true
		}
	case idle && st.Version != target && since > d.applyResendAfter && !n.Operator:
		// The op never started: the leader that marked the node died before
		// its call, or the call was lost. The node's own state shows no op,
		// so sending it again cannot start a second upgrade. It is a restart
		// all the same, so it passes the same gate as the first call: the
		// voter that is down now may be the leader that marked it.
		if d.mayRestart(ctx, r, n, d.host.members(), d.host.voters()) {
			d.sendApply(ctx, r, *n, m, n.Op)
		}
	}
	return false
}

// requeue sends an upgrading node whose step is over back to pending for
// this pass. While the rollout starts no restart, no restart follows soon,
// so the node also gets its own cordon mark back.
func (d *rolloutDriver) requeue(ctx context.Context, r *RolloutRecord, n *RolloutNodeRecord) {
	if !d.update(ctx, RolloutNodeUpdate{RolloutID: r.ID, NodeID: n.NodeID, State: upgradewire.NodePending, ExpectState: upgradewire.NodeUpgrading, ClearError: true}) {
		return
	}
	if !rolloutStartsRestarts(r.State) {
		d.restoreCordon(ctx, n)
	}
	d.logf("cluster: rollout node back to pending; its earlier step is over", "rollout_id", r.ID, "node_id", n.NodeID, "op", n.Op, "state", r.State)
}

// healthy is §6.2's check: alive in gossip on the target, a server's
// applied index close to the leader's, a worker's capacity heartbeat fresh.
func (d *rolloutDriver) healthy(n *RolloutNodeRecord, m Member, st UpgradeNodeStatus, target string) bool {
	if n.NodeID != d.host.selfID() && (!m.Alive || m.Version != target) {
		return false
	}
	if n.Tier == rolloutTierServer && n.NodeID != d.host.selfID() {
		if st.AppliedIndex+d.indexSlack < d.host.appliedIndex() {
			return false
		}
	}
	if n.Tier == rolloutTierWorker && CanOwnSandboxRole(m.Role) && m.CapacityStale {
		return false
	}
	return true
}

// restoreCordon gives a node back its own cordon mark from the start of
// the rollout (§6.2).
func (d *rolloutDriver) restoreCordon(ctx context.Context, n *RolloutNodeRecord) {
	if n.WasCordoned || !d.host.drained()[n.NodeID] {
		return
	}
	if err := d.host.setDrain(ctx, n.NodeID, false); err != nil {
		d.warnf("cluster: rollout could not uncordon a node; it stays cordoned until uncordoned by hand", "node_id", n.NodeID, "err", err)
	}
}

// migrationFailedPrefix starts the error of a node whose one-way
// migrations failed: the leader cordoned it for that.
const migrationFailedPrefix = "one-way migrations failed: "

// Waits between retries of a node whose one-way migrations failed: they
// double from the first to the last.
const (
	finalizeRetryFirst = 10 * time.Second
	finalizeRetryMax   = 5 * time.Minute
)

// retryWait is one node's backoff: its next try and the wait that set it.
type retryWait struct {
	next time.Time
	wait time.Duration
}

// finalizeDue reports whether nodeID's migrations may run again now.
func (d *rolloutDriver) finalizeDue(nodeID string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	b, ok := d.finalizeRetry[nodeID]
	return !ok || !now.Before(b.next)
}

// finalizeFailed backs nodeID off and returns the wait.
func (d *rolloutDriver) finalizeFailed(nodeID string, now time.Time) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.finalizeRetry[nodeID]
	b.wait = min(max(2*b.wait, finalizeRetryFirst), finalizeRetryMax)
	b.next = now.Add(b.wait)
	d.finalizeRetry[nodeID] = b
	return b.wait
}

func (d *rolloutDriver) finalizeOK(nodeID string) {
	d.mu.Lock()
	delete(d.finalizeRetry, nodeID)
	d.mu.Unlock()
}

// tickFinalizing runs every node's one-way migrations (§6.5, CEO D16).
func (d *rolloutDriver) tickFinalizing(ctx context.Context, r *RolloutRecord, members map[string]Member) {
	now := d.host.now()
	for _, n := range r.sortedNodes() {
		if n.Migrated {
			continue
		}
		m, ok := members[n.NodeID]
		if !ok || !m.Alive || !d.finalizeDue(n.NodeID, now) {
			continue
		}
		req := UpgradeStepRequest{RolloutID: r.ID, Step: UpgradeStepFinalize, Direction: r.Direction, Version: r.TargetVersion, Term: d.host.term()}
		node, rolloutID := *n, r.ID
		d.run(n.NodeID, func() {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.stepTimeout)
			defer cancel()
			_, err := d.nodes.Step(cctx, m, req)
			switch {
			case err == nil:
				d.finalizeOK(node.NodeID)
				if d.update(cctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: node.NodeID, Migrated: true, ClearError: true}) &&
					strings.HasPrefix(node.Error, migrationFailedPrefix) {
					// It failed before and was cordoned for that (below).
					d.restoreCordon(cctx, &node)
				}
			case stepRetryable(err):
			default:
				// The node stays cordoned and shows the error; the rollout
				// stays finalizing until it reports (§6.6). The same failure
				// again writes nothing, and the retries wait longer each
				// time: a broken node must not fill the Raft log.
				wait := d.finalizeFailed(node.NodeID, d.host.now())
				if msg := migrationFailedPrefix + err.Error(); node.Error != msg {
					d.update(cctx, RolloutNodeUpdate{RolloutID: rolloutID, NodeID: node.NodeID, Error: msg})
				}
				if !d.host.drained()[node.NodeID] {
					if err := d.host.setDrain(cctx, node.NodeID, true); err != nil {
						d.warnf("cluster: rollout could not cordon a node whose migrations failed", "node_id", node.NodeID, "err", err)
					}
				}
				d.warnf("cluster: rollout node's one-way migrations failed; will retry", "rollout_id", rolloutID, "node_id", node.NodeID, "in", wait, "err", err)
			}
		})
	}
	r = d.host.rollout()
	if r != nil && r.State == upgradewire.StateFinalizing && r.progressBlocked(evMigrated) == "" {
		d.event(ctx, RolloutCommand{Event: evMigrated, RolloutID: r.ID})
	}
}

// update writes one node move and reports whether it applied.
func (d *rolloutDriver) update(ctx context.Context, u RolloutNodeUpdate) bool {
	res, err := d.host.nodeUpdate(ctx, u)
	if err != nil {
		d.warnf("cluster: rollout node write failed", "rollout_id", u.RolloutID, "node_id", u.NodeID, "state", u.State, "err", err)
		return false
	}
	return res.Changed
}

// event writes one rollout event, when it would change the rollout. The
// transition function answers first, from this leader's record, as it
// answers the FSM: an event it refuses or that changes nothing (all_done
// while a node is manual, migration_failed while finalizing) would be a
// Raft entry every tick that does nothing.
func (d *rolloutDriver) event(ctx context.Context, rc RolloutCommand) {
	cur := d.host.rollout()
	if cur == nil || cur.ID != rc.RolloutID {
		return
	}
	if v := decideRollout(cur, rolloutEvent{Kind: rc.Event}); v.Outcome == outcomeNoop || v.Outcome == outcomeRefused {
		return
	}
	res, err := d.host.event(ctx, rc)
	if err != nil {
		d.warnf("cluster: rollout event failed", "rollout_id", rc.RolloutID, "event", rc.Event, "err", err)
		return
	}
	if res.Changed && res.Rollout != nil {
		d.logf("cluster: rollout moved", "rollout_id", rc.RolloutID, "event", rc.Event, "state", res.Rollout.State, "error", rc.Error)
	}
}

// failedSummary names the failed nodes and their errors.
func failedSummary(r *RolloutRecord, what string) string {
	var parts []string
	for _, id := range r.nodesIn(upgradewire.NodeFailed) {
		parts = append(parts, fmt.Sprintf("%s %s: %s", id, what, r.Nodes[id].Error))
	}
	return strings.Join(parts, "; ")
}

// prevFiles names the binaries a node reported at staging as the previous
// version's assets for its CPU type. Only binaries the target replaces
// count: a rollback puts back what the upgrade changed, and a binary the
// upgrade never touched (Caddy, when the release leaves it out) would only
// make a rollback hunt for a copy it does not need.
func prevFiles(installed map[string]string, arch string, target map[string]string) map[string]string {
	if len(installed) == 0 || arch == "" {
		return nil
	}
	replaced := map[string]bool{}
	for name := range target {
		if m := rolloutAssetRe.FindStringSubmatch(name); m != nil {
			replaced[m[1]] = true
		}
	}
	out := map[string]string{}
	for role, sum := range installed {
		if replaced[role] {
			out[role+"_linux_"+arch] = sum
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// manualCommand is the one command an operator runs on a node with remote
// upgrade off (§6.3, D15).
func manualCommand(req UpgradeStepRequest) string {
	nr := nodeupgrade.Request{Version: req.Version, SHA256: req.Files, AllowUnversioned: req.AllowUnversioned}
	return "sudo sandboxd " + strings.Join(nr.Args(), " ")
}

func stepCode(err error) string {
	var se *UpgradeStepError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

// stepRetryable reports whether a failed call is worth sending again: the
// node was unreachable, busy, catching up, or not (yet) convinced this
// leader leads.
func stepRetryable(err error) bool {
	if err == nil {
		return false
	}
	var se *UpgradeStepError
	if !errors.As(err, &se) {
		return true // transport: the node is restarting or unreachable
	}
	switch se.Code {
	case upgradeCodeRetry, upgradeCodeNotLeader, upgradeCodeStaleTerm, upgradewire.ErrCodeRolloutConflict:
		return true
	}
	return se.Status == http.StatusServiceUnavailable || se.Status == http.StatusTooManyRequests || se.Status == http.StatusBadGateway
}

func sortedMemberIDs(m map[string]Member) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// clusterRolloutHost is rolloutHost on a real Cluster.
type clusterRolloutHost struct{ c *Cluster }

func (h clusterRolloutHost) selfID() string { return h.c.nodeID }
func (h clusterRolloutHost) isLeader() bool { return h.c.IsLeader() }
func (h clusterRolloutHost) term() uint64   { return h.c.raft.raft.CurrentTerm() }
func (h clusterRolloutHost) rollout() *RolloutRecord {
	r, _ := h.c.fsm.rolloutView()
	return r
}
func (h clusterRolloutHost) members() map[string]Member {
	out := map[string]Member{}
	for _, m := range h.c.membersWithCapacity() {
		out[m.NodeID] = m
	}
	return out
}
func (h clusterRolloutHost) voters() []string {
	v, _ := h.c.raftVoters()
	return v
}
func (h clusterRolloutHost) isRaftServer(id string) bool {
	_, ok := h.c.configuredServer(id)
	return ok
}
func (h clusterRolloutHost) drained() map[string]bool { return h.c.fsm.drainedNodesSnapshot() }
func (h clusterRolloutHost) appliedIndex() uint64     { return h.c.fsm.currentVersion() }
func (h clusterRolloutHost) setDrain(ctx context.Context, id string, drained bool) error {
	return h.c.SetNodeDrainState(ctx, id, drained)
}
func (h clusterRolloutHost) nodeUpdate(ctx context.Context, u RolloutNodeUpdate) (rolloutApplyResult, error) {
	return h.c.proposeRolloutNode(ctx, u)
}
func (h clusterRolloutHost) event(ctx context.Context, rc RolloutCommand) (rolloutApplyResult, error) {
	return h.c.proposeRolloutCommand(ctx, rc)
}
func (h clusterRolloutHost) finalizeTarget(r *RolloutRecord) (ActiveVersion, error) {
	return h.c.finalizeTarget(r)
}
func (h clusterRolloutHost) now() time.Time { return time.Now() }
func (h clusterRolloutHost) operatorStepsAllowed() bool {
	return h.c.raftServersRunAtLeast(rolloutOperatorFSMOpsVersion, "operator-driven rollout steps") == nil
}

// clusterNodeClient is rolloutNodeClient over the internal mTLS channel.
// The leader's own steps (one-voter clusters) run in process.
type clusterNodeClient struct{ c *Cluster }

func (n clusterNodeClient) Step(ctx context.Context, m Member, req UpgradeStepRequest) (UpgradeStepResponse, error) {
	if m.NodeID == n.c.nodeID {
		return n.c.upgrade.Step(ctx, n.c.nodeID, req)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return UpgradeStepResponse{}, err
	}
	var out UpgradeStepResponse
	err = n.c.peerJSON(ctx, m, http.MethodPost, PublicNodesPath+url.PathEscape(m.NodeID)+NodeUpgradeStepSuffix, body, &out)
	return out, err
}

func (n clusterNodeClient) Status(ctx context.Context, m Member, op string) (UpgradeNodeStatus, error) {
	if m.NodeID == n.c.nodeID {
		return n.c.upgrade.Status(op), nil
	}
	var out UpgradeNodeStatus
	path := PublicNodesPath + url.PathEscape(m.NodeID) + NodeUpgradeStepSuffix + "?op=" + url.QueryEscape(op)
	err := n.c.peerJSON(ctx, m, http.MethodGet, path, nil, &out)
	return out, err
}

func (n clusterNodeClient) TransferLeadership(ctx context.Context, to Member) error {
	_, err := n.c.TransferLeadership(ctx, to.NodeID)
	return err
}

// peerJSON calls one peer's internal route as this node and decodes a 2xx
// answer into out; a refusal comes back as an UpgradeStepError.
func (c *Cluster) peerJSON(ctx context.Context, m Member, method, path string, body []byte, out any) error {
	if strings.TrimSpace(m.InternalURL) == "" {
		return fmt.Errorf("cluster: node %s has no internal URL", m.NodeID)
	}
	base := c.ClientForPeer(m.NodeID)
	if base == nil {
		return ErrPeerInternalURLRequired
	}
	client := *base
	client.Timeout = 0
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(m.InternalURL, "/")+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	SetPeerNodeIDHeader(req, c.nodeID)
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeUpgradeStepError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// startRolloutLoop runs the driver, the active-version reconcile, the
// gauges and the file prune on one goroutine. Followers run it too: every
// step but the prune and gauges is leader-gated.
func (c *Cluster) startRolloutLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	c.rolloutStop = cancel
	go func() {
		t := time.NewTicker(rolloutTickEvery)
		defer t.Stop()
		// The first active-version check waits one period, so a node that
		// just started has heard from its peers before it judges them.
		lastActive, lastPrune := time.Now(), time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-c.rolloutWake:
			}
			c.driver.tick(ctx)
			now := time.Now()
			if now.Sub(lastActive) >= activeVersionReconcileEvery {
				c.reconcileActiveVersion(ctx)
				lastActive = now
			}
			if now.Sub(lastPrune) >= upgradePruneEvery {
				r, _ := c.fsm.rolloutView()
				pruneUpgradeFiles(c.upgrade.paths, rolloutKeepSet(r), now)
				lastPrune = now
			}
			c.refreshRolloutGauges()
		}
	}()
}

// upgradePruneEvery is how often a node prunes its upgrade file store.
const upgradePruneEvery = 10 * time.Minute

// wakeRollout runs the next tick now (after a command).
func (c *Cluster) wakeRollout() {
	if c == nil || c.rolloutWake == nil {
		return
	}
	select {
	case c.rolloutWake <- struct{}{}:
	default:
	}
}
