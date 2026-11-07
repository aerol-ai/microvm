package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// The active cluster version and the rollout record in the Raft FSM
// (plans/kubectl-style-cluster-ops.md §6.5, §6.6; CEO D6, D10; eng D6).
//
//	opSetActiveVersion (48) ─► activeVersion       first write, and the
//	                                               no-rollout advance (active_version.go)
//	opRolloutCommand   (49) ─► rollout             one event through decideRollout:
//	                                               a new rollout, stop, resume,
//	                                               finalize (also moves the active
//	                                               version), rollback, progress
//	opRolloutNode      (50) ─► rollout.Nodes[id]   one node's move (nodeMoveAllowed),
//	                                               or a node a join adds
//
// One rollout lives here at a time. Its nodes are written one entry each,
// not as one growing record: 2,000 nodes with a few moves each is about
// 8,000 small entries per rollout.
//
// Every decision reads only the entry and the FSM: times are the
// proposer's StampUnixNano, and a move the tables refuse changes nothing,
// so every replica reaches the same record from the same log.
//
// Rolling upgrade: an older build fails these ops, so the leader proposes
// them only once every Raft server reports rolloutFSMOpsVersion
// (raftServersSupport, never the active version: the active version itself
// is written by op 48). An older snapshot has neither field and restores as
// "no active version, no rollout", which is today's behaviour; an older
// build ignores both fields in a newer snapshot, which is safe because
// nothing is written until every server runs this build.
const (
	opSetActiveVersion opCode = 48 // write the active cluster version (compare-and-set, never lowers it)
	opRolloutCommand   opCode = 49 // one rollout event through decideRollout
	opRolloutNode      opCode = 50 // one node's move inside the rollout
)

// rolloutFSMOpsVersion: opSetActiveVersion, opRolloutCommand, opRolloutNode.
const rolloutFSMOpsVersion = 14

// Rollout tiers, in upgrade order (§6.2).
const (
	rolloutTierServer  = "server"
	rolloutTierIngress = "ingress"
	rolloutTierWorker  = "worker"
)

// ActiveVersion is the cluster version every member has agreed to use
// (§6.5). FV gates new cross-node writes; Release is the build it was
// committed for, for operators.
type ActiveVersion struct {
	FV          int    `json:"fv"`
	Release     string `json:"release,omitempty"`
	RolloutID   string `json:"rollout_id,omitempty"`
	SetUnixNano int64  `json:"set_unix_nano"`
}

// ActiveVersionCommand is opSetActiveVersion: move the active version from
// ExpectFV (0 = never written) to FV. A write whose ExpectFV is not the
// current FV, or that would lower it, changes nothing.
type ActiveVersionCommand struct {
	FV       int    `json:"fv"`
	ExpectFV int    `json:"expect_fv"`
	Release  string `json:"release,omitempty"`
}

// RolloutRecord is the rollout in Raft (§6.6).
type RolloutRecord struct {
	ID              string `json:"id"`
	State           string `json:"state"`
	Direction       string `json:"direction"`
	TargetVersion   string `json:"target_version"`
	PreviousVersion string `json:"previous_version,omitempty"`
	Source          string `json:"source"`
	// Caller is the principal that ran apply. Node steps audit it, taken
	// from here and never from a request.
	Caller           string `json:"caller"`
	Hold             bool   `json:"hold,omitempty"`
	Batch            string `json:"batch"`
	PauseAfter       int    `json:"pause_after,omitempty"`
	Paused           bool   `json:"paused,omitempty"`
	NodeTimeoutNanos int64  `json:"node_timeout_nanos"`
	AllowDowntime    bool   `json:"allow_downtime,omitempty"`
	AllowUnversioned bool   `json:"allow_unversioned,omitempty"`
	// Files maps every release asset of the target, for every CPU type in
	// the rollout, to its SHA-256.
	Files map[string]string `json:"files"`
	// PrevFiles maps the previous version's assets, per CPU type, to their
	// SHA-256, as the nodes reported them at staging (§6.6). A rollback
	// installs these.
	PrevFiles       map[string]string `json:"prev_files,omitempty"`
	CreatedUnixNano int64             `json:"created_unix_nano"`
	UpdatedUnixNano int64             `json:"updated_unix_nano"`
	// StateUnixNano is when the rollout entered its current state.
	StateUnixNano int64  `json:"state_unix_nano,omitempty"`
	Error         string `json:"error,omitempty"`
	// Attempt counts restages and rollbacks; node op IDs carry it, so a
	// retried node step never reuses a finished op.
	Attempt int                           `json:"attempt,omitempty"`
	Nodes   map[string]*RolloutNodeRecord `json:"nodes"`
}

// RolloutNodeRecord is one node's progress.
type RolloutNodeRecord struct {
	NodeID string `json:"node_id"`
	Role   string `json:"role,omitempty"`
	Tier   string `json:"tier"`
	Arch   string `json:"arch,omitempty"`
	State  string `json:"state"`
	// Version is the build the node last reported.
	Version string `json:"version,omitempty"`
	Order   int    `json:"order"`
	Batch   int    `json:"batch,omitempty"`
	Error   string `json:"error,omitempty"`
	// WasCordoned is the node's own cordon mark when the rollout began; the
	// leader puts it back after the node's step (§6.2).
	WasCordoned bool `json:"was_cordoned,omitempty"`
	// Op, Term and DeadlineUnixNano describe the step in flight: the node's
	// operation ID, the leader term that started it, and when the node
	// counts as failed. The dead-owner loop skips a node that is upgrading
	// until DeadlineUnixNano (eng D6, Codex eng finding 2).
	Op               string `json:"op,omitempty"`
	Term             uint64 `json:"term,omitempty"`
	DeadlineUnixNano int64  `json:"deadline_unix_nano,omitempty"`
	// Migrated is true once the node ran its one-way migrations at
	// finalize.
	Migrated        bool   `json:"migrated,omitempty"`
	ManualCommand   string `json:"manual_command,omitempty"`
	UpdatedUnixNano int64  `json:"updated_unix_nano"`
}

// RolloutCommand is opRolloutCommand.
type RolloutCommand struct {
	Event     string `json:"event"`
	RolloutID string `json:"rollout_id,omitempty"`
	// New is apply's rollout (its ID, target, nodes, ...).
	New *RolloutRecord `json:"new,omitempty"`
	// Target is apply's target version.
	Target string `json:"target,omitempty"`
	Error  string `json:"error,omitempty"`
	// Active is finalize's new active version.
	Active *ActiveVersion `json:"active,omitempty"`
}

// RolloutNodeUpdate is opRolloutNode.
type RolloutNodeUpdate struct {
	RolloutID string `json:"rollout_id"`
	NodeID    string `json:"node_id"`
	State     string `json:"state,omitempty"`
	// ExpectState makes the move a compare-and-set: it applies only while
	// the node is in this state. Empty applies from any state the table
	// allows.
	ExpectState      string            `json:"expect_state,omitempty"`
	Version          string            `json:"version,omitempty"`
	Arch             string            `json:"arch,omitempty"`
	Error            string            `json:"error,omitempty"`
	ClearError       bool              `json:"clear_error,omitempty"`
	Op               string            `json:"op,omitempty"`
	Term             uint64            `json:"term,omitempty"`
	DeadlineUnixNano int64             `json:"deadline_unix_nano,omitempty"`
	Migrated         bool              `json:"migrated,omitempty"`
	ManualCommand    string            `json:"manual_command,omitempty"`
	PrevFiles        map[string]string `json:"prev_files,omitempty"`
	// Add puts a node into the rollout (a join during the rollout, §6.5).
	Add *RolloutNodeRecord `json:"add,omitempty"`
	// Pause, on a node update, records that the one --pause-after pause
	// happened.
	Pause bool `json:"pause,omitempty"`
}

// rolloutApplyResult is the leader FSM's answer to a rollout entry.
type rolloutApplyResult struct {
	Verdict rolloutVerdict
	Rollout *RolloutRecord
	Changed bool
}

// activeVersionApplyResult answers opSetActiveVersion.
type activeVersionApplyResult struct {
	Active  ActiveVersion
	Changed bool
}

// errRolloutOpNotForwardable refuses rollout ops on the generic
// leader-forward apply path (ApplyEncoded): only the leader's rollout code
// proposes them, after its checks.
var errRolloutOpNotForwardable = errors.New("cluster: rollout state is written only by the leader's rollout code")

func isRolloutOp(op opCode) bool {
	return op == opSetActiveVersion || op == opRolloutCommand || op == opRolloutNode
}

func cloneRollout(r *RolloutRecord) *RolloutRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.Files = cloneStringMap(r.Files)
	out.PrevFiles = cloneStringMap(r.PrevFiles)
	out.Nodes = make(map[string]*RolloutNodeRecord, len(r.Nodes))
	for id, n := range r.Nodes {
		if n == nil {
			continue
		}
		cp := *n
		out.Nodes[id] = &cp
	}
	return &out
}

func (f *placementFSM) applySetActiveVersionLocked(cmd command) (any, error) {
	in := cmd.ActiveVersion
	if in == nil || in.FV <= 0 {
		return nil, fmt.Errorf("placementFSM: opSetActiveVersion requires a positive fv")
	}
	cur := f.activeVersion
	curFV := 0
	if cur != nil {
		curFV = cur.FV
	}
	if in.ExpectFV != curFV || in.FV < curFV {
		return activeVersionApplyResult{Active: derefActive(cur)}, nil
	}
	if cur != nil && in.FV == curFV && in.Release == cur.Release {
		return activeVersionApplyResult{Active: *cur}, nil
	}
	next := ActiveVersion{FV: in.FV, Release: strings.TrimSpace(in.Release), SetUnixNano: cmd.StampUnixNano}
	f.activeVersion = &next
	f.publishActiveLocked()
	return activeVersionApplyResult{Active: next, Changed: true}, nil
}

func derefActive(a *ActiveVersion) ActiveVersion {
	if a == nil {
		return ActiveVersion{}
	}
	return *a
}

// publishActiveLocked swaps in the active FV for the lock-free readers (the
// write gates, voter auto-join, placement). Caller holds f.mu.
func (f *placementFSM) publishActiveLocked() {
	fv := int64(0)
	if f.activeVersion != nil {
		fv = int64(f.activeVersion.FV)
	}
	f.activeFV.Store(fv)
}

// activeFVValue is the active FV, 0 while it was never written.
func (f *placementFSM) activeFVValue() int {
	if f == nil {
		return 0
	}
	return int(f.activeFV.Load())
}

func (f *placementFSM) activeVersionView() (ActiveVersion, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.activeVersion == nil {
		return ActiveVersion{}, false
	}
	return *f.activeVersion, true
}

func (f *placementFSM) applyRolloutCommandLocked(cmd command) (any, error) {
	in := cmd.RolloutCmd
	if in == nil || strings.TrimSpace(in.Event) == "" {
		return nil, fmt.Errorf("placementFSM: opRolloutCommand requires an event")
	}
	cur := f.rollout
	if in.Event != evApply && (cur == nil || cur.ID != in.RolloutID) {
		// A command for a rollout that was replaced (or never existed):
		// refused, nothing changes.
		return rolloutApplyResult{Verdict: refusedIn(stateOf(cur), "the rollout changed; read it again", ""), Rollout: cloneRollout(cur)}, nil
	}
	target := in.Target
	if in.Event == evApply && in.New != nil {
		target = in.New.TargetVersion
	}
	v := decideRollout(cur, rolloutEvent{Kind: in.Event, Target: target})
	stamp := cmd.StampUnixNano
	switch v.Outcome {
	case outcomeRefused, outcomeExisting, outcomeNoop:
		return rolloutApplyResult{Verdict: v, Rollout: cloneRollout(cur)}, nil
	case outcomeNew:
		if in.New == nil || strings.TrimSpace(in.New.ID) == "" {
			return nil, fmt.Errorf("placementFSM: a new rollout needs its record")
		}
		next := cloneRollout(in.New)
		next.State = upgradewire.StateStaging
		next.Direction = upgradewire.DirectionUpgrade
		next.CreatedUnixNano, next.UpdatedUnixNano, next.StateUnixNano = stamp, stamp, stamp
		next.Error = ""
		for _, n := range next.Nodes {
			n.UpdatedUnixNano = stamp
		}
		// The leader built the node list before this entry; a delete that
		// landed in between must not put the node back.
		next.dropDeleted(f.isDeniedLocked)
		f.rollout = next
	case outcomeRestage:
		next := cloneRollout(cur)
		next.State = upgradewire.StateStaging
		next.Error = ""
		next.Attempt++
		next.UpdatedUnixNano, next.StateUnixNano = stamp, stamp
		for _, n := range next.Nodes {
			if n.State == upgradewire.NodeDone {
				continue
			}
			resetNode(n, stamp)
		}
		f.rollout = next
	case outcomeMove:
		next := cloneRollout(cur)
		if next.State != v.To {
			next.StateUnixNano = stamp
		}
		next.State = v.To
		next.UpdatedUnixNano = stamp
		if in.Error != "" {
			next.Error = in.Error
		}
		switch in.Event {
		case evRollback:
			next.Direction = upgradewire.DirectionRollback
			next.Error = ""
			next.Attempt++
			for _, n := range next.Nodes {
				if n.State == upgradewire.NodeSkipped {
					continue
				}
				resetNode(n, stamp)
			}
		case evPause:
			next.Paused = true
		case evResume, evStop:
			next.Error = in.Error
		case evFinalize:
			if in.Active != nil && in.Active.FV > 0 {
				curFV := f.activeFVValue()
				if in.Active.FV >= curFV {
					a := *in.Active
					a.RolloutID = next.ID
					a.SetUnixNano = stamp
					f.activeVersion = &a
					f.publishActiveLocked()
				}
			}
		}
		f.rollout = next
	}
	f.rolloutVersion++
	return rolloutApplyResult{Verdict: v, Rollout: cloneRollout(f.rollout), Changed: true}, nil
}

// resetNode puts a node back to pending for another pass (a restage or a
// rollback). Its cordon mark at the start and its order stay.
func resetNode(n *RolloutNodeRecord, stamp int64) {
	n.State = upgradewire.NodePending
	n.Error = ""
	n.Op = ""
	n.Term = 0
	n.DeadlineUnixNano = 0
	n.ManualCommand = ""
	n.UpdatedUnixNano = stamp
}

func stateOf(r *RolloutRecord) string {
	if r == nil {
		return stateNone
	}
	return r.State
}

func (f *placementFSM) applyRolloutNodeLocked(cmd command) (any, error) {
	in := cmd.RolloutNode
	if in == nil || strings.TrimSpace(in.RolloutID) == "" || strings.TrimSpace(in.NodeID) == "" {
		return nil, fmt.Errorf("placementFSM: opRolloutNode requires a rollout id and a node id")
	}
	cur := f.rollout
	if cur == nil || cur.ID != in.RolloutID {
		return rolloutApplyResult{Verdict: refusedIn(stateOf(cur), "the rollout changed", ""), Rollout: cloneRollout(cur)}, nil
	}
	stamp := cmd.StampUnixNano
	next := cloneRollout(cur)
	n, ok := next.Nodes[in.NodeID]
	switch {
	case in.Add != nil:
		if ok {
			return rolloutApplyResult{Verdict: rolloutVerdict{Outcome: outcomeNoop}, Rollout: cloneRollout(cur)}, nil
		}
		if f.isDeniedLocked(in.NodeID) {
			return rolloutApplyResult{Verdict: refusedIn(next.State, fmt.Sprintf("node %s was deleted", in.NodeID), ""), Rollout: cloneRollout(cur)}, nil
		}
		add := *in.Add
		add.NodeID = in.NodeID
		add.UpdatedUnixNano = stamp
		if add.State == "" {
			add.State = upgradewire.NodePending
		}
		next.Nodes[in.NodeID] = &add
	case !ok:
		return rolloutApplyResult{Verdict: refusedIn(next.State, fmt.Sprintf("node %s is not in the rollout", in.NodeID), ""), Rollout: cloneRollout(cur)}, nil
	default:
		if in.ExpectState != "" && n.State != in.ExpectState {
			return rolloutApplyResult{Verdict: refusedIn(next.State, fmt.Sprintf("node %s is %s, not %s", in.NodeID, n.State, in.ExpectState), ""), Rollout: cloneRollout(cur)}, nil
		}
		if in.State != "" {
			if !nodeMoveAllowed(next.State, n.State, in.State) {
				return rolloutApplyResult{Verdict: refusedIn(next.State, fmt.Sprintf("node %s cannot move from %s to %s while the rollout is %s", in.NodeID, n.State, in.State, next.State), ""), Rollout: cloneRollout(cur)}, nil
			}
			n.State = in.State
		}
		if in.Version != "" {
			n.Version = in.Version
		}
		if in.Arch != "" {
			n.Arch = in.Arch
		}
		if in.ClearError {
			n.Error = ""
		}
		if in.Error != "" {
			n.Error = in.Error
		}
		if in.Op != "" {
			n.Op = in.Op
		}
		if in.Term != 0 {
			n.Term = in.Term
		}
		if in.DeadlineUnixNano != 0 {
			n.DeadlineUnixNano = in.DeadlineUnixNano
		}
		if in.State != "" && in.State != upgradewire.NodeUpgrading {
			n.DeadlineUnixNano = 0
		}
		if in.Migrated {
			n.Migrated = true
		}
		if in.ManualCommand != "" {
			n.ManualCommand = in.ManualCommand
		}
		n.UpdatedUnixNano = stamp
	}
	if len(in.PrevFiles) > 0 {
		if next.PrevFiles == nil {
			next.PrevFiles = make(map[string]string, len(in.PrevFiles))
		}
		for k, v := range in.PrevFiles {
			// The first report per asset wins: every node on the previous
			// version runs the same file, and a later report from a node
			// that was already upgraded must not replace it.
			if _, have := next.PrevFiles[k]; !have {
				next.PrevFiles[k] = v
			}
		}
	}
	if in.Pause {
		next.Paused = true
	}
	next.UpdatedUnixNano = stamp
	f.rollout = next
	f.rolloutVersion++
	return rolloutApplyResult{Verdict: rolloutVerdict{Outcome: outcomeMove}, Rollout: cloneRollout(next), Changed: true}, nil
}

// isDeniedLocked reports whether nodeID has a deny record. Caller holds f.mu.
func (f *placementFSM) isDeniedLocked(nodeID string) bool {
	_, ok := f.deniedNodes[nodeID]
	return ok
}

// dropDeletedFromRolloutLocked is opDenyNode's part in the rollout: the
// deleted node leaves the record in the same entry, so every replica drops
// it at the same log index. Caller holds f.mu.
func (f *placementFSM) dropDeletedFromRolloutLocked(nodeID string, stamp int64) {
	if f.rollout == nil || f.rollout.Nodes[nodeID] == nil {
		return
	}
	next := cloneRollout(f.rollout)
	next.dropDeleted(func(id string) bool { return id == nodeID })
	next.UpdatedUnixNano = stamp
	f.rollout = next
	f.rolloutVersion++
}

// rolloutView returns a copy of the rollout and the active version.
func (f *placementFSM) rolloutView() (*RolloutRecord, ActiveVersion) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return cloneRollout(f.rollout), derefActive(f.activeVersion)
}

// upgradingDeadline reports whether nodeID is upgrading in the current
// rollout and, if so, until when. The dead-owner loop asks it.
func (f *placementFSM) upgradingDeadline(nodeID string) (time.Time, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.rollout == nil {
		return time.Time{}, false
	}
	n, ok := f.rollout.Nodes[nodeID]
	if !ok || n == nil || n.State != upgradewire.NodeUpgrading || n.DeadlineUnixNano == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, n.DeadlineUnixNano), true
}

// rolloutSnapshotLocked and restoreRolloutLocked carry both records through
// a snapshot.
func (f *placementFSM) rolloutSnapshotLocked() (*ActiveVersion, *RolloutRecord) {
	var a *ActiveVersion
	if f.activeVersion != nil {
		cp := *f.activeVersion
		a = &cp
	}
	return a, cloneRollout(f.rollout)
}

func (f *placementFSM) restoreRolloutLocked(a *ActiveVersion, r *RolloutRecord) {
	f.activeVersion = nil
	if a != nil && a.FV > 0 {
		cp := *a
		f.activeVersion = &cp
	}
	f.rollout = nil
	if r != nil && strings.TrimSpace(r.ID) != "" {
		f.rollout = cloneRollout(r)
		if f.rollout.Nodes == nil {
			f.rollout.Nodes = map[string]*RolloutNodeRecord{}
		}
	}
	f.publishActiveLocked()
}

// RolloutAPIView renders a record as the API answers it.
func RolloutAPIView(r *RolloutRecord, active ActiveVersion) *upgradewire.Rollout {
	if r == nil {
		return nil
	}
	out := &upgradewire.Rollout{
		ID: r.ID, State: r.State, Direction: r.Direction, TargetVersion: r.TargetVersion,
		PreviousVersion: r.PreviousVersion, Source: r.Source, Caller: r.Caller, Hold: r.Hold,
		Batch: r.Batch, PauseAfter: r.PauseAfter, NodeTimeout: time.Duration(r.NodeTimeoutNanos).String(),
		AllowDowntime: r.AllowDowntime, CreatedAt: time.Unix(0, r.CreatedUnixNano).UTC(),
		UpdatedAt: time.Unix(0, r.UpdatedUnixNano).UTC(), Error: r.Error,
		ActiveVersion: active.Release, ActiveFSMOpsVersion: active.FV,
		Nodes: []upgradewire.RolloutNode{},
	}
	for _, n := range r.sortedNodes() {
		out.Nodes = append(out.Nodes, upgradewire.RolloutNode{
			NodeID: n.NodeID, Role: n.Role, Arch: n.Arch, State: n.State, Version: n.Version,
			Order: n.Order, Batch: n.Batch, Error: n.Error, ManualCommand: n.ManualCommand, Migrated: n.Migrated,
			UpdatedAt: time.Unix(0, n.UpdatedUnixNano).UTC(),
		})
	}
	return out
}

// rolloutFileSet lists the hashes the rollout uses (target and previous),
// for the file store's prune.
func rolloutFileSet(r *RolloutRecord) map[string]bool {
	keep := map[string]bool{}
	if r == nil {
		return keep
	}
	for _, sum := range r.Files {
		keep[sum] = true
	}
	for _, sum := range r.PrevFiles {
		keep[sum] = true
	}
	return keep
}

// rolloutTerminal reports whether a rollout no longer holds files or blocks
// a new one: finalized or rolled back.
func rolloutTerminal(r *RolloutRecord) bool {
	return r == nil || r.State == upgradewire.StateFinalized || r.State == upgradewire.StateRolledBack
}

// sortedKeys returns m's keys, sorted.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
