package cluster

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// The rollout state machine (plans/kubectl-style-cluster-ops.md §6.6).
//
// Every move of a rollout, and every move of one node inside it, is decided
// here and only here, by data tables copied from the two tables in §6.6:
//
//	rolloutStateTable    progress events the leader reports (all staged, a
//	                     node failed, every node done, ...)
//	rolloutCommandTable  the operator's commands (apply, stop, resume,
//	                     finalize, rollback) and what each state answers
//	nodeStateTable       one node's moves (pending -> staged -> upgrading -> ...)
//
// decideRollout and nodeMoveAllowed are pure: they read the record and the
// event and return a verdict. The leader asks them before it proposes (so
// the API can answer a refusal without a Raft write), and the FSM asks them
// again when it applies the entry, so every replica reaches the same state
// from the same log however the leader's view raced.

// Rollout events. The first five are operator commands; the rest are
// progress the leader reports.
const (
	evApply           = "apply"
	evStop            = "stop"
	evResume          = "resume"
	evFinalize        = "finalize"
	evRollback        = "rollback"
	evAllStaged       = "all_staged"
	evStageFailed     = "stage_failed"
	evPause           = "pause"
	evAllDone         = "all_done"
	evNodeFailed      = "node_failed"
	evMigrated        = "migrated"
	evMigrationFailed = "migration_failed"
	evRolledBack      = "rolled_back"
)

// Outcomes of a decision.
const (
	// outcomeMove changes the rollout's state to verdict.To.
	outcomeMove = "move"
	// outcomeNew replaces the record with a new rollout (201 on apply).
	outcomeNew = "new"
	// outcomeRestage sends a failed or stopped rollout back to staging with
	// the same target: the same record, its unfinished nodes pending again.
	outcomeRestage = "restage"
	// outcomeExisting answers apply with the current rollout, unchanged
	// (200).
	outcomeExisting = "existing"
	// outcomeNoop is a repeat of a command that already took effect: success,
	// nothing written.
	outcomeNoop = "noop"
	// outcomeRefused is a command the state does not allow.
	outcomeRefused = "refused"
)

// rolloutEvent is one input to decideRollout.
type rolloutEvent struct {
	Kind string
	// Target is apply's target version.
	Target string
}

// rolloutVerdict is decideRollout's answer.
type rolloutVerdict struct {
	Outcome string
	// To is the state after the event (outcomeMove, outcomeRestage).
	To string
	// Direction is the direction after the event, when it changes
	// (rollback).
	Direction string
	// Code, Reason and Hint explain a refusal (upgradewire error codes).
	Code   string
	Reason string
	Hint   string
	// Nodes names the nodes a refusal is about.
	Nodes []string
}

// rolloutStateRow is one row of §6.6's "every move between states" table.
type rolloutStateRow struct {
	From  string
	Event string
	To    string
}

// rolloutStateTable is §6.6's state table, progress rows. The command rows
// of that table (apply, stop, resume, finalize, rollback) live in
// rolloutCommandTable, which also says what a repeat answers.
var rolloutStateTable = []rolloutStateRow{
	{From: upgradewire.StateStaging, Event: evAllStaged, To: upgradewire.StateRunning},
	{From: upgradewire.StateStaging, Event: evStageFailed, To: upgradewire.StateFailed},
	{From: upgradewire.StateRunning, Event: evPause, To: upgradewire.StatePaused},
	{From: upgradewire.StateRunning, Event: evAllDone, To: upgradewire.StateDone},
	{From: upgradewire.StateRunning, Event: evNodeFailed, To: upgradewire.StateFailed},
	{From: upgradewire.StateFinalizing, Event: evMigrated, To: upgradewire.StateFinalized},
	// A node whose one-way migration fails stays cordoned and failed in
	// status; the rollout stays finalizing until it is fixed and reports.
	{From: upgradewire.StateFinalizing, Event: evMigrationFailed, To: upgradewire.StateFinalizing},
	{From: upgradewire.StateRollingBack, Event: evRolledBack, To: upgradewire.StateRolledBack},
	{From: upgradewire.StateRollingBack, Event: evNodeFailed, To: upgradewire.StateFailed},
}

// Command kinds of rolloutCommandTable. apply splits by whether the target
// is the current rollout's.
const (
	cmdApplySame  = "apply same target"
	cmdApplyOther = "apply other target"
)

// rolloutCommandRow is one row of §6.6's command table: the command, the
// states it is allowed in, and the outcome there.
type rolloutCommandRow struct {
	Cmd     string
	States  []string
	Outcome string
	// To is the state after a move.
	To string
	// Hint is printed with a refusal.
	Hint string
}

// stateNone stands for "no rollout" in rolloutCommandTable.
const stateNone = ""

// rolloutCommandTable is §6.6's command table. A command in a state no row
// names is refused with rollout_conflict.
var rolloutCommandTable = []rolloutCommandRow{
	{Cmd: cmdApplySame, States: []string{upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StatePaused, upgradewire.StateDone}, Outcome: outcomeExisting},
	{Cmd: cmdApplySame, States: []string{upgradewire.StateFailed, upgradewire.StateStopped}, Outcome: outcomeRestage, To: upgradewire.StateStaging},
	{Cmd: cmdApplySame, States: []string{upgradewire.StateFinalizing, upgradewire.StateFinalized}, Outcome: outcomeNoop},
	{Cmd: cmdApplySame, States: []string{upgradewire.StateRollingBack}, Outcome: outcomeRefused, Hint: "wait for the rollback to end (aerolvm upgrade status)"},
	{Cmd: cmdApplySame, States: []string{upgradewire.StateRolledBack}, Outcome: outcomeNew, To: upgradewire.StateStaging},
	{Cmd: cmdApplyOther, States: []string{upgradewire.StateFinalized, upgradewire.StateRolledBack, stateNone}, Outcome: outcomeNew, To: upgradewire.StateStaging},
	{Cmd: evStop, States: []string{upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StatePaused}, Outcome: outcomeMove, To: upgradewire.StateStopped},
	{Cmd: evStop, States: []string{upgradewire.StateStopped}, Outcome: outcomeNoop},
	{Cmd: evResume, States: []string{upgradewire.StatePaused}, Outcome: outcomeMove, To: upgradewire.StateRunning},
	{Cmd: evResume, States: []string{upgradewire.StateRunning}, Outcome: outcomeNoop},
	{Cmd: evResume, States: []string{upgradewire.StateStopped, upgradewire.StateFailed}, Outcome: outcomeRefused, Hint: "run aerolvm upgrade apply with the same version again"},
	{Cmd: evRollback, States: []string{upgradewire.StateDone, upgradewire.StateFailed, upgradewire.StateStopped, upgradewire.StatePaused}, Outcome: outcomeMove, To: upgradewire.StateRollingBack},
	{Cmd: evRollback, States: []string{upgradewire.StateRollingBack, upgradewire.StateRolledBack}, Outcome: outcomeNoop},
	{Cmd: evFinalize, States: []string{upgradewire.StateDone}, Outcome: outcomeMove, To: upgradewire.StateFinalizing},
	{Cmd: evFinalize, States: []string{upgradewire.StateFinalizing, upgradewire.StateFinalized}, Outcome: outcomeNoop},
}

// isRolloutCommand reports whether kind is an operator command.
func isRolloutCommand(kind string) bool {
	switch kind {
	case evApply, evStop, evResume, evFinalize, evRollback:
		return true
	}
	return false
}

// decideRollout is the one transition function: what ev does to cur (nil
// is no rollout).
func decideRollout(cur *RolloutRecord, ev rolloutEvent) rolloutVerdict {
	state := stateNone
	if cur != nil {
		state = cur.State
	}
	if !isRolloutCommand(ev.Kind) {
		return decideProgress(cur, state, ev)
	}
	cmd := ev.Kind
	if cmd == evApply {
		cmd = cmdApplyOther
		if cur != nil && cur.TargetVersion == strings.TrimSpace(ev.Target) {
			cmd = cmdApplySame
		}
	}
	for _, row := range rolloutCommandTable {
		if row.Cmd != cmd || !containsState(row.States, state) {
			continue
		}
		v := rolloutVerdict{Outcome: row.Outcome, To: row.To}
		switch {
		case row.Outcome == outcomeRefused:
			v.Code = upgradewire.ErrCodeRolloutConflict
			v.Reason = fmt.Sprintf("the rollout is %s", state)
			v.Hint = row.Hint
		case cmd == evRollback && row.Outcome == outcomeMove:
			v.Direction = upgradewire.DirectionRollback
		case cmd == evFinalize && row.Outcome == outcomeMove:
			// Finalize waits for every skipped node (§6.2, CEO D11).
			if skipped := cur.nodesIn(upgradewire.NodeSkipped); len(skipped) > 0 {
				return rolloutVerdict{
					Outcome: outcomeRefused, Code: upgradewire.ErrCodeSkippedNodes,
					Reason: "nodes were down during the rollout and are not upgraded yet",
					Hint:   "upgrade each one (it is caught up when it comes back) or delete it with aerolvm delete node",
					Nodes:  skipped,
				}
			}
			if cur.Direction == upgradewire.DirectionRollback {
				return refusedIn(state, "a rolled-back rollout has nothing to finalize", "")
			}
			// A node that joined or came back since done is still being
			// caught up: finalize would commit a version it does not run.
			var behind []string
			for _, n := range cur.sortedNodes() {
				if n.State != upgradewire.NodeDone {
					behind = append(behind, n.NodeID)
				}
			}
			if len(behind) > 0 {
				v := refusedIn(state, "nodes are still being upgraded", "wait for them (aerolvm upgrade status)")
				v.Nodes = behind
				return v
			}
		case cmd == evResume && row.Outcome == outcomeMove && cur.Direction == upgradewire.DirectionRollback:
			return refusedIn(state, "a rollback is not paused", "")
		}
		return v
	}
	v := refusedIn(state, "", "")
	switch cmd {
	case cmdApplyOther:
		v.Reason = fmt.Sprintf("a rollout to %s is %s", cur.TargetVersion, state)
		v.Hint = "finalize it (aerolvm upgrade finalize) or roll it back (aerolvm upgrade rollback) first"
	case evStop:
		v.Reason = fmt.Sprintf("the rollout is %s; only a staging, running or paused rollout stops", state)
	case evResume:
		v.Reason = fmt.Sprintf("the rollout is %s; only a paused rollout resumes", state)
	case evFinalize:
		v.Reason = fmt.Sprintf("the rollout is %s; finalize needs a done rollout", state)
	case evRollback:
		v.Reason = fmt.Sprintf("the rollout is %s; stop it first, or finalize ran and there is no rollback", state)
		if state == upgradewire.StateFinalizing || state == upgradewire.StateFinalized {
			v.Reason = "the rollout is finalized: one-way migrations may have run, so there is no rollback (§6.8)"
		}
	}
	if state == stateNone {
		v.Reason = "there is no rollout"
	}
	return v
}

func refusedIn(state, reason, hint string) rolloutVerdict {
	if reason == "" {
		reason = fmt.Sprintf("the rollout is %s", state)
	}
	return rolloutVerdict{Outcome: outcomeRefused, Code: upgradewire.ErrCodeRolloutConflict, Reason: reason, Hint: hint}
}

// decideProgress applies one row of rolloutStateTable, after checking from
// the record that the event's condition really holds. The FSM runs the same
// check, so a progress entry proposed from a stale view changes nothing.
func decideProgress(cur *RolloutRecord, state string, ev rolloutEvent) rolloutVerdict {
	if cur == nil {
		return refusedIn(state, "there is no rollout", "")
	}
	for _, row := range rolloutStateTable {
		if row.From != state || row.Event != ev.Kind {
			continue
		}
		if why := cur.progressBlocked(ev.Kind); why != "" {
			return refusedIn(state, why, "")
		}
		if row.To == state {
			return rolloutVerdict{Outcome: outcomeNoop, To: state}
		}
		return rolloutVerdict{Outcome: outcomeMove, To: row.To}
	}
	return refusedIn(state, fmt.Sprintf("%s does not apply to a %s rollout", ev.Kind, state), "")
}

// progressBlocked says why a progress event's condition does not hold yet,
// or "".
func (r *RolloutRecord) progressBlocked(kind string) string {
	switch kind {
	case evAllStaged:
		for _, n := range r.sortedNodes() {
			switch n.State {
			case upgradewire.NodeStaged, upgradewire.NodeManual, upgradewire.NodeSkipped, upgradewire.NodeDone:
			default:
				return fmt.Sprintf("node %s is %s, not staged", n.NodeID, n.State)
			}
		}
	case evStageFailed, evNodeFailed:
		if len(r.nodesIn(upgradewire.NodeFailed)) == 0 {
			return "no node failed"
		}
	case evPause:
		if r.PauseAfter <= 0 || r.Paused {
			return "the rollout has no pause left"
		}
		if r.workersDone() < r.PauseAfter {
			return fmt.Sprintf("only %d of %d workers are done", r.workersDone(), r.PauseAfter)
		}
	case evAllDone, evRolledBack:
		for _, n := range r.sortedNodes() {
			if n.State != upgradewire.NodeDone && n.State != upgradewire.NodeSkipped {
				return fmt.Sprintf("node %s is %s", n.NodeID, n.State)
			}
		}
	case evMigrated:
		for _, n := range r.sortedNodes() {
			if !n.Migrated {
				return fmt.Sprintf("node %s has not reported its one-way migrations", n.NodeID)
			}
		}
	}
	return ""
}

func containsState(states []string, s string) bool {
	for _, x := range states {
		if x == s {
			return true
		}
	}
	return false
}

// nodeStateRow is one allowed move of one node (§6.6 "Per-node states").
type nodeStateRow struct {
	From string
	To   []string
}

// nodeStateTable lists, for each node state, where an opRolloutNode may
// move it. The rollout-level events (apply again, rollback) reset nodes
// themselves; this table covers the leader's per-node writes.
//
//	pending   -> staged | manual | skipped | failed | done (already on the target)
//	staged    -> upgrading | manual | skipped | failed | done
//	upgrading -> done | failed | skipped
//	manual    -> done | skipped | pending
//	skipped   -> pending (it came back) | done (upgraded by hand)
//	failed    -> pending (retried)
//	done      -> (none; a rollback resets it)
//	any       -> out of the rollout, when the node is deleted (dropDeleted)
var nodeStateTable = []nodeStateRow{
	{From: upgradewire.NodePending, To: []string{upgradewire.NodeStaged, upgradewire.NodeManual, upgradewire.NodeSkipped, upgradewire.NodeFailed, upgradewire.NodeDone, upgradewire.NodeUpgrading}},
	{From: upgradewire.NodeStaged, To: []string{upgradewire.NodeUpgrading, upgradewire.NodeManual, upgradewire.NodeSkipped, upgradewire.NodeFailed, upgradewire.NodeDone}},
	{From: upgradewire.NodeUpgrading, To: []string{upgradewire.NodeDone, upgradewire.NodeFailed, upgradewire.NodeSkipped}},
	{From: upgradewire.NodeManual, To: []string{upgradewire.NodeDone, upgradewire.NodeSkipped, upgradewire.NodePending}},
	{From: upgradewire.NodeSkipped, To: []string{upgradewire.NodePending, upgradewire.NodeDone}},
	{From: upgradewire.NodeFailed, To: []string{upgradewire.NodePending}},
}

// restartStates are the rollout states that start node restarts: the walk
// runs in them (running, rolling-back, and done while it catches up a node
// that came back). Staging restarts nothing yet, and stop, a pause and a
// failure start no new restart (§6.6). The FSM refuses a move to upgrading
// outside them, and a node refuses an apply step outside them
// (checkUpgradeFence), so a stop that lands while a restart is being
// started stops it; one already launched is followed to its result.
var restartStates = []string{upgradewire.StateRunning, upgradewire.StateRollingBack, upgradewire.StateDone}

func rolloutStartsRestarts(state string) bool { return containsState(restartStates, state) }

// nodeMoveAllowed reports whether one node may move from -> to while the
// rollout is in state. Staying in a state is always allowed (a retried
// write).
func nodeMoveAllowed(state, from, to string) bool {
	if from == to {
		return true
	}
	if to == upgradewire.NodeUpgrading && !rolloutStartsRestarts(state) {
		return false
	}
	for _, row := range nodeStateTable {
		if row.From != from {
			continue
		}
		for _, t := range row.To {
			if t == to {
				return true
			}
		}
	}
	return false
}

// dropDeleted takes deleted nodes out of the rollout, from any state (§5,
// §6.2). A deleted node never reports again, so kept in the record it would
// hold finalize forever as skipped, a node timeout as upgrading, or the
// one-way migrations while finalizing. A machine that joins again under the
// same ID comes back as a new member (adoptMembers). It reports whether a
// node left.
func (r *RolloutRecord) dropDeleted(deleted func(nodeID string) bool) bool {
	if r == nil {
		return false
	}
	dropped := false
	for id := range r.Nodes {
		if deleted(id) {
			delete(r.Nodes, id)
			dropped = true
		}
	}
	return dropped
}

// nodesIn lists the IDs of the nodes in state, sorted.
func (r *RolloutRecord) nodesIn(state string) []string {
	if r == nil {
		return nil
	}
	var out []string
	for id, n := range r.Nodes {
		if n != nil && n.State == state {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// workersDone counts worker-tier nodes done in the upgrade direction: what
// --pause-after counts (§6.7: only workers count).
func (r *RolloutRecord) workersDone() int {
	n := 0
	for _, node := range r.Nodes {
		if node != nil && node.Tier == rolloutTierWorker && node.State == upgradewire.NodeDone {
			n++
		}
	}
	return n
}

// sortedNodes returns the nodes in rollout order (then by ID).
func (r *RolloutRecord) sortedNodes() []*RolloutNodeRecord {
	if r == nil {
		return nil
	}
	out := make([]*RolloutNodeRecord, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		if n != nil {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}
