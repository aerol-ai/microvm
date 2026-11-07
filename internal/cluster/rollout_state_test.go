package cluster

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Tests for the one rollout transition function (rollout_state.go): every
// row of both §6.6 tables and of the node table, plus the refusals no row
// names.

var allRolloutStates = []string{
	stateNone, upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StatePaused, upgradewire.StateDone,
	upgradewire.StateFailed, upgradewire.StateStopped, upgradewire.StateFinalizing, upgradewire.StateFinalized,
	upgradewire.StateRollingBack, upgradewire.StateRolledBack,
}

// rolloutIn is a two-node rollout to v2 in state, with every progress
// condition true (nodes done, migrated, a failed node only where asked).
func rolloutIn(state string) *RolloutRecord {
	if state == stateNone {
		return nil
	}
	r := &RolloutRecord{
		ID: "r1", State: state, Direction: upgradewire.DirectionUpgrade, TargetVersion: "v2", PreviousVersion: "v1",
		Nodes: map[string]*RolloutNodeRecord{
			"s1": {NodeID: "s1", Tier: rolloutTierServer, State: upgradewire.NodeDone, Order: 1, Migrated: true},
			"w1": {NodeID: "w1", Tier: rolloutTierWorker, State: upgradewire.NodeDone, Order: 2, Batch: 1, Migrated: true},
		},
	}
	if state == upgradewire.StateRollingBack || state == upgradewire.StateRolledBack {
		r.Direction = upgradewire.DirectionRollback
	}
	return r
}

func TestRolloutStateTableEveryRow(t *testing.T) {
	for _, row := range rolloutStateTable {
		t.Run(row.From+"/"+row.Event, func(t *testing.T) {
			r := rolloutIn(row.From)
			switch row.Event {
			case evStageFailed, evNodeFailed:
				r.Nodes["w1"].State = upgradewire.NodeFailed
			case evAllStaged:
				r.Nodes["w1"].State = upgradewire.NodeStaged
				r.Nodes["s1"].State = upgradewire.NodeManual
			case evPause:
				r.PauseAfter = 1
			case evMigrationFailed:
				r.Nodes["w1"].Migrated = false
			}
			v := decideRollout(r, rolloutEvent{Kind: row.Event})
			want := outcomeMove
			if row.To == row.From {
				want = outcomeNoop
			}
			if v.Outcome != want || (want == outcomeMove && v.To != row.To) {
				t.Fatalf("%s on %s = %+v, want %s to %s", row.Event, row.From, v, want, row.To)
			}
			// Every other state refuses the event.
			for _, s := range allRolloutStates {
				if s == row.From || hasStateRow(s, row.Event) {
					continue
				}
				if got := decideRollout(rolloutIn(s), rolloutEvent{Kind: row.Event}); got.Outcome != outcomeRefused {
					t.Fatalf("%s on %s = %+v, want refused", row.Event, s, got)
				}
			}
		})
	}
}

func hasStateRow(state, event string) bool {
	for _, row := range rolloutStateTable {
		if row.From == state && row.Event == event {
			return true
		}
	}
	return false
}

// A progress event whose condition does not hold changes nothing: the FSM
// asks again at apply, so a stale proposal is harmless.
func TestRolloutProgressNeedsItsCondition(t *testing.T) {
	cases := []struct {
		state, event string
		edit         func(r *RolloutRecord)
		want         string
	}{
		{upgradewire.StateStaging, evAllStaged, func(r *RolloutRecord) { r.Nodes["w1"].State = upgradewire.NodePending }, "not staged"},
		{upgradewire.StateStaging, evStageFailed, func(*RolloutRecord) {}, "no node failed"},
		{upgradewire.StateRunning, evNodeFailed, func(*RolloutRecord) {}, "no node failed"},
		{upgradewire.StateRunning, evPause, func(r *RolloutRecord) { r.PauseAfter = 0 }, "no pause left"},
		{upgradewire.StateRunning, evPause, func(r *RolloutRecord) { r.PauseAfter, r.Paused = 1, true }, "no pause left"},
		{upgradewire.StateRunning, evPause, func(r *RolloutRecord) { r.PauseAfter = 5 }, "only 1 of 5"},
		{upgradewire.StateRunning, evAllDone, func(r *RolloutRecord) { r.Nodes["w1"].State = upgradewire.NodeManual }, "w1 is manual"},
		{upgradewire.StateRollingBack, evRolledBack, func(r *RolloutRecord) { r.Nodes["s1"].State = upgradewire.NodeUpgrading }, "s1 is upgrading"},
		{upgradewire.StateFinalizing, evMigrated, func(r *RolloutRecord) { r.Nodes["s1"].Migrated = false }, "s1 has not reported"},
	}
	for _, tc := range cases {
		r := rolloutIn(tc.state)
		tc.edit(r)
		v := decideRollout(r, rolloutEvent{Kind: tc.event})
		if v.Outcome != outcomeRefused || !strings.Contains(v.Reason, tc.want) {
			t.Fatalf("%s on %s = %+v, want refused with %q", tc.event, tc.state, v, tc.want)
		}
	}
	if v := decideRollout(nil, rolloutEvent{Kind: evAllDone}); v.Outcome != outcomeRefused {
		t.Fatalf("progress with no rollout = %+v", v)
	}
	// Skipped nodes count as finished for done.
	r := rolloutIn(upgradewire.StateRunning)
	r.Nodes["w1"].State = upgradewire.NodeSkipped
	if v := decideRollout(r, rolloutEvent{Kind: evAllDone}); v.Outcome != outcomeMove || v.To != upgradewire.StateDone {
		t.Fatalf("all done with a skipped node = %+v", v)
	}
}

func TestRolloutCommandTableEveryRow(t *testing.T) {
	for _, row := range rolloutCommandTable {
		for _, state := range row.States {
			t.Run(row.Cmd+"/"+state, func(t *testing.T) {
				r := rolloutIn(state)
				ev := rolloutEvent{Kind: row.Cmd}
				switch row.Cmd {
				case cmdApplySame:
					ev = rolloutEvent{Kind: evApply, Target: "v2"}
				case cmdApplyOther:
					ev = rolloutEvent{Kind: evApply, Target: "v3"}
				}
				if row.Cmd == evRollback && state == upgradewire.StateFailed {
					r.Direction = upgradewire.DirectionUpgrade
				}
				v := decideRollout(r, ev)
				if v.Outcome != row.Outcome || v.To != row.To {
					t.Fatalf("%s in %s = %+v, want %s to %q", row.Cmd, state, v, row.Outcome, row.To)
				}
				if row.Outcome == outcomeRefused && (v.Code != upgradewire.ErrCodeRolloutConflict || v.Hint == "") {
					t.Fatalf("refusal without code or hint: %+v", v)
				}
				if row.Cmd == evRollback && row.Outcome == outcomeMove && v.Direction != upgradewire.DirectionRollback {
					t.Fatalf("rollback did not turn the direction: %+v", v)
				}
			})
		}
	}
}

// Commands in states no row names are refused with rollout_conflict and a
// reason that says why.
func TestRolloutCommandsRefusedOutsideTheTable(t *testing.T) {
	cmds := []struct {
		kind, target, cmd string
	}{
		{evApply, "v2", cmdApplySame}, {evApply, "v3", cmdApplyOther},
		{evStop, "", evStop}, {evResume, "", evResume}, {evFinalize, "", evFinalize}, {evRollback, "", evRollback},
	}
	for _, c := range cmds {
		for _, s := range allRolloutStates {
			if commandRowFor(c.cmd, s) {
				continue
			}
			if c.cmd == cmdApplySame && s == stateNone {
				continue // with no rollout every apply is "other"
			}
			v := decideRollout(rolloutIn(s), rolloutEvent{Kind: c.kind, Target: c.target})
			if v.Outcome != outcomeRefused || v.Code != upgradewire.ErrCodeRolloutConflict || v.Reason == "" {
				t.Fatalf("%s in %q = %+v, want a rollout_conflict refusal", c.cmd, s, v)
			}
		}
	}
	if v := decideRollout(rolloutIn(upgradewire.StateFinalized), rolloutEvent{Kind: evRollback}); !strings.Contains(v.Reason, "no rollback") {
		t.Fatalf("rollback after finalize = %+v", v)
	}
	if v := decideRollout(nil, rolloutEvent{Kind: evStop}); v.Reason != "there is no rollout" {
		t.Fatalf("stop with no rollout = %+v", v)
	}
	if v := decideRollout(rolloutIn(upgradewire.StateRunning), rolloutEvent{Kind: evApply, Target: "v3"}); !strings.Contains(v.Hint, "finalize") {
		t.Fatalf("apply other while running = %+v", v)
	}
}

func commandRowFor(cmd, state string) bool {
	for _, row := range rolloutCommandTable {
		if row.Cmd == cmd && containsState(row.States, state) {
			return true
		}
	}
	return false
}

// Finalize waits for skipped nodes (skipped_nodes, listing them), for
// nodes still being caught up, and never finalizes a rollback.
func TestRolloutFinalizeRefusals(t *testing.T) {
	r := rolloutIn(upgradewire.StateDone)
	r.Nodes["w1"].State = upgradewire.NodeSkipped
	v := decideRollout(r, rolloutEvent{Kind: evFinalize})
	if v.Outcome != outcomeRefused || v.Code != upgradewire.ErrCodeSkippedNodes || len(v.Nodes) != 1 || v.Nodes[0] != "w1" || v.Hint == "" {
		t.Fatalf("finalize with a skipped node = %+v", v)
	}
	r = rolloutIn(upgradewire.StateDone)
	r.Nodes["w1"].State = upgradewire.NodePending
	if v := decideRollout(r, rolloutEvent{Kind: evFinalize}); v.Outcome != outcomeRefused || len(v.Nodes) != 1 {
		t.Fatalf("finalize while a node catches up = %+v", v)
	}
	r = rolloutIn(upgradewire.StateDone)
	r.Direction = upgradewire.DirectionRollback
	if v := decideRollout(r, rolloutEvent{Kind: evFinalize}); v.Outcome != outcomeRefused {
		t.Fatalf("finalize a rollback = %+v", v)
	}
	r = rolloutIn(upgradewire.StatePaused)
	r.Direction = upgradewire.DirectionRollback
	if v := decideRollout(r, rolloutEvent{Kind: evResume}); v.Outcome != outcomeRefused {
		t.Fatalf("resume a paused rollback = %+v", v)
	}
}

func TestNodeStateTableEveryRow(t *testing.T) {
	all := []string{upgradewire.NodePending, upgradewire.NodeStaged, upgradewire.NodeUpgrading, upgradewire.NodeDone,
		upgradewire.NodeFailed, upgradewire.NodeManual, upgradewire.NodeSkipped}
	allowed := map[string]bool{}
	for _, row := range nodeStateTable {
		for _, to := range row.To {
			allowed[row.From+">"+to] = true
			if !nodeMoveAllowed(row.From, to) {
				t.Fatalf("%s -> %s is in the table but refused", row.From, to)
			}
		}
	}
	for _, from := range all {
		for _, to := range all {
			got := nodeMoveAllowed(from, to)
			want := from == to || allowed[from+">"+to]
			if got != want {
				t.Fatalf("nodeMoveAllowed(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
	// done is final for the per-node writes; only a rollout event resets it.
	if nodeMoveAllowed(upgradewire.NodeDone, upgradewire.NodePending) || nodeMoveAllowed(upgradewire.NodeDone, upgradewire.NodeFailed) {
		t.Fatal("a node write moved a done node")
	}
}

func TestRolloutRecordHelpers(t *testing.T) {
	var nilRec *RolloutRecord
	if nilRec.nodesIn(upgradewire.NodeDone) != nil || nilRec.sortedNodes() != nil {
		t.Fatal("nil record helpers")
	}
	r := rolloutIn(upgradewire.StateRunning)
	r.Nodes["a0"] = &RolloutNodeRecord{NodeID: "a0", Order: 1, State: upgradewire.NodePending}
	r.Nodes["nil"] = nil
	got := r.sortedNodes()
	if len(got) != 3 || got[0].NodeID != "a0" || got[1].NodeID != "s1" || got[2].NodeID != "w1" {
		t.Fatalf("sorted = %v", got)
	}
	if r.workersDone() != 1 || isRolloutCommand(evAllDone) || !isRolloutCommand(evStop) {
		t.Fatal("helpers")
	}
}
