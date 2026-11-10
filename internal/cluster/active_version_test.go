package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	"github.com/hashicorp/memberlist"
)

// Regression tests for the active cluster version's effects outside the
// FSM (active_version.go): placement skips members below it, voter
// auto-join keeps old servers out of Raft, joins are checked against it,
// and gossip carries the CPU type a rollout needs.

func TestJoinVersionRuleWithRolloutAndActiveVersion(t *testing.T) {
	c := gossipCluster(t, Member{NodeID: "srv-a", Alive: true, Role: config.NodeRoleServer, Version: "v1.2.3"})
	// Before any active version: today's rule.
	if !c.joinVersionAllowed("v1.2.3", 0) || c.joinVersionAllowed("v9", 13) {
		t.Fatal("rule before the active version")
	}
	if c.joinVersion() != version.Version {
		t.Fatal("join version with no rollout")
	}
	applyDenyLogAt(t, c.fsm, 1, activeCmd(13, 0, "v1.2.3", 1))
	cases := []struct {
		v    string
		fv   int
		want bool
	}{{"v9", 13, true}, {"v9", 14, true}, {"v1.2.2", 12, false}, {"v1.2.3", 0, true}, {"v0", 0, false}, {version.Version, 0, true}, {"", 13, false}}
	for _, tc := range cases {
		if got := c.joinVersionAllowed(tc.v, tc.fv); got != tc.want {
			t.Fatalf("active set: joinVersionAllowed(%s, %d) = %v", tc.v, tc.fv, got)
		}
	}
	// During a rollout only its target and previous version may join; a
	// finalizing rollout takes only its target. New nodes install the
	// version the rollout moves to.
	r := newTestRollout("r1", "v2", &RolloutNodeRecord{NodeID: "srv-a", State: upgradewire.NodePending})
	r.PreviousVersion = "v1.2.3"
	applyDenyLogAt(t, c.fsm, 2, command{Op: opRolloutCommand, StampUnixNano: 2, RolloutCmd: &RolloutCommand{Event: evApply, New: r, Target: "v2"}})
	for _, tc := range []struct {
		v    string
		fv   int
		want bool
	}{{"v2", 13, true}, {"v1.2.3", 13, true}, {"v3", 14, false}, {version.Version, 13, false}} {
		if got := c.joinVersionAllowed(tc.v, tc.fv); got != tc.want {
			t.Fatalf("rollout: joinVersionAllowed(%s, %d) = %v", tc.v, tc.fv, got)
		}
	}
	if c.joinVersion() != "v2" {
		t.Fatalf("join version during a rollout = %s", c.joinVersion())
	}
	c.fsm.rollout.State = upgradewire.StateFinalizing
	if c.joinVersionAllowed("v1.2.3", 13) || !c.joinVersionAllowed("v2", 13) {
		t.Fatal("finalizing rollout took the previous version")
	}
	c.fsm.rollout.State, c.fsm.rollout.Direction = upgradewire.StateRollingBack, upgradewire.DirectionRollback
	if c.joinVersion() != "v1.2.3" {
		t.Fatalf("join version during a rollback = %s", c.joinVersion())
	}
}

func TestGossipCarriesArch(t *testing.T) {
	d := newGossipDelegate("n1", "", "http://n1:21212", "", "n1:7000", "https://n1:7002", config.NodeRoleWorker, "", nil)
	enc := d.NodeMeta(memberlist.MetaMaxSize)
	if !strings.Contains(string(enc), `"ar":"`) {
		t.Fatalf("meta = %s, want ar", enc)
	}
	m := memberFromMemberlistNode(&memberlist.Node{Name: "n1", State: memberlist.StateAlive, Meta: enc})
	if m.Arch == "" || m.Arch != d.arch {
		t.Fatalf("decoded arch = %q", m.Arch)
	}
	if self := (&gossipNode{delegate: d}).selfMember(); self.Arch != d.arch {
		t.Fatalf("self arch = %q", self.Arch)
	}
	// The largest realistic meta still fits with ar on the first tiers.
	label := strings.Repeat("n", 63)
	big := &gossipDelegate{
		nodeID: label, nodeName: label, apiURL: "https://" + label + ".example.com:21212", dataPlaneHost: label + ".example.com",
		raftAddr: "10.255.255.255:7000", internalURL: "https://" + label + ".example.com:7002", role: config.NodeRoleServer,
		publicHost: label + ".example.com", buildVersion: "v10.20.30-rc.10+g0123456789ab-dirty", arch: "riscv64",
	}
	big.patScope = "host"
	big.refreshMeta()
	out := big.NodeMeta(memberlist.MetaMaxSize)
	var meta nodeMeta
	if len(out) > memberlist.MetaMaxSize || json.Unmarshal(out, &meta) != nil || meta.RaftAddr == "" || meta.FSMOpsVersion != fsmOpsVersion || meta.Arch != "riscv64" {
		t.Fatalf("largest meta = %d bytes: %+v", len(out), meta)
	}
}
