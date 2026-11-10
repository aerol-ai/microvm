package cluster

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// placeDenyFenceSandboxes gives owner one sandbox that opts into failover
// recreate and one that does not, and makes gossip read owner as alive with
// no free CPU, so it is never picked as the new home. The member is written
// before any deny record, as in a real delete: the record does not purge the
// member index (DeleteNode calls applyDenySet only after it evicts), and the
// fence cluster's gossip refresh is stopped, so the index keeps reading the
// node as alive.
func placeDenyFenceSandboxes(t *testing.T, c *Cluster, owner string) (failoverID, plainID string) {
	t.Helper()
	failover := placeFailoverPlacement(t, c, "sb-"+owner+"-failover", owner)
	plainID = "sb-" + owner + "-plain"
	applyRaftCommand(t, c, command{
		Op: opPlace, SandboxID: plainID, OwnerNodeID: owner, OwnerAPIURL: "http://" + owner,
		IncarnationID: "inc-" + plainID, Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
	c.gossip.currentMemberIndex().upsert(recreateCandidate(owner, config.NodeRoleWorker, 0))
	return failover.SandboxID, plainID
}

func denyNodeForTest(t *testing.T, c *Cluster, nodeID string) {
	t.Helper()
	applyRaftCommand(t, c, command{
		Op:            opDenyNode,
		StampUnixNano: time.Now().UnixNano(),
		NodeDeny:      &NodeDenyRecord{NodeID: nodeID, Role: config.NodeRoleWorker},
	})
}

// TestEvictionFenceNeverCountsADeletedNodeAsBack pins how the operator's node
// delete fits main's dead-owner fence. The fence stops an eviction when the
// owner shows alive again, so a node that comes back keeps its sandboxes. A
// deleted node is refused at peer auth, gossip and placement, so it never
// counts as back: its eviction finishes even while its machine still runs
// and gossip still reads it as alive.
func TestEvictionFenceNeverCountsADeletedNodeAsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	cases := []struct {
		name    string
		deleted bool
		wantErr error
		// moved: the failover sandbox went to the leader and the plain one
		// was orphaned. Otherwise both stay with the owner.
		moved bool
	}{
		{name: "deleted node that keeps gossiping alive", deleted: true, moved: true},
		{name: "node that was not deleted and comes back", deleted: false, wantErr: errOwnerRejoined},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := newEvictFenceCluster(t, fmt.Sprintf("srv-evict-deny-%d", i))
			defer cleanup()
			const owner = "wkr-gossiping"
			failoverID, plainID := placeDenyFenceSandboxes(t, c, owner)
			if tc.deleted {
				denyNodeForTest(t, c, owner)
			}
			if m, ok := c.gossip.lookupMember(owner); !ok || !m.Alive {
				t.Fatalf("precondition: gossip must read %s as alive, got ok=%v alive=%v", owner, ok, m.Alive)
			}

			reassigned, orphaned, err := c.evictOwnerPlacements(context.Background(), owner)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("evictOwnerPlacements err = %v, want %v", err, tc.wantErr)
			}
			failover, _ := c.fsm.get(failoverID)
			plain, _ := c.fsm.get(plainID)
			if tc.moved {
				if reassigned != 1 || orphaned != 1 {
					t.Fatalf("reassigned=%d orphaned=%d, want 1 and 1", reassigned, orphaned)
				}
				if failover.OwnerNodeID != c.nodeID {
					t.Fatalf("failover sandbox owner = %q, want the leader %q: the fence stopped a deleted node's eviction", failover.OwnerNodeID, c.nodeID)
				}
				if !plain.IsOrphaned() {
					t.Fatalf("plain sandbox owner = %q, want orphaned: the fence stopped a deleted node's eviction", plain.OwnerNodeID)
				}
				return
			}
			if reassigned != 0 || orphaned != 0 {
				t.Fatalf("reassigned=%d orphaned=%d, want 0 and 0 for a node that came back", reassigned, orphaned)
			}
			for _, p := range []Placement{failover, plain} {
				if p.IsOrphaned() || p.OwnerNodeID != owner {
					t.Fatalf("%s: owner=%q orphaned=%v, want it left with %s, which came back", p.SandboxID, p.OwnerNodeID, p.IsOrphaned(), owner)
				}
			}
		})
	}
}

// TestDeleteNodeOfARunningNodeHandsItsSandboxesOver is the same rule through
// the operator's path: aerolvm delete node --force on a worker whose machine
// still runs writes the deny record and then evicts, and the eviction is not
// stopped by the node still showing alive in gossip.
func TestDeleteNodeOfARunningNodeHandsItsSandboxesOver(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newEvictFenceCluster(t, "srv-delete-running")
	defer cleanup()
	const owner = "wkr-still-running"
	failoverID, plainID := placeDenyFenceSandboxes(t, c, owner)

	res, err := c.DeleteNode(context.Background(), owner, true)
	if err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if !res.Denied || res.Reassigned != 1 || res.Orphaned != 1 {
		t.Fatalf("DeleteNode = %+v, want denied with 1 reassigned and 1 orphaned", res)
	}
	if p, _ := c.fsm.get(failoverID); p.OwnerNodeID != c.nodeID {
		t.Fatalf("failover sandbox owner = %q, want the leader %q", p.OwnerNodeID, c.nodeID)
	}
	if p, _ := c.fsm.get(plainID); !p.IsOrphaned() {
		t.Fatalf("plain sandbox owner = %q, want orphaned", p.OwnerNodeID)
	}
	if c.fsm.ownedCount(owner) != 0 {
		t.Fatalf("deleted node still owns %d sandboxes", c.fsm.ownedCount(owner))
	}
}
