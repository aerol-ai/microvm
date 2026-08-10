package clusterlist

import (
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

type stubListCluster struct {
	*cluster.Noop
	members    []cluster.Member
	placements []cluster.Placement
}

func (c *stubListCluster) Members() []cluster.Member { return c.members }
func (c *stubListCluster) Placements() []cluster.Placement {
	return append([]cluster.Placement(nil), c.placements...)
}

func TestSelectPeersUsesPlacementOwnersNotFullMembership(t *testing.T) {
	members := make([]cluster.Member, 0, 300)
	members = append(members, cluster.Member{
		NodeID: "self", APIURL: "http://self", Alive: true, Role: config.NodeRoleMixed,
	})
	for i := 0; i < 300; i++ {
		members = append(members, cluster.Member{
			NodeID: fmt.Sprintf("w-%03d", i),
			APIURL: fmt.Sprintf("http://w-%03d", i),
			Alive:  true,
			Role:   config.NodeRoleWorker,
		})
	}
	members[1].NodeID = "owner-a"
	members[1].APIURL = "http://owner-a"
	members[2].NodeID = "owner-b"
	members[2].APIURL = "http://owner-b"

	c := &stubListCluster{
		Noop:    cluster.NewNoop("self", "http://self", ""),
		members: members,
		placements: []cluster.Placement{
			{SandboxID: "sb-1", OwnerNodeID: "owner-a", OwnerRef: "tenant-1"},
			{SandboxID: "sb-2", OwnerNodeID: "owner-b", OwnerRef: "tenant-1"},
			{SandboxID: "sb-3", OwnerNodeID: "owner-a", OwnerRef: "tenant-2"},
		},
	}
	peers := SelectPeers(c, "tenant-1")
	if len(peers) != 2 {
		t.Fatalf("SelectPeers(tenant-1) = %d peers, want 2", len(peers))
	}
	got := map[string]bool{}
	for _, p := range peers {
		got[p.NodeID] = true
	}
	if !got["owner-a"] || !got["owner-b"] {
		t.Fatalf("peers = %+v, want owner-a and owner-b", peers)
	}

	c.placements = nil
	if peers = SelectPeers(c, ""); peers != nil {
		t.Fatalf("empty placements at large membership: got %d peers, want nil", len(peers))
	}
}
