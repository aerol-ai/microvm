package cluster

import (
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestIngressShardFilterAppendsSelfAndDedups(t *testing.T) {
	// Many ingress members so sharding engages; self not initially listed as ingress.
	members := make([]Member, 0, MaxReplicatedIngressRouteNodes+2)
	for i := 0; i < MaxReplicatedIngressRouteNodes+1; i++ {
		members = append(members, Member{NodeID: fmt.Sprintf("ing-%02d", i), Alive: true, Role: config.NodeRoleIngress, APIURL: "http://x"})
	}
	// Duplicate id should be ignored by ingressShardNodeIDs / ingressRouteOwners.
	members = append(members, Member{NodeID: "ing-00", Alive: true, Role: config.NodeRoleIngress, APIURL: "http://dup"})
	filter := IngressShardFilterForNode(members, "self-extra", config.NodeRoleIngress)
	if filter.ShardCount == 0 && len(filter.Shards) == 0 {
		// self-extra was appended; with > Max nodes we should get a non-empty shard filter
		t.Fatalf("expected sharded filter for oversized ingress + self, got %+v", filter)
	}
	route := IngressRouteForSandbox(members, "sb-1")
	if len(route.Owners) != 2 {
		t.Fatalf("large tier route owners=%+v, want primary+replica", route.Owners)
	}
}
