package cluster

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestIsMixedArchitectureRole(t *testing.T) {
	for _, tc := range []struct {
		role string
		want bool
	}{
		{"", true},
		{config.NodeRoleMixed, true},
		{"server,worker,ingress", true},
		{"worker,ingress", true},
		{"server,worker", true},
		{"server,ingress", true},
		{config.NodeRoleServer, false},
		{config.NodeRoleWorker, false},
		{config.NodeRoleIngress, false},
	} {
		if got := IsMixedArchitectureRole(tc.role); got != tc.want {
			t.Fatalf("IsMixedArchitectureRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}

func TestLiveMemberCountSkipsDeadAndBlankNodes(t *testing.T) {
	members := []Member{
		{NodeID: "node-1", Alive: true},
		{NodeID: "node-2", Alive: false},
		{NodeID: "", Alive: true},
		{NodeID: "   ", Alive: true},
		{NodeID: "node-3", Alive: true},
	}

	if got := LiveMemberCount(members); got != 2 {
		t.Fatalf("LiveMemberCount() = %d, want 2", got)
	}
}

func TestLargeClusterTopologyAllowsSmallMixedCluster(t *testing.T) {
	members := makeTopologyMembers(
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
		config.NodeRoleMixed,
	)

	if err := LargeClusterTopologyError(members); err != nil {
		t.Fatalf("LargeClusterTopologyError small mixed cluster = %v, want nil", err)
	}
}

func TestLargeClusterTopologyAllowsDedicatedProductionShape(t *testing.T) {
	members := makeTopologyMembers(
		config.NodeRoleServer,
		config.NodeRoleServer,
		config.NodeRoleServer,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleIngress,
		config.NodeRoleIngress,
	)

	if err := LargeClusterTopologyError(members); err != nil {
		t.Fatalf("LargeClusterTopologyError dedicated production cluster = %v, want nil", err)
	}
}

func TestLargeClusterTopologyRejectsMixedOrHybridNodes(t *testing.T) {
	members := makeTopologyMembers(
		config.NodeRoleServer,
		config.NodeRoleServer,
		config.NodeRoleServer,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleIngress,
		"worker,ingress",
	)

	err := LargeClusterTopologyError(members)
	if !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("LargeClusterTopologyError hybrid cluster = %v, want ErrInvalidTopology", err)
	}
	if !strings.Contains(err.Error(), "mixed or hybrid-role nodes") {
		t.Fatalf("error = %q, want mixed/hybrid explanation", err.Error())
	}
}

func TestLargeClusterTopologyRequiresAllDedicatedTiers(t *testing.T) {
	members := makeTopologyMembers(
		config.NodeRoleServer,
		config.NodeRoleServer,
		config.NodeRoleServer,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
		config.NodeRoleWorker,
	)

	err := LargeClusterTopologyError(members)
	if !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("LargeClusterTopologyError missing ingress = %v, want ErrInvalidTopology", err)
	}
	if !strings.Contains(err.Error(), "missing=ingress") {
		t.Fatalf("error = %q, want missing ingress", err.Error())
	}
}

func TestInvalidTopologyFromMessageWrapsSentinel(t *testing.T) {
	err := invalidTopologyFromMessage(ErrInvalidTopology.Error() + ": live cluster contains mixed nodes")
	if !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("invalidTopologyFromMessage = %v, want ErrInvalidTopology", err)
	}
}

func makeTopologyMembers(roles ...string) []Member {
	members := make([]Member, 0, len(roles))
	for i, role := range roles {
		members = append(members, Member{
			NodeID: fmt.Sprintf("node-%02d", i+1),
			Role:   role,
			Alive:  true,
		})
	}
	return members
}

// The server tier is the only tier that holds Raft state. SB_CLUSTER_MAX_AUTO_VOTERS
// caps voters, not replicas: a surplus server-role node joins as a non-voter and
// still receives the full FSM. Worker and ingress scale out freely because they
// run Agent and hold nothing.
func TestLargeClusterTopologyCapsTheServerTier(t *testing.T) {
	build := func(servers, workers, ingress int) []Member {
		out := make([]Member, 0, servers+workers+ingress)
		for i := 0; i < servers; i++ {
			out = append(out, Member{NodeID: fmt.Sprintf("server-%03d", i), Alive: true, Role: config.NodeRoleServer})
		}
		for i := 0; i < workers; i++ {
			out = append(out, Member{NodeID: fmt.Sprintf("worker-%03d", i), Alive: true, Role: config.NodeRoleWorker})
		}
		for i := 0; i < ingress; i++ {
			out = append(out, Member{NodeID: fmt.Sprintf("ingress-%03d", i), Alive: true, Role: config.NodeRoleIngress})
		}
		return out
	}

	for _, tc := range []struct {
		name    string
		servers int
		workers int
		ingress int
		wantErr bool
	}{
		{"at the cap is allowed", MaxServerTierNodes, 40, 4, false},
		{"one over the cap fails closed", MaxServerTierNodes + 1, 40, 4, true},
		{"a fat control plane fails closed", 50, 500, 20, true},
		{"small clusters are exempt", MaxServerTierNodes + 3, 0, 0, false},
		{"workers and ingress scale out freely", 3, 1900, 97, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := LargeClusterTopologyError(build(tc.servers, tc.workers, tc.ingress))
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidTopology) {
					t.Fatalf("err = %v, want ErrInvalidTopology", err)
				}
				if !strings.Contains(err.Error(), "server tier is capped") {
					t.Fatalf("err = %v, want the server-tier message", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// Dead server-role nodes must not count against the cap, or a rolling
// replacement would wedge every create until gossip reaped the old members.
func TestLargeClusterTopologyServerCapIgnoresDeadServers(t *testing.T) {
	members := make([]Member, 0, MaxServerTierNodes+30)
	for i := 0; i < MaxServerTierNodes; i++ {
		members = append(members, Member{NodeID: fmt.Sprintf("server-%03d", i), Alive: true, Role: config.NodeRoleServer})
	}
	for i := 0; i < 5; i++ {
		members = append(members, Member{NodeID: fmt.Sprintf("server-old-%03d", i), Alive: false, Role: config.NodeRoleServer})
	}
	for i := 0; i < 20; i++ {
		members = append(members, Member{NodeID: fmt.Sprintf("worker-%03d", i), Alive: true, Role: config.NodeRoleWorker})
	}
	members = append(members, Member{NodeID: "ingress-000", Alive: true, Role: config.NodeRoleIngress})

	if err := LargeClusterTopologyError(members); err != nil {
		t.Fatalf("dead servers counted against the cap: %v", err)
	}
}
