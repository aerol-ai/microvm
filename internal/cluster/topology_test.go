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
