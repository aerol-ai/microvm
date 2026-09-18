package cluster

import (
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
)

// MaxMixedClusterNodes is the largest live cluster size allowed to keep the
// legacy mixed/hybrid convenience topology. Above this, production clusters
// must run dedicated server, worker, and ingress tiers.
const MaxMixedClusterNodes = 10

// MaxServerTierNodes caps the live server-role tier. The voter cap
// (SB_CLUSTER_MAX_AUTO_VOTERS, default 5) bounds how many nodes *vote*, not how
// many hold state: a surplus server-role node is added as a Raft non-voter and
// still receives the full log and FSM — at 100k sandboxes that is ~72 MB of
// placement state plus a leader replication stream each. Scaling out belongs in
// the worker and ingress tiers, which run Agent and hold no FSM at all, so the
// control plane stays a small fixed set however large the fleet grows.
//
// 7 = the default 5 voters plus two slots, so a rolling replacement can bring a
// new server up before retiring the old one without tripping the gate.
// Deliberately a constant, like MaxMixedClusterNodes: an env override here
// would just re-open the foot-gun it exists to close.
const MaxServerTierNodes = 7

type topologyRoleSet struct {
	server      bool
	worker      bool
	ingress     bool
	legacyMixed bool
}

func topologyRoles(role string) topologyRoleSet {
	trimmed := strings.TrimSpace(role)
	if trimmed == "" {
		return topologyRoleSet{server: true, worker: true, ingress: true, legacyMixed: true}
	}
	var out topologyRoleSet
	for raw := range strings.SplitSeq(trimmed, ",") {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case config.NodeRoleServer:
			out.server = true
		case config.NodeRoleWorker:
			out.worker = true
		case config.NodeRoleIngress:
			out.ingress = true
		case config.NodeRoleMixed:
			out.server = true
			out.worker = true
			out.ingress = true
			out.legacyMixed = true
		}
	}
	return out
}

func (r topologyRoleSet) roleCount() int {
	n := 0
	if r.server {
		n++
	}
	if r.worker {
		n++
	}
	if r.ingress {
		n++
	}
	return n
}

func (r topologyRoleSet) dedicated() bool {
	return !r.legacyMixed && r.roleCount() == 1
}

// IsMixedArchitectureRole reports whether a role value runs more than one
// production tier. Empty legacy metadata is treated as mixed because old nodes
// behaved as server+worker+ingress.
func IsMixedArchitectureRole(role string) bool {
	return !topologyRoles(role).dedicated()
}

// LiveMemberCount counts live members with a usable node ID.
func LiveMemberCount(members []Member) int {
	live := 0
	for _, m := range members {
		if m.Alive && strings.TrimSpace(m.NodeID) != "" {
			live++
		}
	}
	return live
}

// LargeClusterTopologyError enforces the production topology contract:
// clusters above MaxMixedClusterNodes must have dedicated server, worker, and
// ingress tiers. Small clusters keep the legacy convenience behavior.
func LargeClusterTopologyError(members []Member) error {
	live := 0
	server := 0
	worker := 0
	ingress := 0
	mixedNodes := make([]string, 0)

	for _, m := range members {
		nodeID := strings.TrimSpace(m.NodeID)
		if !m.Alive || nodeID == "" {
			continue
		}
		live++
		roles := topologyRoles(m.Role)
		if roles.server {
			server++
		}
		if roles.worker {
			worker++
		}
		if roles.ingress {
			ingress++
		}
		if !roles.dedicated() {
			mixedNodes = append(mixedNodes, nodeID)
		}
	}

	if live <= MaxMixedClusterNodes {
		return nil
	}
	if len(mixedNodes) > 0 {
		return fmt.Errorf("%w: clusters with more than %d live nodes cannot include mixed or hybrid-role nodes (live=%d nodes=%s); use dedicated server, worker, and ingress roles",
			ErrInvalidTopology, MaxMixedClusterNodes, live, strings.Join(mixedNodes, ","))
	}
	missing := make([]string, 0, 3)
	if server == 0 {
		missing = append(missing, config.NodeRoleServer)
	}
	if worker == 0 {
		missing = append(missing, config.NodeRoleWorker)
	}
	if ingress == 0 {
		missing = append(missing, config.NodeRoleIngress)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: clusters with more than %d live nodes require dedicated server, worker, and ingress tiers (live=%d missing=%s)",
			ErrInvalidTopology, MaxMixedClusterNodes, live, strings.Join(missing, ","))
	}
	if server > MaxServerTierNodes {
		return fmt.Errorf("%w: the server tier is capped at %d live nodes (live_servers=%d); every server-role node carries a full Raft FSM replica, and SB_CLUSTER_MAX_AUTO_VOTERS caps only voters — extra servers join as non-voters and still replicate the whole placement map. Re-role the surplus nodes to worker or ingress",
			ErrInvalidTopology, MaxServerTierNodes, server)
	}
	return nil
}

func invalidTopologyFromMessage(message string) error {
	if message == ErrInvalidTopology.Error() {
		return ErrInvalidTopology
	}
	prefix := ErrInvalidTopology.Error() + ": "
	if strings.HasPrefix(message, prefix) {
		return fmt.Errorf("%w: %s", ErrInvalidTopology, strings.TrimPrefix(message, prefix))
	}
	return nil
}
