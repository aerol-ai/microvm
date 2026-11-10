package cluster

import (
	"sort"

	"github.com/hashicorp/raft"
)

// RaftRoles is one Raft server's view of the configuration: every configured
// server (true when it votes) and the current leader.
type RaftRoles struct {
	Servers map[string]bool
	Leader  string
}

// RaftRoleReader is implemented by a node that holds Raft state. It is
// deliberately NOT part of Client, like DrainedNodesReader: a worker has no
// Raft view, and no test double should have to grow one.
type RaftRoleReader interface {
	RaftRoles() (RaftRoles, bool)
}

// RaftRoles reads this server's Raft configuration. ok is false when there
// is no Raft (a half-built test cluster) or the read failed.
func (c *Cluster) RaftRoles() (RaftRoles, bool) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return RaftRoles{}, false
	}
	future := c.raft.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return RaftRoles{}, false
	}
	servers := future.Configuration().Servers
	out := RaftRoles{Servers: make(map[string]bool, len(servers)), Leader: c.Leader()}
	for _, srv := range servers {
		out.Servers[string(srv.ID)] = srv.Suffrage == raft.Voter
	}
	return out, true
}

// Voters lists the voting servers, sorted. It is the configuration, not
// gossip: a voter down long enough for gossip to forget it is still
// listed, and still counts toward the majority Raft needs.
func (r RaftRoles) Voters() []string {
	out := make([]string, 0, len(r.Servers))
	for id, voter := range r.Servers {
		if voter {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Annotate fills Voter and Leader on members from r, in place.
func (r RaftRoles) Annotate(members []Member) []Member {
	for i := range members {
		members[i].Voter = r.Servers[members[i].NodeID]
		members[i].Leader = r.Leader != "" && members[i].NodeID == r.Leader
	}
	return members
}

// AnnotateRaftRoles fills Voter and Leader on members from c's Raft view, in
// place. It costs one configuration read, so only the operator endpoints call
// it, never Members() itself: create routing and list fan-out read Members()
// on every request and need neither field. A client with no Raft view (an
// agent, Noop) leaves members unchanged; an agent's Members() is already a
// server's annotated answer.
func AnnotateRaftRoles(c Client, members []Member) []Member {
	reader, ok := c.(RaftRoleReader)
	if !ok {
		return members
	}
	roles, ok := reader.RaftRoles()
	if !ok {
		return members
	}
	return roles.Annotate(members)
}
