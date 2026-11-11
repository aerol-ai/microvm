package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Readiness (plans/kubernetes-v2-architecture.md C1; the design is decision
// D8 of the first Kubernetes plan, §5.4). /health says the process is up;
// /ready says whether to send this node traffic. A node cut off from the
// control plane answered /health with 200, so load balancers and Kubernetes
// kept sending it requests that failed (TODOS.md, "A partitioned node keeps
// serving"). /ready answers 503 when the node is not part of the control
// plane, or has not heard from a working one for longer than a grace
// window above normal election time.

// ControlPlaneContact is what a node knows about its own link to the
// control plane.
type ControlPlaneContact struct {
	// Member is false for a server-role node that is not in the raft
	// configuration (removed, or never joined). Agents are never raft
	// members, so for them it is always true.
	Member bool
	// Last is the last time this node had proof of a working control plane:
	// now for the raft leader; a follower's last contact from the leader;
	// an agent's last successful control-plane exchange. Zero: never.
	Last time.Time
}

// ControlPlaneContactReporter is implemented by the clients that can lose
// the control plane (*Cluster, *Agent). Noop, the single-node client, is
// the whole control plane and does not implement it.
type ControlPlaneContactReporter interface {
	ControlPlaneContact(ctx context.Context) ControlPlaneContact
}

// ControlPlaneContact reports this server's raft view. The leader has the
// newest view there is, so its contact is now. A follower's is raft's last
// contact from the leader: heartbeats every HeartbeatTimeout/10 keep it
// fresh, and pre-vote keeps a minority side from refreshing it by
// campaigning (stale_read.go). A Cluster without raft (a single-process
// FSM) is the whole control plane.
func (c *Cluster) ControlPlaneContact(context.Context) ControlPlaneContact {
	state, last, ok := c.leaderContact()
	if !ok {
		return ControlPlaneContact{Member: true, Last: time.Now()}
	}
	member := c.raftMember()
	if state == raft.Leader {
		return ControlPlaneContact{Member: member, Last: time.Now()}
	}
	return ControlPlaneContact{Member: member, Last: last}
}

// raftMember reports whether this node is in the raft configuration, as a
// voter or not. A configuration that cannot be read counts as a member: it
// is the contact time, not this read, that says the node is cut off.
func (c *Cluster) raftMember() bool {
	if c.raftMemberHook != nil {
		return c.raftMemberHook()
	}
	if c.raft == nil || c.raft.raft == nil {
		return true
	}
	f := c.raft.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return true
	}
	for _, s := range f.Configuration().Servers {
		if string(s.ID) == c.nodeID {
			return true
		}
	}
	return false
}

// agentContact records an agent's proof of a working control plane.
type agentContact struct {
	mu   sync.Mutex
	last time.Time
	// probing holds callers while one probe is in flight, so readiness
	// checks from many probes never send more than one request at a time.
	probing *sync.Cond
	busy    bool
}

func (c *agentContact) record(t time.Time) {
	c.mu.Lock()
	if t.After(c.last) {
		c.last = t
	}
	c.mu.Unlock()
}

// agentContactProbeAfter is how old an agent's last contact may be before
// a readiness check asks the control plane itself. Below the 10 s default
// grace, so a probe lands before readiness would fail; above the 5 s of
// the ownership lease's reads, so a busy worker never probes.
var agentContactProbeAfter = 6 * time.Second

// ControlPlaneContact reports the last successful control-plane exchange.
// Workers renew their ownership lease every 5 s and gateways reconcile on a
// timer, so this is normally fresh. When it is not, one probe asks the
// control plane who leads (Leader); an answer naming a leader counts,
// since a server that answers but has no leader cannot serve this node.
// Concurrent callers share that one probe.
func (a *Agent) ControlPlaneContact(ctx context.Context) ControlPlaneContact {
	c := &a.contact
	c.mu.Lock()
	if c.probing == nil {
		c.probing = sync.NewCond(&c.mu)
	}
	if time.Since(c.last) <= agentContactProbeAfter {
		last := c.last
		c.mu.Unlock()
		return ControlPlaneContact{Member: true, Last: last}
	}
	if c.busy {
		for c.busy {
			c.probing.Wait()
		}
		last := c.last
		c.mu.Unlock()
		return ControlPlaneContact{Member: true, Last: last}
	}
	c.busy = true
	c.mu.Unlock()

	if a.leaderProbe(ctx) != "" {
		c.record(time.Now())
	}

	c.mu.Lock()
	c.busy = false
	last := c.last
	c.probing.Broadcast()
	c.mu.Unlock()
	return ControlPlaneContact{Member: true, Last: last}
}

// leaderProbe is Leader, swappable in tests.
func (a *Agent) leaderProbe(context.Context) string {
	if a.leaderProbeHook != nil {
		return a.leaderProbeHook()
	}
	return a.Leader()
}
