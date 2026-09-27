package cluster

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// PublicInternalDrainedNodesPath returns the whole drained set in one call.
//
// The per-node route (PublicInternalDrainStatePath) is one control-plane round
// trip per question. The secret reseal asks about every current holder of
// every HA sandbox an owner has, on a 30s tick, on every node — at 2,000
// workers that is thousands of round trips a second for a set that is almost
// always empty and changes only when an operator drains something.
const PublicInternalDrainedNodesPath = "/v1/cluster/internal/drained-nodes"

// DrainedNodesResponse is the wire shape of PublicInternalDrainedNodesPath.
type DrainedNodesResponse struct {
	Drained []string `json:"drained"`
}

// DrainedNodesReader is implemented by clients that can return the drained
// set in one read. It is deliberately NOT part of Client: callers type-assert
// and fall back to per-node IsNodeDrained, so no test double has to grow a
// method it never exercises.
type DrainedNodesReader interface {
	DrainedNodes() map[string]bool
}

// DrainedNodes reads the FSM's drained set with no network hop.
func (c *Cluster) DrainedNodes() map[string]bool {
	if c == nil || c.fsm == nil {
		return nil
	}
	return c.fsm.drainedNodesSnapshot()
}

// drainedNodesTTL bounds how stale an agent's drained view may be. A drain is
// an operator action measured in minutes; 10s of lag only delays a reseal
// that the next tick performs, while it caps fleet-wide control-plane load at
// one request per agent per 10s.
const drainedNodesTTL = 10 * time.Second

type drainedNodesCache struct {
	mu        sync.Mutex
	set       map[string]bool
	fetchedAt time.Time
	have      bool
}

// DrainedNodes returns the control plane's drained set, cached for
// drainedNodesTTL. On a failed refresh it keeps serving the last good set:
// forgetting a drain because one request failed would put a secret copy
// straight back onto the node being evacuated.
func (a *Agent) DrainedNodes() map[string]bool {
	if a == nil {
		return nil
	}
	a.drained.mu.Lock()
	defer a.drained.mu.Unlock()
	if a.drained.have && time.Since(a.drained.fetchedAt) < drainedNodesTTL {
		return copyDrainedSet(a.drained.set)
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlPlaneRequestTimeout)
	defer cancel()
	var resp DrainedNodesResponse
	if err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalDrainedNodesPath, PublicInternalDrainedNodesPath, nil, &resp); err != nil {
		if a.logger != nil {
			a.logger.Warn("cluster agent: drained-set lookup failed; using the last known set", "err", err, "have_previous", a.drained.have)
		}
		return copyDrainedSet(a.drained.set)
	}
	set := make(map[string]bool, len(resp.Drained))
	for _, id := range resp.Drained {
		if id != "" {
			set[id] = true
		}
	}
	a.drained.set, a.drained.fetchedAt, a.drained.have = set, time.Now(), true
	return copyDrainedSet(set)
}

func copyDrainedSet(in map[string]bool) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		if v {
			out[k] = true
		}
	}
	return out
}
