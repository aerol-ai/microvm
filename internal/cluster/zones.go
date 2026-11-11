package cluster

import (
	"math/rand"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Zone rules (C10, plans/kubernetes-v2-architecture.md §11). A node's zone is
// its "zone" label, set by SB_NODE_ZONE; on Kubernetes the operator copies
// topology.kubernetes.io/zone into it. Nodes without one share the zone "".
// The rules apply to every cluster, plain VMs included (eng review D9), and
// change nothing on a cluster whose nodes all have the same zone or none:
//
//   - New sandboxes spread across zones by free room (spreadByZone).
//   - Failover never goes into the zone of the node that just died, unless
//     no other zone has room (placementOpts.avoidZone).
//   - A sandbox's sealed-secret backups go to zones other than its owner's
//     (SelectSecretRecipients), so one zone loss cannot take the owner and
//     every backup together.

// memberZone is the zone a member last reported in its capacity heartbeat.
func memberZone(m Member) string {
	return strings.TrimSpace(m.Capacity.Labels[models.PlacementZoneLabel])
}

// zoneSampleSize bounds how many candidates per zone spreadByZone scores. A
// zone's free room is an average; a sample of this size reads it closely
// enough, and placement stays O(1) in scoring work as the fleet grows.
const zoneSampleSize = 16

// spreadByZone narrows candidates to one zone when they span more than one:
// two zones drawn at random, and the one with more free room on average wins
// (power of two choices, one level up). The usual power of two choices then
// runs inside it. Spreading by room rather than by count keeps each zone's
// headroom alike, so a zone loss leaves the others able to take its
// sandboxes (§11 "Workers: each pool keeps headroom in every zone").
// score is the same per-node score placement uses.
//
// It runs on every cluster create, over every candidate (2,000 at the
// design's scale), so it copies nothing until a zone has won: one pass
// counts the zones, and a cluster with one zone (or none) gets candidates
// back as they are. Only the winning zone's members are copied out.
func spreadByZone(candidates []Member, score func(Member) float64) []Member {
	if len(candidates) < 2 {
		return candidates
	}
	var zones []string
	count := make(map[string]int, 4)
	for i := range candidates {
		z := memberZone(candidates[i])
		if count[z] == 0 {
			zones = append(zones, z)
		}
		count[z]++
	}
	if len(zones) < 2 {
		return candidates
	}
	i := rand.Intn(len(zones))
	j := rand.Intn(len(zones) - 1)
	if j >= i {
		j++
	}
	win := zones[i]
	if zoneRoom(candidates, zones[j], score) > zoneRoom(candidates, win, score) {
		win = zones[j]
	}
	out := make([]Member, 0, count[win])
	for i := range candidates {
		if memberZone(candidates[i]) == win {
			out = append(out, candidates[i])
		}
	}
	return out
}

// zoneRoom is the mean score of up to zoneSampleSize of zone's members among
// candidates, read from a random start so a big zone is not always read from
// its first nodes.
func zoneRoom(candidates []Member, zone string, score func(Member) float64) float64 {
	n := len(candidates)
	if n == 0 {
		return 0
	}
	start := rand.Intn(n)
	var sum float64
	k := 0
	for i := 0; i < n && k < zoneSampleSize; i++ {
		m := &candidates[(start+i)%n]
		if memberZone(*m) != zone {
			continue
		}
		sum += score(*m)
		k++
	}
	if k == 0 {
		return 0
	}
	return sum / float64(k)
}

// withoutZone returns the candidates outside zone, or all of them when every
// candidate is inside it: failover into the failed zone beats no failover.
func withoutZone(candidates []Member, zone string) []Member {
	if zone == "" {
		return candidates
	}
	out := make([]Member, 0, len(candidates))
	for _, m := range candidates {
		if memberZone(m) != zone {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return candidates
	}
	return out
}

// maxRememberedZones bounds zoneMemory. A server sees each node it ever held
// a heartbeat from; past this many it stops adding new ones, so a fleet that
// churns node IDs cannot grow it forever. A node it does not know gets no
// zone rule on failover, which is today's behavior.
const maxRememberedZones = 8192

// zoneMemory keeps the last zone each node reported. The capacity lease of a
// node that dies is dropped once it leaves the membership view, but the
// failover that follows needs its zone, so it is kept here apart from the
// lease. Each server fills its own from the heartbeats it reads; a server
// that becomes leader after a node died may not know that node's zone, and
// then the failover has no zone rule.
type zoneMemory struct {
	mu    sync.RWMutex
	zones map[string]string
}

func (z *zoneMemory) record(nodeID, zone string) {
	if z == nil || nodeID == "" {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.zones == nil {
		z.zones = make(map[string]string)
	}
	if cur, ok := z.zones[nodeID]; ok {
		if cur != zone {
			z.zones[nodeID] = zone
		}
		return
	}
	if len(z.zones) >= maxRememberedZones {
		return
	}
	z.zones[nodeID] = zone
}

func (z *zoneMemory) zoneOf(nodeID string) string {
	if z == nil {
		return ""
	}
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.zones[nodeID]
}

func (z *zoneMemory) forget(nodeID string) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.zones, nodeID)
}
