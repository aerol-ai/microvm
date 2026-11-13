package cluster

import (
	"expvar"
	"math/rand"
	"time"
)

// Sampled placement (C18 E6, plans/kubernetes-v2-architecture.md §9.4, L-f).
// A placement decision used to copy every member's record (twice: the
// gossip snapshot and the capacity overlay) and judge them all, then score a
// sample of zoneSampleSize per zone. At 500 workers that was 0.6 ms and
// 0.9 MB of garbage per create on the leader, and both grow with the fleet
// (BenchmarkSelectPlacementFleet). In a large fleet the decision now draws
// placementSampleSize members at random from the index's owner list
// (workers that can own sandboxes), judges only those with the same rules
// (placementFilter.scan), and chooses as before (choosePlacement).
//
// The full scan still decides when the sample cannot: a fleet smaller than
// sampledPlacementMinOwners (exact, and cheap there); a create bound to one
// node or to a template's holders; a membership whose topology is invalid;
// and a sample with fewer than two members that can take the request, so a
// nearly full cell still finds its last free worker and an empty result
// still says exactly why (capacity, labels, drain, gateway).
//
// What changes on the sampled path: the candidates handed back (the secret
// recipients' pool, an older agent's answer) are the sample's, and the
// scheduler's reject counts cover the sample.
const (
	// sampledPlacementMinOwners: below this the full scan is exact and costs
	// little (about 150 µs at 100 workers).
	sampledPlacementMinOwners = 64
	// placementSampleSize: about zoneSampleSize per zone in a three-zone
	// cell, the same number spreadByZone scored from the full set.
	placementSampleSize = 3 * zoneSampleSize
)

var (
	placementSampledDecisions = expvar.NewInt("aerolvm_cluster_placement_sampled_total")
	placementFullScans        = expvar.NewInt("aerolvm_cluster_placement_full_scans_total")
)

// selectPlacementSampled is the sampled decision; ok is false when the full
// scan must decide instead.
func (c *Cluster) selectPlacementSampled(f placementFilter, opts placementOpts) (PlacementTarget, []Member, bool) {
	if f.req.RequiredNodeID != "" || f.req.TemplateID != "" || c.gossip == nil {
		return PlacementTarget{}, nil, false
	}
	idx := c.gossip.currentMemberIndex()
	sample, owners, topologyErr := idx.sampleOwners(placementSampleSize, rand.Intn)
	if topologyErr != nil || owners < sampledPlacementMinOwners {
		return PlacementTarget{}, nil, false
	}
	now := time.Now()
	if c.capacityLeases != nil {
		c.capacityLeases.applyInPlace(sample, now)
	}
	// After the capacity read, as on the full path (pendingLoadByNode).
	f.pending = c.pendingLoadByNode(now.Unix())
	r := f.scan(sample)
	if len(r.candidates) < 2 {
		return PlacementTarget{}, nil, false
	}
	target, candidates, err := c.choosePlacement(f, opts, r)
	if err != nil {
		return PlacementTarget{}, nil, false
	}
	placementSampledDecisions.Add(1)
	return target, candidates, true
}
