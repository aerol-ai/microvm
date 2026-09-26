package service

import (
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// stubPlacementPage serves an owner-filtered, sorted, paged view over a literal
// placement slice, matching what the FSM's owner index does: materialized rows
// only (no reservations, no orphans), ordered by sandbox ID, cursor-exclusive.
//
// Test clusters that hold a []cluster.Placement implement PlacementPage through
// this so the reconcile sweep exercises the same read shape production uses.
// Embedding cluster.Noop is not enough — its PlacementPage answers
// Authoritative:false, which the sweep correctly treats as "view unavailable,
// skip" rather than "nothing is placed."
func stubPlacementPage(all []cluster.Placement, req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	req = req.Normalize()
	owner := strings.TrimSpace(req.OwnerNodeID)

	matched := make([]cluster.Placement, 0, len(all))
	for _, p := range all {
		if p.SandboxID == "" {
			continue
		}
		if owner != "" {
			if strings.TrimSpace(p.OwnerNodeID) != owner || p.IsReserved() || p.IsOrphaned() {
				continue
			}
		}
		if req.PageToken != "" && p.SandboxID <= req.PageToken {
			continue
		}
		matched = append(matched, p)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].SandboxID < matched[j].SandboxID })

	next := ""
	if len(matched) > req.Limit {
		matched = matched[:req.Limit]
		next = matched[len(matched)-1].SandboxID
	}
	return cluster.PlacementPageResponse{Placements: matched, NextPageToken: next, Authoritative: true}
}
