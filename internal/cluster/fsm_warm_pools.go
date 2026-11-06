package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// API warm-pool entries in the Raft FSM (plans/agent-sandbox-feature-
// parity.md W1). An entry is fleet-wide operator config: one per image, no
// owner. Every server holds the whole set; a worker with a warm pool polls
// it from the server tier (warm_pools.go) and parks slots for it locally.
// Nothing about placement or ownership reads it, so an entry can never move
// a sandbox.
const (
	opPutWarmPool    opCode = 33 // create or replace one image's warm-pool entry
	opDeleteWarmPool opCode = 34 // remove one; deleting a missing entry is a no-op
)

// ErrWarmPoolLimit is a put of a new entry when models.MaxWarmPools already
// exist. Decided at apply time, so racing creates resolve the same way on
// every replica.
var ErrWarmPoolLimit = errors.New("cluster: warm pool limit reached")

// WarmPoolRecord is one replicated entry. Times come from the proposer's
// stamp, never the applier's clock, so replicas agree.
type WarmPoolRecord struct {
	Image           string `json:"image"`
	Depth           int    `json:"depth"`
	Generation      int64  `json:"generation"`
	CreatedUnixNano int64  `json:"created_unix_nano"`
	UpdatedUnixNano int64  `json:"updated_unix_nano"`
}

// sameSettings compares what a PUT sets, not the bookkeeping.
func (r WarmPoolRecord) sameSettings(o WarmPoolRecord) bool {
	return r.Depth == o.Depth
}

// warmPoolApplyResult is the leader FSM's answer to opPutWarmPool.
type warmPoolApplyResult struct {
	Pool    WarmPoolRecord
	Changed bool
}

func (f *placementFSM) applyPutWarmPoolLocked(cmd command) (any, error) {
	in := cmd.WarmPool
	if in == nil || strings.TrimSpace(in.Image) == "" {
		return nil, fmt.Errorf("placementFSM: opPutWarmPool requires an entry")
	}
	if f.warmPools == nil {
		f.warmPools = make(map[string]*WarmPoolRecord)
	}
	old, exists := f.warmPools[in.Image]
	if exists && old.sameSettings(*in) {
		return warmPoolApplyResult{Pool: *old}, nil
	}
	if !exists && len(f.warmPools) >= models.MaxWarmPools {
		return nil, fmt.Errorf("%w: at most %d warm pools may be configured", ErrWarmPoolLimit, models.MaxWarmPools)
	}
	rec := *in
	rec.Generation, rec.CreatedUnixNano = 1, cmd.StampUnixNano
	if exists {
		rec.Generation, rec.CreatedUnixNano = old.Generation+1, old.CreatedUnixNano
	}
	rec.UpdatedUnixNano = cmd.StampUnixNano
	f.warmPools[rec.Image] = &rec
	f.warmPoolsVersion = f.version
	return warmPoolApplyResult{Pool: rec, Changed: true}, nil
}

func (f *placementFSM) applyDeleteWarmPoolLocked(cmd command) error {
	in := cmd.WarmPool
	if in == nil || strings.TrimSpace(in.Image) == "" {
		return fmt.Errorf("placementFSM: opDeleteWarmPool requires an image")
	}
	if _, ok := f.warmPools[in.Image]; !ok {
		// Idempotent, and not a change: a worker's cursor stays current.
		return nil
	}
	delete(f.warmPools, in.Image)
	f.warmPoolsVersion = f.version
	return nil
}

// readWarmPools answers a read from this replica. Version is the Raft index
// of the last change (or of the snapshot this state was restored from); a
// reader that already holds it gets Unchanged and no list.
func (f *placementFSM) readWarmPools(req WarmPoolReadRequest) WarmPoolReadResponse {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := WarmPoolReadResponse{Version: f.warmPoolsVersion, Authoritative: true}
	if req.Since != 0 && req.Since == f.warmPoolsVersion {
		out.Unchanged = true
		return out
	}
	out.Pools = f.warmPoolsSnapshotLocked()
	return out
}

// warmPoolsSnapshotLocked is every entry, by image.
func (f *placementFSM) warmPoolsSnapshotLocked() []WarmPoolRecord {
	out := make([]WarmPoolRecord, 0, len(f.warmPools))
	for _, rec := range f.warmPools {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

// restoreWarmPoolsLocked loads a snapshot's entries. The snapshot's index
// becomes the version, so every cursor from before it refetches.
func (f *placementFSM) restoreWarmPoolsLocked(records []WarmPoolRecord, version uint64) {
	f.warmPools = make(map[string]*WarmPoolRecord, len(records))
	for _, r := range records {
		if strings.TrimSpace(r.Image) == "" {
			continue
		}
		rec := r
		f.warmPools[rec.Image] = &rec
	}
	f.warmPoolsVersion = version
}
