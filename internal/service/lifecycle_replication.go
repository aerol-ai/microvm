package service

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// lifecycleReplicationLag is how far the replicated lifecycle may fall behind
// a keep-alive. See replicateRecoveryLifecycle.
const lifecycleReplicationLag = time.Minute

// replicateRecoveryLifecycle replicates a sandbox's new lifecycle for a
// failover recreate, the one reader of the replicated copy
// (replicateRecoverySpecPatch), and lets that copy lag a keep-alive.
//
// An E2B keep-alive stores its deadline as an age: time since create plus the
// timeout (lifecycleForTimeout). So every call moves StopAtAge or DestroyAtAge
// later by the time since the last call, and on a failover sandbox each call
// was a Raft entry every server syncs, for a copy only a failover reads. The
// write is skipped when the only change is an age timer moved later by at most
// lifecycleReplicationLag and the replicated deadline is still at least that
// far away (replicatedLifecycleCurrent). After a failover the sandbox then
// stops or is deleted at most a minute before the deadline the last keep-alive
// set, never after it. Every other change writes as before: a timer turned on
// or off or moved earlier, an idle or exit timer, destroy_at, serverless.
//
// Ages count from created_at, and a failover recreate keeps the first create
// time (persistSandboxCreate), so the replicated deadline is the same on
// every node.
//
// The decision is made on a copy no older than this node's last spec write
// (writeReplicatedSpec). Before that, on a worker, the call right after a
// write could read a follower's copy from before it and write again: live
// (UC-704) 2 entries for 100 calls in 5 s instead of 1.
func (s *Service) replicateRecoveryLifecycle(ctx context.Context, id string, sb *models.Sandbox, lc models.Lifecycle) {
	sb, ok := s.recoverySpecWanted(ctx, id, sb)
	if !ok {
		return
	}
	var createdAt time.Time
	if sb != nil {
		createdAt = sb.CreatedAt
	}
	s.replicateSpecPatchUnless(ctx, id, func(spec *models.CreateSandboxRequest) {
		spec.Lifecycle = &lc
	}, func(spec *models.CreateSandboxRequest) bool {
		return replicatedLifecycleCurrent(spec.Lifecycle, lc, createdAt, time.Now())
	})
}

// replicatedLifecycleCurrent reports whether the replicated lifecycle may
// stand in for next: equal but for StopAtAge and DestroyAtAge, and each of
// those either unchanged or moved later by at most lifecycleReplicationLag
// with its replicated deadline still at least that far from now.
func replicatedLifecycleCurrent(replicated *models.Lifecycle, next models.Lifecycle, createdAt, now time.Time) bool {
	if replicated == nil || createdAt.IsZero() {
		return false
	}
	rest := func(l models.Lifecycle) []byte {
		l.StopAtAge, l.DestroyAtAge = 0, 0
		b, err := json.Marshal(l)
		if err != nil {
			return nil
		}
		return b
	}
	a, b := rest(*replicated), rest(next)
	if a == nil || !bytes.Equal(a, b) {
		return false
	}
	return ageTimerCurrent(replicated.StopAtAge, next.StopAtAge, createdAt, now) &&
		ageTimerCurrent(replicated.DestroyAtAge, next.DestroyAtAge, createdAt, now)
}

// ageTimerCurrent is replicatedLifecycleCurrent for one age timer (0: off).
func ageTimerCurrent(replicated, next time.Duration, createdAt, now time.Time) bool {
	switch {
	case replicated == next:
		return true
	case replicated == 0 || next == 0 || next < replicated:
		return false
	case next-replicated > lifecycleReplicationLag:
		return false
	default:
		return createdAt.Add(replicated).Sub(now) >= lifecycleReplicationLag
	}
}
