package service

import (
	"context"
	"errors"
	"sync"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
)

// egressBlockTracker records which sandboxes had a gateway block (hold,
// quota) change while a full Sync was being built and applied. The Sync
// replaces the gateway's state with specs read from the store at its start,
// so a change landing in between would be undone; the changed sandboxes are
// re-applied from the store once the Sync is done (review 2 finding 2).
// Block writers aren't held off meanwhile: a hold must take effect at once.
type egressBlockTracker struct {
	mu      sync.Mutex
	active  bool
	changed map[string]bool
}

func (t *egressBlockTracker) start() {
	t.mu.Lock()
	t.active, t.changed = true, map[string]bool{}
	t.mu.Unlock()
}

func (t *egressBlockTracker) stop() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = false
	out := make([]string, 0, len(t.changed))
	for id := range t.changed {
		out = append(out, id)
	}
	t.changed = nil
	return out
}

func (t *egressBlockTracker) seen(id string) {
	t.mu.Lock()
	if t.active {
		t.changed[id] = true
	}
	t.mu.Unlock()
}

// egressBlockSeen notes a block change for a Sync in progress. Writers call
// it after recording the change in the store and before telling the
// gateway.
func (s *Service) egressBlockSeen(id string) { s.egressBlocks.seen(id) }

// reapplyBlocks sets each sandbox's gateway hold and quota blocks to what
// the store says now.
func (s *Service) reapplyBlocks(ctx context.Context, ids []string) {
	gw := s.egressGateway()
	for _, id := range ids {
		sb, err := s.store.Get(ctx, id)
		if err != nil {
			continue
		}
		st, err := s.store.GetEgressState(ctx, id)
		if err != nil {
			continue
		}
		for reason, on := range map[egress.BlockReason]bool{
			egress.BlockHold:  st.HoldReason != "",
			egress.BlockQuota: gatewayQuotaBlocked(sb),
		} {
			if err := gw.SetBlocked(ctx, id, reason, on); err != nil && !errors.Is(err, egress.ErrNotAttached) {
				s.logger.Warn("egress: block not re-applied after the full sync", "sandbox_id", id, "error", err)
			}
		}
	}
}

// gatewayQuotaBlocked reports whether the stored row puts the sandbox over
// its egress quota: the same test for a full Sync's specs and the blocks it
// re-applies, so the two never disagree.
func gatewayQuotaBlocked(sb *models.Sandbox) bool {
	return sb.NetworkQuotaExceeded && sb.NetworkBytesOutLimit > 0 && sb.NetworkBytesOut >= sb.NetworkBytesOutLimit
}

// egressHeld reports whether a sandbox has any hold recorded.
func (s *Service) egressHeld(ctx context.Context, sb *models.Sandbox) bool {
	if s.store == nil {
		return false
	}
	st, err := s.store.GetEgressState(ctx, sb.ID)
	return err == nil && st.HoldReason != ""
}
