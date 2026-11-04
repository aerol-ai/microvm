package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Hold enforcement has one lifecycle across every writer (PR #622 review
// 3). A sandbox's hold record and everything enforced from it (the host
// hold DROP, the gateway's hold block, a mediator's block-all) change only
// under the sandbox's hold lock (Service.egressHoldLocks), so a release
// that read a weaker reason can't lift the external blocks of a stronger
// hold that arrived meanwhile: the hold waits, then lands on top. The
// record is the truth; every external layer is derived from it.
//
// A block write that doesn't reach the gateway is not forgotten: the
// sandbox goes into egressBlockPending and its blocks are re-applied from
// the store until one write succeeds. A full Sync re-applies them after
// its replacement and fails while any is still pending, so the gateway is
// not reported ready on a state that is missing a hold.

// egressBlockPending is the set of sandboxes whose gateway blocks may differ
// from their record.
type egressBlockPending struct {
	mu  sync.Mutex
	ids map[string]bool
}

func (p *egressBlockPending) add(id string) {
	p.mu.Lock()
	if p.ids == nil {
		p.ids = map[string]bool{}
	}
	p.ids[id] = true
	p.mu.Unlock()
}

func (p *egressBlockPending) remove(id string) {
	p.mu.Lock()
	delete(p.ids, id)
	p.mu.Unlock()
}

func (p *egressBlockPending) list() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.ids))
	for id := range p.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// setGatewayBlock sends one block write to the gateway. A sandbox the
// gateway doesn't have is fine (the gateway keeps the write for its attach);
// any other failure leaves the sandbox pending.
func (s *Service) setGatewayBlock(ctx context.Context, id string, reason egress.BlockReason, on bool) error {
	err := s.egressGateway().SetBlocked(ctx, id, reason, on)
	if err == nil || errors.Is(err, egress.ErrNotAttached) {
		return nil
	}
	s.egressBlocksPending.add(id)
	return err
}

// retryPendingBlocks re-applies, from the store, the gateway blocks of every
// sandbox whose last block write failed. It reports the ones still failing.
func (s *Service) retryPendingBlocks(ctx context.Context) error {
	var errs []error
	for _, id := range s.egressBlocksPending.list() {
		unlock := s.egressHoldLocks.lock(id)
		err := s.reapplyBlocksLocked(ctx, id)
		unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		s.egressBlocksPending.remove(id)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("egress: gateway blocks not applied: %w", err)
	}
	return nil
}

// reapplyBlocksLocked sets a sandbox's gateway hold and quota blocks to what
// the store says now. Callers hold the sandbox's hold lock.
func (s *Service) reapplyBlocksLocked(ctx context.Context, id string) error {
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	held, err := s.egressHeld(ctx, sb)
	if err != nil {
		return err
	}
	gw := s.egressGateway()
	for _, b := range []struct {
		reason egress.BlockReason
		on     bool
	}{{egress.BlockHold, held}, {egress.BlockQuota, gatewayQuotaBlocked(sb)}} {
		if err := gw.SetBlocked(ctx, id, b.reason, b.on); err != nil && !errors.Is(err, egress.ErrNotAttached) {
			return err
		}
	}
	return nil
}

// gatewayQuotaBlocked reports whether the stored counters put the sandbox
// over its egress quota: the same test for a full Sync's specs, an attach,
// the blocks a retry re-applies, and the quota mirror itself
// (applyNetworkQuotaState's overOut). The counters and limits are stored
// before the mirror writes a quota block or lifts one, so a snapshot read
// after a write's sync token always holds the state that write enforced.
// The NetworkQuotaExceeded flag isn't used: it is stored only after the
// mirror's write, and a Sync between the two would drop a block its token
// claims to cover (PR #622 review 4 finding 4).
func gatewayQuotaBlocked(sb *models.Sandbox) bool {
	_, overOut := quotaOver(sb)
	return overOut
}

// egressHeld reports whether a sandbox has a hold recorded. A record that
// can't be read counts as held: every caller derives a block from it, and an
// unknown hold must never reopen a sandbox (review 3 finding 7). The error
// is returned too, for callers that report an apply as unconfirmed.
func (s *Service) egressHeld(ctx context.Context, sb *models.Sandbox) (bool, error) {
	if s.store == nil {
		return false, nil
	}
	st, err := s.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		return true, err
	}
	return st.HoldReason != "", nil
}
