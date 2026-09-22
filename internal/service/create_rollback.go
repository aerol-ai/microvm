package service

import (
	"context"
	"sync"
	"time"
)

// createRollbackTimeout is how long a create-path rollback gets to undo what
// the create committed. A var so tests can reach its expiry without waiting it
// out.
var createRollbackTimeout = 30 * time.Second

// rollbackBudget hands a create-path rollback a DETACHED cleanup context whose
// clock starts when the rollback begins — not when the create did.
//
// Detached, because the request that failed is often the reason for the
// failure: a timed-out or cancelled create must still be able to delete the
// row it committed and the runtime it started. Started lazily, because a
// create can legitimately run far longer than the rollback budget — a cold
// WASM module pull and compile, a large image, a Firecracker cold boot, all
// inside a 600s create default. A budget taken at function entry had usually
// expired by the time a late step failed, so RollbackSandboxCreate could not
// open its transaction and the row stayed "started" after its runtime was torn
// down. The runtime create paths share this so the mistake cannot be made
// again in one of them.
type rollbackBudget struct {
	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc
}

// Context returns the rollback's budget, starting it on first use. Every step
// of one rollback shares it.
func (b *rollbackBudget) Context() context.Context {
	b.once.Do(func() {
		b.ctx, b.cancel = context.WithTimeout(context.Background(), createRollbackTimeout)
	})
	return b.ctx
}

// Release frees the budget's timer. Safe on a budget that was never used.
func (b *rollbackBudget) Release() {
	// Synchronizes with the Do that set cancel, so reading it is race-free.
	b.once.Do(func() {})
	if b.cancel != nil {
		b.cancel()
	}
}
