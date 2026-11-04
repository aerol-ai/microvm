package firecracker

import (
	"context"
	"sync"
)

// vmGate lets one operation at a time hold a running sandbox's VM: Stop, or
// a snapshot that has the guest's root filesystem frozen. Without it a Stop
// arriving mid-snapshot would save the VM with its filesystem frozen, and
// the sandbox would come back from Start unable to write until the guest's
// safety timer thawed it. Waiting honours the caller's context. The zero
// value is ready to use.
type vmGate struct {
	mu   sync.Mutex
	held map[string]chan struct{}
}

// lock waits until no one holds sandboxID's gate, takes it, and returns the
// release.
func (g *vmGate) lock(ctx context.Context, sandboxID string) (func(), error) {
	for {
		g.mu.Lock()
		busy, held := g.held[sandboxID]
		if !held {
			if g.held == nil {
				g.held = make(map[string]chan struct{})
			}
			done := make(chan struct{})
			g.held[sandboxID] = done
			g.mu.Unlock()
			return func() {
				g.mu.Lock()
				delete(g.held, sandboxID)
				g.mu.Unlock()
				close(done)
			}, nil
		}
		g.mu.Unlock()
		select {
		case <-busy:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
