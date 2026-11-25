package containerd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// A failed warm claim's leftover (errClaimLeftover). In the double failure
// the claim's container still runs in a network namespace the sandbox id
// holds: moving the namespace's owner back to the park failed, and so did
// removing the container. The pool keeps the slot and retries the removal
// (dockerpool pending_destroy.go), but it retries the park's container
// only: the namespace, its address and their rules stay with the sandbox
// id. Two things follow, and the set below handles both:
//
//   - A retried create with the same id that finds no free warm slot goes
//     cold, and the cold path's netns step hands it the namespace the id
//     holds: the one the claim's container still runs in. So while the id
//     is here, the cold path refuses it with errClaimLeftover, as the
//     claim did (Create).
//   - Nothing frees that namespace unless a retried create of the id
//     removes it as its leftover, or the daemon restarts. So when the
//     pool's retry finally removes the container, the driver frees it
//     too, once it is sure no container of the sandbox is left in it
//     (finishClaimLeftover).
//
// It lives only in memory: a restart drops the pool's retry list as well,
// and the boot purge and the netns reconcile cover both.

// claimLeftovers is the set of failed claims whose container the pool has
// not removed yet, by park slot id. The cold path asks it about every
// create, so n keeps that to one atomic load while the set is empty, which
// is all but always.
type claimLeftovers struct {
	n      atomic.Int32
	mu     sync.Mutex
	bySlot map[string]claimLeftover
}

// claimLeftover is one failed claim: the sandbox id it was for, and the
// park's address, which the namespace the id holds carries.
type claimLeftover struct {
	sandboxID string
	address   string
}

// remember records that slotID's container is the leftover of a failed
// claim for sandboxID. The caller remembers it before the slot reaches the
// pool's retry list, so the retry can never run first and leave the id
// remembered with nothing left to clear it.
func (l *claimLeftovers) remember(slotID, sandboxID, address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bySlot == nil {
		l.bySlot = make(map[string]claimLeftover)
	}
	if _, ok := l.bySlot[slotID]; !ok {
		l.n.Add(1)
	}
	l.bySlot[slotID] = claimLeftover{sandboxID: sandboxID, address: address}
}

// holds reports whether a failed claim for sandboxID still has its
// container on this node.
func (l *claimLeftovers) holds(sandboxID string) bool {
	if l.n.Load() == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.bySlot {
		if c.sandboxID == sandboxID {
			return true
		}
	}
	return false
}

// of returns slotID's failed claim, if it is one.
func (l *claimLeftovers) of(slotID string) (claimLeftover, bool) {
	if l.n.Load() == 0 {
		return claimLeftover{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.bySlot[slotID]
	return c, ok
}

// forget drops slotID once its container is gone.
func (l *claimLeftovers) forget(slotID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.bySlot[slotID]; ok {
		delete(l.bySlot, slotID)
		l.n.Add(-1)
	}
}

// netnsAddresser is a netns handoff that can say which address the slot a
// sandbox id holds has (netns.RuntimeHandoff).
type netnsAddresser interface {
	Address(ctx context.Context, sandboxID string) (string, error)
}

// finishClaimLeftover runs after destroyParked removed slotID's container.
// When that container was a failed claim's leftover, the namespace the
// sandbox id still holds is freed, in Destroy's order: the address's rules
// first, while the slot still holds the address, then the slot. Then the id
// is forgotten, and a cold create of it may go on.
//
// The namespace is freed only when it is really empty: no container of the
// sandbox is left on this node (every container put in a sandbox's
// namespace carries its id, by name or by label), and the slot the id
// holds still has the park's address. Otherwise the sandbox runs again (a
// retried create removed the leftover and claimed another slot), and its
// slot is its own: the id is forgotten and nothing is freed. A slot the id
// no longer holds was freed by that create already.
//
// A check that cannot be made is an error, and the id stays remembered:
// the pool keeps the slot and runs the whole teardown again, which is
// idempotent, so the check is retried with it.
func (d *Driver) finishClaimLeftover(ctx context.Context, slotID string) error {
	leftover, ok := d.claimLeftovers.of(slotID)
	if !ok {
		return nil
	}
	if err := d.freeClaimLeftoverNetns(ctx, leftover); err != nil {
		return fmt.Errorf("free the network namespace of failed claim for %s: %w", leftover.sandboxID, err)
	}
	d.claimLeftovers.forget(slotID)
	return nil
}

func (d *Driver) freeClaimLeftoverNetns(ctx context.Context, leftover claimLeftover) error {
	addresser, ok := d.netns.(netnsAddresser)
	if d.netns == nil || !ok {
		return nil
	}
	held, err := addresser.Address(ctx, leftover.sandboxID)
	if err != nil {
		return err
	}
	if held == "" || held != leftover.address {
		return nil
	}
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	found, err := client.ListContainers(ctx, "id=="+leftover.sandboxID, "labels."+sandboxIDLabelKey+"=="+leftover.sandboxID)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		d.logger.Info("containerd warm claim: the failed claim's container is gone and the sandbox runs again; its network namespace stays with it",
			"sandbox_id", leftover.sandboxID, "container_ip", held)
		return nil
	}
	if !d.clearsOnRelease() {
		_ = d.ClearNetworkRules(held)
	}
	if err := d.netns.Release(ctx, leftover.sandboxID); err != nil {
		return err
	}
	d.logger.Info("containerd warm claim: freed the network namespace a failed claim left under the sandbox id",
		"sandbox_id", leftover.sandboxID, "container_ip", held)
	return nil
}

// refusesClaimLeftover reports whether a create of sandboxID must not go
// cold, because a failed claim's container may still run in the namespace
// the id holds.
func (d *Driver) refusesClaimLeftover(sandboxID string) bool {
	return d.claimLeftovers.holds(sandboxID)
}
