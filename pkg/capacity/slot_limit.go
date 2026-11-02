package capacity

import "slices"

// SlotLimit is a per-node network-slot pool that the admitter counts itself,
// from its own reservations, for sandboxes whose slot no store table tracks:
// the docker engine's sandbox bridge, where dockerd attaches one veth per
// running container and the kernel refuses the 1,024th.
//
// Every reservation whose runtime the pool serves holds one slot, warm-pool
// parks (park:*) included. That makes the count exact without a new record:
// a create reserves before the container exists and releases on any failure,
// destroy and stop release (dockerd tears the veth down on stop, and
// StartSandbox re-admits), and after a restart ReplayReservations rebuilds it
// from the store.
type SlotLimit struct {
	// Name is the SlotPool name advertised in Snapshot.SlotPools.
	Name string
	// Pool names the pool in operator words; it leads the refusal message.
	Pool string
	// Runtimes are the runtimes whose sandboxes take a slot.
	Runtimes []string
	// Total is how many slots the pool has; <= 0 turns the limit off.
	Total int
}

// serves reports whether a reservation for runtime takes a slot. A create
// always carries its resolved runtime by the time it is admitted.
func (l SlotLimit) serves(runtime string) bool {
	return l.Total > 0 && slices.Contains(l.Runtimes, runtime)
}

// SetSlotLimit installs the admitter-counted slot pool (Total <= 0 removes
// it) and recounts the reservations already held, so it is correct whether
// it runs before or after ReplayReservations.
func (a *Admitter) SetSlotLimit(l SlotLimit) {
	l.Runtimes = slices.Clone(l.Runtimes)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.slotLimit = l
	a.slotUsed, a.slotParked = 0, 0
	for id, req := range a.reservations {
		if !l.serves(req.Runtime) {
			continue
		}
		a.slotUsed++
		if _, ok := a.reclaimable[id]; ok {
			a.slotParked++
		}
	}
}

// SlotPool reports the admitter-counted pool as a capacity report carries it;
// ok=false when none is set. A warm slot ready in its pool counts as free: a
// create adopts it or reclaims it, so it never needs a new port.
func (a *Admitter) SlotPool() (SlotPool, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.slotLimit
	if l.Total <= 0 {
		return SlotPool{}, false
	}
	return SlotPool{
		Name:     l.Name,
		Runtimes: slices.Clone(l.Runtimes),
		Total:    l.Total,
		Free:     max(l.Total-a.slotUsed+a.slotParked, 0),
	}, true
}
