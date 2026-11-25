package containerd

import "context"

// Giving an address back: the one owner of "this holder is gone".
//
// An address's firewall rules and its netns slot go together, and only the
// slot's current holder may give them back. Every path that ends a holder
// calls giveBack, which asks the netns pool to check the holder, clear the
// rules and free the slot as one step under the slot's lock
// (netns.RuntimeHandoff.ReleaseOwned):
//
//	path                                       holder      rules cleared
//	Destroy of a sandbox with a row            sandbox id  its own lists
//	Destroy of a failed claim's leftover       sandbox id  the whole address
//	a failed cold create's undo                sandbox id  the create's lists, if put on early
//	destroyParked: pool teardown, its retry,   park id     the whole address
//	  boot purge, a failed claim's discard
//	a failed claim's discard, after the above  sandbox id  the whole address
//	a failed claim's free step (pool retry)    sandbox id  the whole address, only at
//	                                                       the claim's own address
//	a park that failed half way                park id     the whole address
//	boot reconcile (netns Pool.Reconcile)      dead owner  the whole address (SetAddressClearer)
//
// Rule clears used to run before the release, outside the lock, so two
// paths giving the same address back (a leftover's Destroy and the pool's
// retry) could clear it after the other had freed it and the pool had
// handed it to a new sandbox, removing that sandbox's rules. Under the lock
// the holder is checked again, so a second caller finds nothing to do.
// TestGiveBackOwnsEveryRuleClearAndRelease fails on a path that clears
// rules or releases a slot by itself.
//
// In privilege mode split the slot's release clears every rule of the
// address itself (CreateRules.ClearsOnRelease), so no clear is passed.
// Without the native pool (no netns handoff) an address is the
// container's, freed with it; only its rules are this driver's.

// ownedReleaser is a netns handoff that gives an address back as one step
// under the slot's lock (netns.RuntimeHandoff).
type ownedReleaser interface {
	ReleaseOwned(ctx context.Context, sandboxID, want string, clear func(ip string)) (string, error)
}

// poolAddressChecker tells whether an address is one of the pool's
// (netns.RuntimeHandoff.AddressInPool).
type poolAddressChecker interface {
	AddressInPool(ctx context.Context, ip string) (bool, error)
}

// giveBackReq is one address given back.
type giveBackReq struct {
	// owner is the id the slot is held under: a sandbox id or a park id.
	owner string
	// known is the address the caller knows for owner ("" for none). With
	// the pool, the slot's own address is cleared, not this.
	known string
	// match gives back only a slot with the known address: for a caller
	// that holds no create lease on owner (a failed claim's free step).
	match bool
	// notInPool clears known when owner holds no slot and no slot of the
	// pool records known: a sandbox made before the native pool was turned
	// on, whose address went with its container.
	notInPool bool
	// clear clears an address's rules; nil for none.
	clear func(ip string)
}

// testHookGiveBack runs as giveBack starts, with the owner. Tests order two
// paths with it.
var testHookGiveBack func(owner string)

// giveBack gives back the address req.owner holds and answers it ("" when
// there was nothing to give back). An error is a read of the pool that
// failed: nothing was cleared or freed.
func (d *Driver) giveBack(ctx context.Context, req giveBackReq) (string, error) {
	if testHookGiveBack != nil {
		testHookGiveBack(req.owner)
	}
	clear := req.clear
	if d.netns == nil {
		if clear != nil && req.known != "" {
			clear(req.known)
		}
		return req.known, nil
	}
	if d.clearsOnRelease() {
		clear = nil
	}
	if req.owner == "" || (req.match && req.known == "") {
		return "", nil
	}
	want := ""
	if req.match {
		want = req.known
	}
	r, ok := d.netns.(ownedReleaser)
	if !ok {
		// A handoff without ReleaseOwned (tests' stand-ins): the same
		// steps, without the slot lock.
		if clear != nil && req.known != "" {
			clear(req.known)
		}
		return req.known, d.netns.Release(ctx, req.owner)
	}
	ip, err := r.ReleaseOwned(ctx, req.owner, want, clear)
	if ip != "" || err != nil || !req.notInPool || clear == nil || req.known == "" {
		return ip, err
	}
	if c, ok := d.netns.(poolAddressChecker); ok {
		inPool, err := c.AddressInPool(ctx, req.known)
		if err != nil || inPool {
			return "", err
		}
		clear(req.known)
		return req.known, nil
	}
	return "", nil
}

// wholeAddress clears every rule of an address, for a holder whose lists
// no row records (clearAddressRules).
func (d *Driver) wholeAddress(ip string) { _ = d.clearAddressRules(ip) }

// ClearAddressRules clears every rule keyed by containerIP (netrules
// ClearAddress, or the block rules for a firewall without it). The netns
// pool's boot reconcile gives a dead holder's address back with it in
// single mode (netns Pool.SetAddressClearer).
func (d *Driver) ClearAddressRules(containerIP string) error { return d.clearAddressRules(containerIP) }
