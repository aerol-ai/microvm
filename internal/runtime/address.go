package runtime

import (
	"context"
	"strings"
)

// AddressObserver is how a create learns its sandbox's address before the
// runtime finishes building the sandbox, and how anything keyed by that
// address is told before the runtime gives the address back.
//
// The egress gateway is the reason it exists. A hostname-filtered create
// attaches the sandbox to the gateway by address; a driver that knows the
// address early (a prepaid netns slot, a pause-netns slot, a Firecracker
// TAP slot) reports it so the attach overlaps the rest of the build instead
// of waiting for it (plans/egress-domain-filtering.md §8.2). A driver that
// learns the address only from the finished create (Docker's own IPAM)
// reports nothing, and the create attaches afterwards as before.
//
// It rides the create's (or destroy's) context, so drivers and callers that
// don't use it are untouched; a context without one makes both calls no-ops.
type AddressObserver interface {
	// AddressKnown reports the sandbox's address, at most once per create.
	// The driver calls it only after the request's network rules (the
	// block-all DROP of a hostname-filtered create) are installed on ip and
	// before the workload can run, and ip must be the address the create
	// returns: the observer may act on ip at once.
	AddressKnown(ip string)
	// ReleasingAddress is called once the workload can no longer send from
	// ip and before the driver gives ip back (a failed create's cleanup, a
	// destroy), so the address never reaches another sandbox while state
	// keyed by it for this one is left. It returns when that state is gone
	// or its removal is queued for retry.
	ReleasingAddress(ip string)
}

type addressObserverKey struct{}

// WithAddressObserver carries o on ctx for a runtime Create or Destroy.
func WithAddressObserver(ctx context.Context, o AddressObserver) context.Context {
	if o == nil {
		return ctx
	}
	return context.WithValue(ctx, addressObserverKey{}, o)
}

// AddressObserverFrom returns the observer ctx carries, or nil.
func AddressObserverFrom(ctx context.Context) AddressObserver {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(addressObserverKey{}).(AddressObserver)
	return o
}

// NotifyAddressKnown tells ctx's observer, if any, the sandbox's address.
func NotifyAddressKnown(ctx context.Context, ip string) {
	if ip = strings.TrimSpace(ip); ip == "" {
		return
	}
	if o := AddressObserverFrom(ctx); o != nil {
		o.AddressKnown(ip)
	}
}

// NotifyReleasingAddress tells ctx's observer, if any, that ip is about to
// be given back.
func NotifyReleasingAddress(ctx context.Context, ip string) {
	if ip = strings.TrimSpace(ip); ip == "" {
		return
	}
	if o := AddressObserverFrom(ctx); o != nil {
		o.ReleasingAddress(ip)
	}
}
