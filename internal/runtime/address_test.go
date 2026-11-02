package runtime

import (
	"context"
	"slices"
	"testing"
)

type recObserver struct{ known, released []string }

func (r *recObserver) AddressKnown(ip string)     { r.known = append(r.known, ip) }
func (r *recObserver) ReleasingAddress(ip string) { r.released = append(r.released, ip) }

// TestAddressObserverOnContext: the observer rides the context to the
// driver; without one, or for an empty address, the notifications are
// no-ops, so drivers call them unconditionally.
func TestAddressObserverOnContext(t *testing.T) {
	ctx := context.Background()
	if WithAddressObserver(ctx, nil) != ctx || AddressObserverFrom(ctx) != nil || AddressObserverFrom(nil) != nil { //nolint:staticcheck // nil-ctx tolerance is under test
		t.Fatal("no observer must leave the context alone and read back nil")
	}
	NotifyAddressKnown(ctx, "10.0.0.2")
	NotifyReleasingAddress(ctx, "10.0.0.2")
	o := &recObserver{}
	ctx = WithAddressObserver(ctx, o)
	if AddressObserverFrom(ctx) != o {
		t.Fatal("observer not carried")
	}
	NotifyAddressKnown(ctx, " 10.0.0.2 ")
	NotifyAddressKnown(ctx, "")
	NotifyReleasingAddress(ctx, "10.0.0.2")
	NotifyReleasingAddress(ctx, "  ")
	if !slices.Equal(o.known, []string{"10.0.0.2"}) || !slices.Equal(o.released, []string{"10.0.0.2"}) {
		t.Fatalf("known %v released %v", o.known, o.released)
	}
}
