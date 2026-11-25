package containerd

import (
	"context"
	"errors"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
)

// The event path's owner check (service ipClaimedByOther): a stop or
// destroy event that comes late, for a sandbox whose address went back
// and was handed on, must not clear the new holder's rules. The store
// already sees a holder once its netns slot row records the address. What
// it cannot see is a slot still being built: in privilege mode split a
// cold create's rules go on with the namespace (CreateRules.FoldsIntoBuild),
// inside the build, before the row records the address CNI gave it. IPOwner
// answers from the same slot rows, plus that one case: while a slot is
// being built and nothing records the address, the owner is unknown, and
// the late event clears nothing (a rule left behind fails closed and the
// next pass clears it).
//
// The Docker driver answers from dockerd's live network list
// (pkg/docker ipowner.go), which names parked slots as no sandbox's. Here
// the netns slot rows are the live view, and they name a parked slot by
// its park id, as the store's own claimant list does, so the two agree.

var _ sbruntime.IPOwnerResolver = (*Driver)(nil)

// errAddressBeingBuilt is IPOwner's answer while a slot is being built
// with its rules folded in, and no slot records the address yet.
var errAddressBeingBuilt = errors.New("containerd: a netns slot is being built; its address is not recorded yet")

// addressHolderReader reads who holds an address in the netns pool
// (netns.RuntimeHandoff.AddressHolder).
type addressHolderReader interface {
	AddressHolder(ctx context.Context, ip string) (holder string, building bool, err error)
}

// IPOwner reports which sandbox (or park) holds ip in the netns pool, ""
// for none. Without the native pool it has no view (ErrNoIPOwnerView). One
// store read; the event path only.
func (d *Driver) IPOwner(ctx context.Context, ip string) (string, error) {
	r, ok := d.netns.(addressHolderReader)
	if d.netns == nil || !ok {
		return "", sbruntime.ErrNoIPOwnerView
	}
	holder, building, err := r.AddressHolder(ctx, ip)
	if err != nil {
		return "", err
	}
	if holder == "" && building && d.foldsRulesIntoBuild() {
		return "", errAddressBeingBuilt
	}
	return holder, nil
}

// foldsRulesIntoBuild reports whether a cold create's rules go on inside
// its namespace build (privilege mode split).
func (d *Driver) foldsRulesIntoBuild() bool {
	cr := d.createRules()
	return cr != nil && cr.FoldsIntoBuild()
}
