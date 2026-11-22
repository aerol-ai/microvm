package taphost

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Slot is one Firecracker guest's network slot: its TAP device, the /30
// the device routes, the host's and the guest's addresses on it, and the
// guest's vsock CID. The TAP pool (internal/network/tap) hands slots out of
// SQLite; GuestMAC is an optional host-neighbor override used by snapshot
// restores whose guest NIC MAC is frozen in snapshot state.
type Slot struct {
	TapName  string
	CIDR     string
	HostIP   string
	GuestIP  string
	VsockCID uint32
	GuestMAC string
}

// NamePrefix starts every TAP device's name: fctap0, fctap1, ...
const NamePrefix = "fctap"

// MaxPoolSize is the TAP pool's cap (tap.Pool.Seed refuses more).
const MaxPoolSize = 10000

// firstVsockCID is slot 0's vsock CID: 0, 1 and 2 are the hypervisor's,
// the reserved CID and the host's.
const firstVsockCID = 3

// SlotAt is slot index of a pool laid out from baseCIDR with poolSize
// slots, exactly as tap.Pool.Seed lays it out (a /30 per slot, the host
// on .1 and the guest on .2; TestSlotAtMatchesSeed pins the two
// together). The root helper (privilege mode split) works a TAP's
// addresses out from its name with this, from its own settings, so the
// agent names a TAP and nothing else.
func SlotAt(baseCIDR string, poolSize, index int) (Slot, error) {
	p, err := netip.ParsePrefix(baseCIDR)
	if err != nil || !p.Addr().Is4() {
		return Slot{}, fmt.Errorf("tap slot: base %q is not an IPv4 CIDR", baseCIDR)
	}
	if poolSize <= 0 || poolSize > MaxPoolSize {
		return Slot{}, fmt.Errorf("tap slot: pool size %d: want 1 to %d", poolSize, MaxPoolSize)
	}
	if 4*poolSize > 1<<(32-p.Bits()) {
		return Slot{}, fmt.Errorf("tap slot: base %s holds fewer than %d slots", baseCIDR, poolSize)
	}
	// MaxPoolSize also bounds index on its own, before it narrows to a
	// uint32 below.
	if index < 0 || index >= poolSize || index >= MaxPoolSize {
		return Slot{}, fmt.Errorf("tap slot: index %d is outside the pool of %d", index, poolSize)
	}
	base := p.Masked().Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	at := func(delta uint32) netip.Addr {
		n := v + 4*uint32(index) + delta
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
	return Slot{
		TapName:  NamePrefix + strconv.Itoa(index),
		CIDR:     at(0).String() + "/30",
		HostIP:   at(1).String(),
		GuestIP:  at(2).String(),
		VsockCID: firstVsockCID + uint32(index),
	}, nil
}

// IndexOf is the slot index a TAP name holds: NamePrefix and a decimal
// index with no sign and no leading zero, below poolSize. Anything else is
// not one of the pool's TAPs.
func IndexOf(name string, poolSize int) (int, bool) {
	digits, ok := strings.CutPrefix(name, NamePrefix)
	if !ok || digits == "" || len(digits) > 5 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n >= poolSize || poolSize > MaxPoolSize {
		return 0, false
	}
	return n, true
}
