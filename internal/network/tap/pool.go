// Package tap manages the per-host pool of (TAP-device, host-IP, guest-IP,
// /30-CIDR, vsock-CID) slots that Firecracker microVMs claim at create
// time. The state lives in SQLite (firecracker_tap_pool table); this
// package owns the seed + allocation policy and exposes a typed API
// over the raw store CRUD.
//
// What lives here vs. internal/store:
//
//   - internal/store: schema, raw CRUD, partial unique index, idempotency
//     primitives. The load-bearing transactional substrate. Touching this
//     triggers pr-review.md §5 (TCP-host-port-pool & L4-bootstrap fragility
//     class) — the indexes are the contract.
//
//   - this package: policy on top of those primitives. Computing the next
//     /30 from a base CIDR, picking the next vsock CID, naming TAP devices
//     ("fctapN"), validating SeedConfig. No SQL, no transactions of its
//     own — the store is the boundary.
//
// What does NOT live here yet: actual host-side TAP device manipulation
// (`ip link add fctap0 type tap`, `ip addr add 172.16.0.1/30 dev fctap0`,
// `ip link set fctap0 up`). The first cut wires only the *allocation
// bookkeeping* — the act of creating the slot row and reserving the IP.
// Real `ip` invocations are the runtime driver's job and land in a
// follow-up file (`tap/host.go`) once Driver.Create needs them. Keeping
// allocation separate from realization mirrors the host-port pool
// (allocation in store; bind() in caddy-l4) and lets each step be tested
// in isolation.
package tap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// vsockCIDStart is the lowest vsock CID we hand out. CIDs 0/1/2 are
// reserved by the virtio-vsock spec for hypervisor / host / any —
// allocating in that range corrupts the host's vsock device table. The
// store layer also enforces this; duplication here gives the seed loop
// a fast-fail before it ever hits SQLite.
const vsockCIDStart uint32 = 3

// tapNamePrefix is the prefix used for synthesized TAP device names.
// Kept short (fctap + index) because Linux caps interface names at 15
// chars (IFNAMSIZ); fctapN with N up to 9999 is comfortably inside.
const tapNamePrefix = "fctap"

// SeedConfig describes the network plan the pool is laid out from.
// BaseCIDR is carved into /30 subnets, one per slot; PoolSize is the
// number of /30s to produce (and therefore the maximum number of
// concurrent Firecracker sandboxes per host). Both fields are required.
//
// Why /30 specifically: a /30 holds 4 addresses — network, host-side TAP
// IP, guest IP, broadcast. That's the minimum that lets the host route
// to the guest. /31 (RFC 3021) would also work but is unsupported by
// some older `ip` tooling; /30 is the safe default.
type SeedConfig struct {
	BaseCIDR string
	PoolSize int
}

// Pool is the policy layer. Holds a *store.Store reference; the zero
// value is not usable.
type Pool struct {
	st *store.Store
}

// New returns a Pool. The store must already be open. The Pool does not
// take ownership; the caller is responsible for the store's lifetime.
func New(st *store.Store) *Pool {
	return &Pool{st: st}
}

// Seed lays out PoolSize slots from BaseCIDR. Idempotent: a re-Seed
// with the same config is a no-op (the underlying ON CONFLICT(tap_name)
// DO NOTHING in the store path handles this). A re-Seed with a DIFFERENT
// BaseCIDR or PoolSize will silently keep the original layout for any
// pre-existing tap_name rows and add the new ones — operators must
// migrate manually (drop + reseed) if they need to shrink or relocate
// the pool. This is by design: rewriting an in-use slot would orphan
// running sandboxes.
func (p *Pool) Seed(ctx context.Context, cfg SeedConfig, now time.Time) error {
	if cfg.PoolSize <= 0 {
		return errors.New("tap: SeedConfig.PoolSize must be > 0")
	}
	if cfg.PoolSize > 10000 {
		// Cap. Past this we exceed IFNAMSIZ for the fctapN name AND
		// burn through the vsock CID space quickly. 10k slots on one
		// host is already absurd; surface the misconfiguration loudly.
		return fmt.Errorf("tap: SeedConfig.PoolSize=%d exceeds 10000 cap", cfg.PoolSize)
	}
	ip, network, err := net.ParseCIDR(cfg.BaseCIDR)
	if err != nil {
		return fmt.Errorf("tap: parse BaseCIDR %q: %w", cfg.BaseCIDR, err)
	}
	ip = ip.To4()
	if ip == nil {
		return errors.New("tap: BaseCIDR must be IPv4 (IPv6 vsock pool is a future axis)")
	}
	// Confirm BaseCIDR is large enough to hold PoolSize /30s. Each /30
	// is 4 addresses; PoolSize * 4 addresses must fit in the base
	// network's address span.
	ones, bits := network.Mask.Size()
	available := 1 << (bits - ones)
	needed := cfg.PoolSize * 4
	if available < needed {
		return fmt.Errorf("tap: BaseCIDR %s holds %d addresses but pool needs %d (size %d × 4)",
			cfg.BaseCIDR, available, needed, cfg.PoolSize)
	}
	base := network.IP.To4()
	if base == nil {
		return errors.New("tap: base IP is not IPv4")
	}

	for i := 0; i < cfg.PoolSize; i++ {
		offset := uint32(i) * 4
		hostIP := addOffset(base, offset+1)
		guestIP := addOffset(base, offset+2)
		subnet := addOffset(base, offset).String() + "/30"
		slot := store.FirecrackerTapSlot{
			TapName:  fmt.Sprintf("%s%d", tapNamePrefix, i),
			CIDR:     subnet,
			HostIP:   hostIP.String(),
			GuestIP:  guestIP.String(),
			VsockCID: vsockCIDStart + uint32(i),
		}
		if err := p.st.SeedFirecrackerTapSlot(ctx, slot, now); err != nil {
			return fmt.Errorf("tap: seed slot %d: %w", i, err)
		}
	}
	return nil
}

// addOffset returns base + delta as an IPv4 net.IP. Caller must have
// already To4()-normalized base. Used by Seed to walk /30 boundaries
// without dragging in math/big or a CIDR library.
func addOffset(base net.IP, delta uint32) net.IP {
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += delta
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Slot is the Pool-level view of an allocated network slot. Mirrors
// store.FirecrackerTapSlot but lives in this package so callers (the
// Firecracker driver) depend on the policy layer's type, not the
// store's. SandboxID is always non-empty here — a Slot returned by the
// pool is always claimed. GuestMAC is an optional host-neighbor override
// used by snapshot restores whose guest NIC MAC is frozen in snapshot state.
type Slot struct {
	TapName  string
	CIDR     string
	HostIP   string
	GuestIP  string
	VsockCID uint32
	GuestMAC string
}

// Allocate claims a slot for sandboxID. Idempotent (re-Allocate for the
// same sandbox returns the existing slot, not a new one). Returns
// store.ErrNoFreeFirecrackerTapSlot when the pool is exhausted — the
// runtime driver translates that into a 503-ish admission error so the
// operator sees "pool exhausted" rather than a confusing timeout.
func (p *Pool) Allocate(ctx context.Context, sandboxID string, now time.Time) (*Slot, error) {
	raw, err := p.st.AllocateFirecrackerTapSlot(ctx, sandboxID, now)
	if err != nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// Get returns the slot owned by sandboxID, or nil. Used by Inspect /
// Destroy paths. Errors from the underlying store bubble up untouched.
func (p *Pool) Get(ctx context.Context, sandboxID string) (*Slot, error) {
	raw, err := p.st.GetFirecrackerTapSlotBySandbox(ctx, sandboxID)
	if err != nil || raw == nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// Release returns a sandbox's slot to the pool. Idempotent.
func (p *Pool) Release(ctx context.Context, sandboxID string) error {
	return p.st.ReleaseFirecrackerTapSlot(ctx, sandboxID)
}

// Transfer re-keys a claimed slot from fromID to toID. Used by the
// Firecracker warm-VMM pool: warm slots allocate TAPs under their pool slot id,
// then a create transfers that same TAP to the sandbox id on warm hit.
func (p *Pool) Transfer(ctx context.Context, fromID, toID string, now time.Time) (*Slot, error) {
	raw, err := p.st.TransferFirecrackerTapSlot(ctx, fromID, toID, now)
	if err != nil || raw == nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// Stats reports current occupancy. Used by /healthz and the admission
// controller — a near-empty pool blocks new Firecracker creates upstream
// of the failing Allocate call.
type Stats = store.FirecrackerTapPoolStats

func (p *Pool) Stats(ctx context.Context) (Stats, error) {
	return p.st.GetFirecrackerTapPoolStats(ctx)
}

func slotFromStore(s *store.FirecrackerTapSlot) *Slot {
	if s == nil {
		return nil
	}
	return &Slot{
		TapName:  s.TapName,
		CIDR:     s.CIDR,
		HostIP:   s.HostIP,
		GuestIP:  s.GuestIP,
		VsockCID: s.VsockCID,
	}
}
