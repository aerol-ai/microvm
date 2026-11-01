package capacity

import (
	"errors"
	"strings"
)

// Slot pools are the per-node limits that are not CPU, memory or disk: each
// running (or stopped) sandbox of a runtime holds one slot until it is
// destroyed — a containerd netns (veth + bridge port + address), a
// Firecracker TAP device with its /30 and vsock CID, a WASM instance under
// SB_WASM_MAX_INSTANCES. A host can have CPU and memory to spare and still be
// full for a runtime because its pool is, which is what a bank density run
// found: every metal worker stopped at 256 containerd and 256 Firecracker
// sandboxes while admission still had room.

// SlotPoolExhaustedError is the error a bounded per-node slot pool returns
// when it has no free slot. It is a capacity refusal, not a fault: errors.Is
// matches ErrCapacityExceeded, so every surface answers it like any other
// admission refusal (503 with Retry-After), the SDKs retry it, and cluster
// placement can send the retry to a node that still has slots.
//
// Pools declare one package-level value each (store.ErrNoFreeContainerNetnsSlot,
// store.ErrNoFreeFirecrackerTapSlot, ...), so errors.Is against that value
// keeps working by identity.
type SlotPoolExhaustedError struct {
	// Pool names the exhausted pool in operator words ("container netns
	// pool"); it leads the message so a log line says which limit was hit.
	Pool string
}

// NewSlotPoolExhausted returns the exhaustion error for the named pool.
func NewSlotPoolExhausted(pool string) *SlotPoolExhaustedError {
	return &SlotPoolExhaustedError{Pool: strings.TrimSpace(pool)}
}

func (e *SlotPoolExhaustedError) Error() string {
	pool := "slot pool"
	if e != nil && e.Pool != "" {
		pool = e.Pool
	}
	return pool + ": no free slot (" + ErrCapacityExceeded.Error() + ")"
}

// Unwrap makes errors.Is(err, ErrCapacityExceeded) true, which is the whole
// classification contract: no API surface needs to know slot pools exist.
func (e *SlotPoolExhaustedError) Unwrap() error { return ErrCapacityExceeded }

// SlotPoolExhausted reports whether err is a slot-pool refusal and, if so,
// which pool refused.
func SlotPoolExhausted(err error) (string, bool) {
	var e *SlotPoolExhaustedError
	if errors.As(err, &e) && e != nil {
		return e.Pool, true
	}
	return "", false
}

// Slot pool names advertised in Snapshot.SlotPools. Placement matches pools by
// Runtimes, not by name; the names are for operators and dashboards.
const (
	SlotPoolContainerNetns = "container_netns"
	SlotPoolFirecrackerTap = "firecracker_tap"
	SlotPoolWasmInstances  = "wasm_instances"
)

// SlotPool is one bounded per-node pool as a capacity heartbeat reports it.
// Runtimes lists every runtime whose creates take a slot from it: on a
// containerd node runc ("docker") and gVisor share the one netns pool, so a
// pending gVisor create uses up a slot a docker create could have had.
type SlotPool struct {
	Name     string   `json:"name"`
	Runtimes []string `json:"runtimes"`
	Total    int      `json:"total"`
	Free     int      `json:"free"`
}

// Serves reports whether creates of runtime take a slot from this pool.
func (p SlotPool) Serves(runtime string) bool {
	for _, r := range p.Runtimes {
		if r == runtime {
			return true
		}
	}
	return false
}

// SlotPoolFor returns the pool runtime's creates draw from on this host.
// ok=false means the host reports no bounded pool for it — a runtime without
// one (docker engine, isolate), or a peer that predates SlotPools — and
// placement treats that as "unknown, allow", like an empty SupportedRuntimes.
func (s Snapshot) SlotPoolFor(runtime string) (SlotPool, bool) {
	for _, p := range s.SlotPools {
		if p.Serves(runtime) {
			return p, true
		}
	}
	return SlotPool{}, false
}
