package firecracker

// poolspawner.go is the runtime-side adapter that lets the warm-VMM
// pool (internal/pool/vmm) drive Driver.WarmSpawn through a narrow
// interface. The pool's refill goroutine calls Spawn; this file turns
// that call into a WarmSpawnRequest and hands back a vmm.SpawnedHandle
// the pool can store in its slot row.
//
// Direction of dependency: runtime/firecracker imports internal/pool/vmm.
// vmm does NOT import runtime/firecracker (the import-cycle wall the
// spawner.go seam was designed to preserve). main.go constructs a
// *PoolSpawner against the same *Driver it already passes to the rest
// of the daemon, then injects it into the pool.

import (
	"context"
	"fmt"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
)

// PoolSpawner adapts a *Driver to vmmpool.Spawner. Construction is a
// thin wrapper around a driver pointer — no state, no locks; every
// Spawn call delegates to Driver.WarmSpawn and returns the resulting
// WarmHandle directly (WarmHandle's method set is the structural
// superset of vmmpool.SpawnedHandle, so no conversion shim is needed).
//
// The import is aliased to vmmpool because the runtime package already
// has an internal *vmm type (the firecracker process supervisor) and
// the unaliased import would shadow it.
type PoolSpawner struct {
	driver *Driver
}

// NewPoolSpawner wires a driver into the pool's Spawner contract.
// main.go calls this once at boot, alongside the vmmpool.Pool
// construction.
func NewPoolSpawner(driver *Driver) *PoolSpawner {
	return &PoolSpawner{driver: driver}
}

// Spawn satisfies vmmpool.Spawner. The refill goroutine has already
// chosen a slot ID and resolved the template's snapshot artifacts; this
// method only forwards them into the runtime's WarmSpawn primitive.
// The returned handle's Shutdown is what the pool calls when the slot
// ages out or the daemon stops.
func (s *PoolSpawner) Spawn(ctx context.Context, slotID string, inputs vmmpool.SnapshotInputs) (vmmpool.SpawnedHandle, error) {
	if s == nil || s.driver == nil {
		return nil, fmt.Errorf("firecracker pool spawner: driver is nil")
	}
	handle, err := s.driver.WarmSpawn(ctx, WarmSpawnRequest{
		SlotID:             slotID,
		TemplateID:         inputs.TemplateID,
		SnapshotMemoryPath: inputs.SnapshotMemoryPath,
		SnapshotStatePath:  inputs.SnapshotStatePath,
		SnapshotChecksum:   inputs.SnapshotChecksum,
		VsockCID:           inputs.VsockCID,
	})
	if err != nil {
		return nil, err
	}
	return handle, nil
}
