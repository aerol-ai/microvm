// Package containerdpool is the warm-container pool for containerd sandboxes.
// Queue mechanics reuse dockerpool; only the Spawner/adopt path is engine-specific.
package containerdpool

import (
	"log/slog"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

type (
	Pool          = dockerpool.Pool
	ParkedSlot    = dockerpool.ParkedSlot
	Spawner       = dockerpool.Spawner
	SpawnerHandle = dockerpool.SpawnerHandle
	Key           = dockerpool.Key
)

var (
	ErrNoSlot     = dockerpool.ErrNoSlot
	ErrStaleImage = dockerpool.ErrStaleImage
)

// New constructs a warm pool for containerd park/adopt (Phase 3).
func New(logger *slog.Logger) *Pool {
	return dockerpool.New(logger)
}

// KeyFromRequest builds a pool key from a create request and resolved runtime.
func KeyFromRequest(req models.CreateSandboxRequest, runtime string) Key {
	return dockerpool.KeyFromRequest(req, runtime)
}

// ParkReservationID is the capacity admitter key for a parked slot.
func ParkReservationID(slotID string) string {
	return dockerpool.ParkReservationID(slotID)
}
