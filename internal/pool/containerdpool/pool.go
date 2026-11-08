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

// metrics is the containerd pool's own series (aerolvm_containerd_pool_*).
// Its events still count into the shared aerolvm_docker_pool_* series too,
// which the warm-pool dashboards read (dockerpool.MetricFamily).
var metrics = dockerpool.NewMetricFamily("aerolvm_containerd_pool")

// New constructs a warm pool for containerd park/adopt (Phase 3).
func New(logger *slog.Logger) *Pool {
	p := dockerpool.New(logger)
	p.SetMetricFamily(metrics)
	return p
}

// KeyFromRequest builds a pool key from a create request and resolved runtime.
func KeyFromRequest(req models.CreateSandboxRequest, runtime string) Key {
	return dockerpool.KeyFromRequest(req, runtime)
}

// ParkReservationID is the capacity admitter key for a parked slot.
func ParkReservationID(slotID string) string {
	return dockerpool.ParkReservationID(slotID)
}
