package capacity

import (
	"strings"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
)

// ParkReservationID is the admitter key for a warm-pool parked slot.
func ParkReservationID(slotID string) string {
	return "park:" + strings.TrimSpace(slotID)
}

// ParkGate implements warm-pool refill gating against the host admitter.
type ParkGate struct {
	Admitter *Admitter
	// GuardShape is reserved for one default-shaped sandbox after each park.
	GuardShape Request
}

// CanPark reports whether parking another slot leaves the guard band.
func (g *ParkGate) CanPark(shape dockerpool.ParkShape) bool {
	if g == nil || g.Admitter == nil {
		return true
	}
	snap := g.Admitter.Snapshot()
	if !snap.CanAdmit {
		return false
	}
	probe := Request{
		CPU:       shape.CPU,
		MemoryMB:  shape.MemoryMB,
		DiskGB:    shape.DiskGB,
		GPUs:      shape.GPUs,
		GPUVendor: shape.GPUVendor,
		Runtime:   shape.Runtime,
	}
	probe.CPU += g.GuardShape.CPU
	probe.MemoryMB += g.GuardShape.MemoryMB
	probe.DiskGB += g.GuardShape.DiskGB
	probe.GPUs += g.GuardShape.GPUs
	ok, _ := g.Admitter.CanAdmitRequest(probe)
	return ok
}

// ParkReservation reserves capacity under park:<slot-id>.
func (g *ParkGate) ParkReservation(slotID string, shape dockerpool.ParkShape) error {
	if g == nil || g.Admitter == nil {
		return nil
	}
	return g.Admitter.Admit(ParkReservationID(slotID), Request{
		CPU:       shape.CPU,
		MemoryMB:  shape.MemoryMB,
		DiskGB:    shape.DiskGB,
		GPUs:      shape.GPUs,
		GPUVendor: shape.GPUVendor,
		Runtime:   shape.Runtime,
	})
}

// ReleasePark frees a park reservation.
func (g *ParkGate) ReleasePark(slotID string) {
	if g == nil || g.Admitter == nil {
		return
	}
	g.Admitter.Release(ParkReservationID(slotID))
}

// ReleaseParkReservation is the service-side transfer after adopt.
func ReleaseParkReservation(admitter *Admitter, parkID string) {
	if admitter == nil || strings.TrimSpace(parkID) == "" {
		return
	}
	admitter.Release(ParkReservationID(parkID))
}
