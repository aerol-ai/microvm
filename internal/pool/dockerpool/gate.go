package dockerpool

// ParkShape is the resource reservation shape for one parked slot.
type ParkShape struct {
	CPU       float64
	MemoryMB  int
	DiskGB    int
	GPUs      int
	GPUVendor string
	Runtime   string
}

// RefillGate decides whether a new park is allowed and tracks reservations.
type RefillGate interface {
	CanPark(shape ParkShape) bool
	ParkReservation(slotID string, shape ParkShape) error
	ReleasePark(slotID string)
}
