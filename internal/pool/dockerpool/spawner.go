package dockerpool

import "context"

// ParkedSlot is the in-memory handle for one warm container.
type ParkedSlot struct {
	ID             string
	ContainerID    string
	ContainerIP    string
	ImageID        string
	Key            Key
	BootstrapToken string
	Handle         SpawnerHandle
}

// SpawnerHandle is the host-side parked connection and listener state.
type SpawnerHandle interface {
	Alive() bool
	Adopt(ctx context.Context, sandboxID, token, adoptNonce string) error
	Close() error
}

// Spawner parks containers ahead of demand.
type Spawner interface {
	Park(ctx context.Context, slotID string, key Key) (*ParkedSlot, error)
	DestroyParked(ctx context.Context, slot *ParkedSlot) error
}
