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
	// TeardownRetry marks the copy the pool passes to DestroyParked when it
	// retries a teardown that failed (pending_destroy.go). The engine's
	// first attempt already closed the handle and did what must happen
	// before the container goes; a retry only removes the container and
	// what must wait for its absence.
	TeardownRetry bool
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
