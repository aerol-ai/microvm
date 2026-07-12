package docker

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/docker/netstats"
)

// EventsSource is the engine-agnostic surface the service layer uses for the
// daemon event monitor and netstats PID resolution. *Client satisfies it for
// the dockerd path; internal/runtime/containerd.Driver satisfies it for the
// containerd path. Keeping DockerEvent on this seam avoids a second event
// type while both engines can coexist during migration.
type EventsSource interface {
	StreamEvents(ctx context.Context, out chan<- DockerEvent) error
	netstats.PIDLookup
}

// Ensure *Client implements EventsSource at compile time.
var _ EventsSource = (*Client)(nil)
