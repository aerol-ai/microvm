package kubepod

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// The driver is the service's event source in pod mode (docker.EventsSource),
// from the same watch as its view (watch.go):
//
//   - "start" when a pod's sandbox container is first seen running;
//   - "oom" then "die" when it is seen ended, OOM-killed;
//   - "die" when it is seen ended, with its exit code;
//   - "die" when a pod seen running goes away with no end seen (removed by
//     force, or its node went away).
//
// Each carries the kubelet's own time (the container's start or finish),
// the clock SandboxRuntimeState.StartedAt is read from, so the service tells
// an old run's exit from the current run's (internal/service/run_starts.go).
//
// A pod deleted by Stop is not a "destroy": the sandbox still exists,
// stopped, and Start makes its pod again. Only the service's own destroy
// removes a sandbox. Nothing is sent for pods already there when the
// worker starts: events are live only, as Docker's and containerd's are.

var _ docker.EventsSource = (*Driver)(nil)

// publishLocked hands ev to every StreamEvents caller without waiting: the
// watch must never stall on a slow reader, since stops and creates wait on
// its view. A reader that falls eventBuffer events behind loses the newest
// ones; reconcile still sees each sandbox's state.
func (c *podCache) publishLocked(ev docker.DockerEvent) {
	for _, ch := range c.subs {
		select {
		case ch <- ev:
		default:
			c.dropped++
		}
	}
}

func (c *podCache) subscribe() (<-chan docker.DockerEvent, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextSub
	c.nextSub++
	ch := make(chan docker.DockerEvent, eventBuffer)
	c.subs[id] = ch
	return ch, func() {
		c.mu.Lock()
		delete(c.subs, id)
		c.mu.Unlock()
	}
}

func (c *podCache) droppedEvents() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// StreamEvents sends this worker's sandbox start and exit events to out
// until ctx ends. RunWatch must be running for any to come.
func (d *Driver) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	ch, unsubscribe := d.cache.subscribe()
	defer unsubscribe()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-ch:
			select {
			case out <- ev:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// ErrNoProcessView is ContainerPID's answer: in pod mode the sandbox runs
// on another machine, or in another kernel, from the worker, so the worker
// has no process ID to read its network counters from.
var ErrNoProcessView = errors.New("kubepod: the worker cannot see a sandbox's processes in pod mode")

// ContainerPID implements netstats.PIDLookup; pod mode has no answer.
func (d *Driver) ContainerPID(context.Context, string) (int, error) {
	return 0, ErrNoProcessView
}
