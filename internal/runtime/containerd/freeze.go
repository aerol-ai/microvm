package containerd

import (
	"context"
	"fmt"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
)

// Freeze pauses the sandbox's task with the cgroup freezer (task.Pause),
// memory intact, for the cluster ownership fence (runtime.Freezer). The
// sandbox row is not touched, and the event mapper already ignores
// TaskPaused/TaskResumed, so nothing downstream reads the freeze as a stop.
//
// Idempotent: a task that is already paused (or pausing), not running, or
// absent has nothing executing, so there is nothing to do.
func (d *Driver) Freeze(ctx context.Context, containerRef string) error {
	task, err := d.loadTaskForFreeze(ctx, containerRef)
	if err != nil || task == nil {
		return err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return fmt.Errorf("freeze %s: task status: %w", containerRef, err)
	}
	if status.Status != cntr.Running {
		return nil
	}
	if err := task.Pause(ctx); err != nil {
		return fmt.Errorf("freeze %s: %w", containerRef, err)
	}
	return nil
}

// Thaw undoes Freeze (task.Resume). A task that is not paused, or absent, is
// already in the state Thaw leaves it in.
func (d *Driver) Thaw(ctx context.Context, containerRef string) error {
	task, err := d.loadTaskForFreeze(ctx, containerRef)
	if err != nil || task == nil {
		return err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return fmt.Errorf("thaw %s: task status: %w", containerRef, err)
	}
	if status.Status != cntr.Paused && status.Status != cntr.Pausing {
		return nil
	}
	if err := task.Resume(ctx); err != nil {
		return fmt.Errorf("thaw %s: %w", containerRef, err)
	}
	return nil
}

// loadTaskForFreeze returns the container's task, or nil when the container
// or its task does not exist (nothing to freeze or thaw).
func (d *Driver) loadTaskForFreeze(ctx context.Context, containerRef string) (cntr.Task, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	container, err := client.LoadContainer(ctx, containerRef)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load container: %w", err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load task: %w", err)
	}
	return task, nil
}
