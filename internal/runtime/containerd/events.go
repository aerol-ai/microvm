package containerd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/typeurl/v2"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// StreamEvents subscribes to containerd task lifecycle events for managed
// workloads and normalizes them into docker.DockerEvent for the service
// event monitor.
func (d *Driver) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	envelopes, errs := client.SubscribeEvents(ctx, `topic~="/tasks/"`)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errs:
			if err != nil {
				return fmt.Errorf("containerd event stream: %w", err)
			}
		case ev, ok := <-envelopes:
			if !ok {
				return nil
			}
			normalized, ok := normalizeContainerdEvent(ev)
			if !ok {
				continue
			}
			// Warm-adopt keeps container ID as park-*; resolve the
			// aerolvm.sandbox_id label so the service event monitor can
			// match store rows without waiting for reconcile.
			if c, loadErr := client.LoadContainer(ctx, normalized.ContainerID); loadErr == nil {
				if sid := d.sandboxIDFromContainer(ctx, c); sid != "" {
					normalized.SandboxID = sid
				}
			}
			select {
			case out <- normalized:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// normalizeContainerdEvent maps a containerd task-lifecycle envelope onto the
// docker.DockerEvent the service monitor consumes. Topics are matched against
// the canonical containerd constants (real topics are "/tasks/exit" etc., NOT
// "/tasks/exited"), and the container ID is read from the typed protobuf
// payload — it is not present in the topic path.
func normalizeContainerdEvent(ev *events.Envelope) (docker.DockerEvent, bool) {
	if ev == nil {
		return docker.DockerEvent{}, false
	}
	var action string
	switch ev.Topic {
	case runtime.TaskStartEventTopic:
		action = "start"
	case runtime.TaskPausedEventTopic:
		action = "stop"
	case runtime.TaskExitEventTopic:
		action = "die"
	case runtime.TaskOOMEventTopic:
		action = "oom"
	case runtime.TaskDeleteEventTopic:
		action = "destroy"
	default:
		return docker.DockerEvent{}, false
	}
	id, exitCode := containerIDAndExitFromEvent(ev)
	if id == "" {
		return docker.DockerEvent{}, false
	}
	return docker.DockerEvent{
		ContainerID: id,
		SandboxID:   id, // enriched with sandbox_id label in StreamEvents
		Action:      action,
		ExitCode:    exitCode,
		Time:        ev.Timestamp,
	}, true
}

// containerIDFromEvent decodes the typed task-event payload and returns its
// ContainerID. All task events (TaskStart/TaskExit/TaskDelete/TaskOOM/…)
// expose GetContainerID(), so a single interface assertion covers them.
func containerIDFromEvent(ev *events.Envelope) string {
	id, _ := containerIDAndExitFromEvent(ev)
	return id
}

func containerIDAndExitFromEvent(ev *events.Envelope) (string, int) {
	if ev == nil || ev.Event == nil {
		return "", 0
	}
	decoded, err := typeurl.UnmarshalAny(ev.Event)
	if err != nil {
		return "", 0
	}
	id := ""
	if g, ok := decoded.(interface{ GetContainerID() string }); ok {
		id = g.GetContainerID()
	}
	exitCode := 0
	if g, ok := decoded.(interface{ GetExitStatus() uint32 }); ok {
		exitCode = int(g.GetExitStatus())
	}
	return id, exitCode
}

// ContainerPID returns the init PID for a running task. "Not running here"
// (no container / no task) is (0, nil) so the events mux can fall through to
// the other engine; genuine lookup failures propagate so netstats diagnostics
// aren't silently swallowed.
func (d *Driver) ContainerPID(ctx context.Context, containerRef string) (int, error) {
	client, err := d.ensureClient()
	if err != nil {
		return 0, err
	}
	container, err := client.LoadContainer(ctx, containerRef)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return 0, nil // container exists but has no running task
		}
		return 0, err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return 0, err
	}
	if status.Status != cntr.Running {
		return 0, nil
	}
	pids, err := task.Pids(ctx)
	if err != nil {
		return 0, err
	}
	if len(pids) == 0 {
		return 0, nil
	}
	return int(pids[0].Pid), nil
}

// pollToolboxHealthFn is the toolbox readiness probe; tests stub it to avoid HTTP.
var pollToolboxHealthFn = pollToolboxHealth

func pollToolboxHealth(ctx context.Context, containerIP string, toolboxPort int) error {
	target := fmt.Sprintf("http://%s:%d/health", containerIP, toolboxPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("toolbox health status %d", resp.StatusCode)
	}
	return nil
}
