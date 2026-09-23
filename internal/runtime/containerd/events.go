package containerd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/errdefs"
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
	// Two filters (OR'd by containerd). Task topics carry start/exit/oom, but
	// they cannot tell "the process ended" from "the container was removed":
	// /tasks/delete fires on BOTH, because the task is the process and it is
	// reaped either way. Only /containers/delete means the container object is
	// gone, which is what Docker's "destroy" denotes and what the service
	// consumer acts on by deleting the sandbox row.
	envelopes, errs := client.SubscribeEvents(ctx, `topic~="/tasks/"`, `topic=="`+containerDeleteEventTopic+`"`)
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

// containerDeleteEventTopic is containerd's CONTAINER-level delete topic. The
// core/runtime package only exports /tasks/* constants, so this one is spelled
// out here; it is published by plugins/services/containers as
// "/containers/delete" and carries an apievents.ContainerDelete payload.
const containerDeleteEventTopic = "/containers/delete"

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
	case runtime.TaskExitEventTopic:
		action = "die"
	case runtime.TaskOOMEventTopic:
		action = "oom"
	case containerDeleteEventTopic:
		action = "destroy"
	default:
		// TaskDelete is deliberately NOT mapped to "destroy". It is
		// /tasks/delete — the TASK (the process) being reaped — which happens
		// on every ordinary stop while the container object survives and stays
		// restartable. Mapping it to "destroy" made handleDestroyEvent delete
		// the sandbox row on a manual stop, so a stopped sandbox vanished and
		// UC-14/UC-15 (stop, then start again) broke on the containerd engine —
		// the default engine for every non-local deployment. Observed live on
		// single-node 2026-09-23, intermittently: die(stop_mode=manual) ->
		// POST /stop 200 -> "destroyed via docker event" 2ms later -> GET 404.
		// Same failure shape as the TaskPaused case below, one topic over.
		// TaskPaused/TaskResumed are deliberately NOT mapped. The service
		// consumer folds "stop" into markSandboxStopped (route + netrules +
		// admitter teardown), so mapping TaskPaused→"stop" made an internal
		// CreateSnapshot pause tear the live sandbox down — and TaskResumed,
		// unmapped, never restored it. Docker's pause/unpause are likewise
		// ignored by the consumer; parity requires the same here.
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
	// ContainerDelete names the container with GetID(), not GetContainerID().
	// Order matters: task events ALSO have GetID(), where it is the EXEC id
	// ("" for the init process), so GetContainerID must win whenever present or
	// an exec's exit would be attributed to a container named after the exec.
	if id == "" {
		if g, ok := decoded.(interface{ GetID() string }); ok {
			id = g.GetID()
		}
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
