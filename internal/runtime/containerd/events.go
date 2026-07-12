package containerd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/events"

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
			select {
			case out <- normalized:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func normalizeContainerdEvent(ev *events.Envelope) (docker.DockerEvent, bool) {
	if ev == nil {
		return docker.DockerEvent{}, false
	}
	var action string
	switch {
	case contains(ev.Topic, "/tasks/started"):
		action = "start"
	case contains(ev.Topic, "/tasks/paused"), contains(ev.Topic, "/tasks/stopped"):
		action = "stop"
	case contains(ev.Topic, "/tasks/deleted"):
		action = "destroy"
	case contains(ev.Topic, "/tasks/oom"):
		action = "oom"
	case contains(ev.Topic, "/tasks/exited"):
		action = "die"
	default:
		return docker.DockerEvent{}, false
	}
	id := extractContainerID(ev)
	if id == "" {
		return docker.DockerEvent{}, false
	}
	return docker.DockerEvent{
		ContainerID: id,
		SandboxID:   id,
		Action:      action,
		Time:        ev.Timestamp,
	}, true
}

func extractContainerID(ev *events.Envelope) string {
	// containerd task topics embed the container id in the topic path:
	// /tasks/create/<ns>/<container>/<task>
	parts := splitTopic(ev.Topic)
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func splitTopic(topic string) []string {
	var out []string
	cur := ""
	for _, r := range topic {
		if r == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ContainerPID returns the init PID for a running task.
func (d *Driver) ContainerPID(ctx context.Context, containerRef string) (int, error) {
	client, err := d.ensureClient()
	if err != nil {
		return 0, err
	}
	container, err := client.LoadContainer(ctx, containerRef)
	if err != nil {
		return 0, err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return 0, nil
	}
	status, err := task.Status(ctx)
	if err != nil || status.Status != cntr.Running {
		return 0, nil
	}
	pids, err := task.Pids(ctx)
	if err != nil || len(pids) == 0 {
		return 0, err
	}
	return int(pids[0].Pid), nil
}

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
