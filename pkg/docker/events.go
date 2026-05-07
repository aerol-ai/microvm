package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// DockerEvent is a normalized container lifecycle event from the Docker engine,
// scoped to containers carrying our managed label.
type DockerEvent struct {
	ContainerID string
	SandboxID   string
	Action      string // "die", "destroy", "oom", "start", "stop"
	ExitCode    int    // populated on "die" when reported by Docker
	Time        time.Time
}

// StreamEvents subscribes to Docker's /events feed for managed containers and
// pushes normalized events to out. It blocks until ctx is cancelled or the
// stream errors. Callers are expected to reconnect on error.
func (c *Client) StreamEvents(ctx context.Context, out chan<- DockerEvent) error {
	// Filters: container events only, restricted to our managed label, and only
	// the lifecycle actions we react to.
	filters := map[string]map[string]bool{
		"type":  {"container": true},
		"label": {managedLabelKey + "=true": true},
		"event": {
			"die":     true,
			"destroy": true,
			"oom":     true,
			"start":   true,
			"stop":    true,
		},
	}
	encodedFilters, err := json.Marshal(filters)
	if err != nil {
		return fmt.Errorf("encode event filters: %w", err)
	}

	query := url.Values{}
	query.Set("filters", string(encodedFilters))

	target := "http://docker/events?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}

	response, err := c.streamClient.Do(request)
	if err != nil {
		return fmt.Errorf("subscribe events: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("docker events returned status %d", response.StatusCode)
	}

	decoder := json.NewDecoder(response.Body)
	for {
		var raw rawDockerEvent
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("decode event: %w", err)
		}

		event, ok := raw.normalize()
		if !ok {
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case out <- event:
		}
	}
}

// rawDockerEvent matches the subset of Docker's event payload we care about.
// Docker uses both "status" (legacy) and "Action" (newer) for the action name.
type rawDockerEvent struct {
	Status string `json:"status"`
	Action string `json:"Action"`
	ID     string `json:"id"`
	Time   int64  `json:"time"`
	Actor  struct {
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

func (r rawDockerEvent) normalize() (DockerEvent, bool) {
	action := r.Action
	if action == "" {
		action = r.Status
	}
	if action == "" || r.ID == "" {
		return DockerEvent{}, false
	}

	// Docker tags every container event Actor with the container's name. We
	// set the name to the sandbox ID at create time, so it's the authoritative
	// sandbox identifier here.
	sandboxID := sandboxIDFromContainerName(r.Actor.Attributes["name"])
	if sandboxID == "" {
		return DockerEvent{}, false
	}

	exitCode := 0
	if raw, ok := r.Actor.Attributes["exitCode"]; ok && raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			exitCode = parsed
		}
	}

	eventTime := time.Time{}
	if r.Time > 0 {
		eventTime = time.Unix(r.Time, 0).UTC()
	}

	return DockerEvent{
		ContainerID: r.ID,
		SandboxID:   sandboxID,
		Action:      action,
		ExitCode:    exitCode,
		Time:        eventTime,
	}, true
}
