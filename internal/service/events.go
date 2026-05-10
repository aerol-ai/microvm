package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	eventReconnectInitial = 1 * time.Second
	eventReconnectMax     = 30 * time.Second
	eventChannelBuffer    = 32
)

// StartEventMonitor launches the Docker event consumer goroutine. It is the
// realtime counterpart to Reconcile() — when a container dies, OOM-kills, or
// is destroyed out-of-band, this loop updates the DB and tears down routes
// within ~1s instead of waiting for the next reconcile tick.
func (s *Service) StartEventMonitor(ctx context.Context) {
	if !s.cfg.EnableEventMonitor {
		return
	}

	go s.runEventMonitor(ctx)
}

func (s *Service) runEventMonitor(ctx context.Context) {
	backoff := eventReconnectInitial
	for {
		if ctx.Err() != nil {
			return
		}

		events := make(chan docker.DockerEvent, eventChannelBuffer)
		streamCtx, cancel := context.WithCancel(ctx)

		streamDone := make(chan error, 1)
		go func() {
			streamDone <- s.events.StreamEvents(streamCtx, events)
			close(events)
		}()

		// Drain events until the stream returns.
		s.consumeEvents(streamCtx, events)
		err := <-streamDone
		cancel()

		if ctx.Err() != nil {
			return
		}

		if err != nil {
			s.logger.Warn("docker event stream ended", "error", err, "retry_in", backoff)
		} else {
			s.logger.Info("docker event stream ended", "retry_in", backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > eventReconnectMax {
			backoff = eventReconnectMax
		}
	}
}

func (s *Service) consumeEvents(ctx context.Context, events <-chan docker.DockerEvent) {
	for event := range events {
		if ctx.Err() != nil {
			return
		}
		if err := s.handleDockerEvent(ctx, event); err != nil {
			s.logger.Warn("handle docker event failed",
				"sandbox_id", event.SandboxID,
				"action", event.Action,
				"error", err,
			)
		}
	}
}

func (s *Service) handleDockerEvent(ctx context.Context, event docker.DockerEvent) error {
	sandbox, err := s.store.Get(ctx, event.SandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Either an orphan container (no DB row) or the API-driven destroy
			// path raced ahead and removed the row already. Reconcile() handles
			// orphan cleanup; either way there's nothing to update here.
			return nil
		}
		return fmt.Errorf("load sandbox: %w", err)
	}

	switch event.Action {
	case "die", "stop", "oom":
		return s.markSandboxStopped(ctx, sandbox, event)
	case "destroy":
		return s.handleDestroyEvent(ctx, sandbox)
	case "start":
		return s.handleStartEvent(ctx, sandbox)
	default:
		return nil
	}
}

// markSandboxStopped handles die/stop/oom events: the container exited but the
// sandbox row stays — Start can resurrect it, the image is still needed, and
// the capacity reservation is legitimately held. Routes are torn down and
// per-IP netrules cleared so a stopped sandbox doesn't leave dangling Caddy
// upstreams pointing at an IP Docker may reassign on the next start.
func (s *Service) markSandboxStopped(ctx context.Context, sandbox *models.Sandbox, event docker.DockerEvent) error {
	previousIP := sandbox.ContainerIP

	sandbox.Status = models.SandboxStatusStopped
	sandbox.UpdatedAt = time.Now().UTC()
	if event.Action == "oom" {
		sandbox.LastError = "container killed by OOM"
	} else if event.Action == "die" && event.ExitCode != 0 {
		sandbox.LastError = fmt.Sprintf("container exited with code %d", event.ExitCode)
	}

	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return fmt.Errorf("update sandbox status: %w", err)
	}

	// Tear down routes and per-IP netrules best-effort. Caddy upsert/delete
	// helpers and netrules.ClearBlockAllEgress are all idempotent.
	if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		s.logger.Warn("delete sandbox route failed", "sandbox_id", sandbox.ID, "error", err)
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.deleteExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("delete port route failed", "sandbox_id", sandbox.ID, "port", port.Port, "protocol", port.Protocol, "error", err)
		}
	}
	if previousIP != "" {
		if err := s.docker.ClearNetworkRules(previousIP); err != nil {
			s.logger.Warn("clear network rules failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
		}
	}

	s.logger.Info("audit sandbox stopped via docker event",
		"sandbox_id", sandbox.ID,
		"action", event.Action,
		"exit_code", event.ExitCode,
		"status", string(sandbox.Status),
	)
	return nil
}

// handleDestroyEvent fires when Docker emits a destroy for a container we own
// — typically `docker rm -f <id>` outside the API, OOM-then-autoremove, or a
// daemon-side cleanup. Semantically equivalent to API DestroySandbox and the
// reconcile destroyed-branch: delete the row, cascading exposed_ports and
// freeing any L4 host_port reservation immediately. Without this, the row
// would sit at status=destroyed until the next reconcile pass picked it up,
// holding its host_port slot in the unique-index pool the entire time. With
// SB_AUTO_RECONCILE=false or a stalled reconcile loop, that slot would be
// stuck indefinitely.
func (s *Service) handleDestroyEvent(ctx context.Context, sandbox *models.Sandbox) error {
	previousIP := sandbox.ContainerIP

	// Best-effort teardown. Order matches DestroySandbox (caddy → mounts →
	// store.Delete → admitter → maybeRemoveImage); container destroy is
	// skipped because the event itself means the container is already gone.
	// Failures here are picked up by gcZombieCaddyEntries / mounts.Sweep on
	// the next reconcile pass.
	if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		s.logger.Warn("delete sandbox route failed", "sandbox_id", sandbox.ID, "error", err)
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.deleteExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("delete port route failed", "sandbox_id", sandbox.ID, "port", port.Port, "protocol", port.Protocol, "error", err)
		}
	}
	if err := s.mounts.UnmountAll(sandbox.ID); err != nil {
		s.logger.Warn("unmount on destroy event failed", "sandbox_id", sandbox.ID, "error", err)
	}
	if previousIP != "" {
		if err := s.docker.ClearNetworkRules(previousIP); err != nil {
			s.logger.Warn("clear network rules failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
		}
	}

	// store.Delete must happen BEFORE maybeRemoveImage: HasActiveImageRef
	// queries the sandboxes table and treats any non-destroyed row as a live
	// reference. Deleting first lets the image GC see the correct state.
	// ErrNotFound is benign — the API-driven destroy path may have raced us.
	if err := s.store.Delete(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("delete sandbox: %w", err)
	}

	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}
	s.maybeRemoveImage(ctx, sandbox.Image)

	s.logger.Info("audit sandbox destroyed via docker event",
		"sandbox_id", sandbox.ID,
		"image", sandbox.Image,
	)
	return nil
}

func (s *Service) handleStartEvent(ctx context.Context, sandbox *models.Sandbox) error {
	// Re-attach Caddy routes if the runtime IP changed (Docker daemon restart
	// can reassign IPs). Inspect to get the current address rather than trust
	// what's in the DB.
	state, err := s.docker.Inspect(ctx, sandbox.ContainerID)
	if err != nil {
		return fmt.Errorf("inspect container: %w", err)
	}
	if state.ContainerIP == "" {
		return nil
	}

	if state.ContainerIP != sandbox.ContainerIP {
		s.logger.Info("sandbox IP changed",
			"sandbox_id", sandbox.ID,
			"previous_ip", sandbox.ContainerIP,
			"new_ip", state.ContainerIP,
		)
	}

	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
	sandbox.UpdatedAt = time.Now().UTC()
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return fmt.Errorf("update sandbox runtime: %w", err)
	}

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort); err != nil {
		return fmt.Errorf("upsert sandbox route: %w", err)
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.upsertExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("upsert port route failed", "sandbox_id", sandbox.ID, "port", port.Port, "protocol", port.Protocol, "error", err)
		}
	}
	s.syncAllowedPorts(ctx, sandbox)
	return nil
}
