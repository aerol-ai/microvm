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
		if err := s.markSandboxStopped(ctx, sandbox, event); err != nil {
			return err
		}
		// Close the running window at the stop edge so a sandbox that ran and
		// exited between reconcile sweeps still has its tail metered. Uses the
		// pre-stop row (CPU/mem/disk/owner intact); no-op without a reporter.
		s.emitLifecycleStopUsage(ctx, sandbox, time.Now(), false)
		return nil
	case "destroy":
		if err := s.handleDestroyEvent(ctx, sandbox); err != nil {
			return err
		}
		// Terminal: meter the final tail and forget the sandbox's cursor.
		s.emitLifecycleStopUsage(ctx, sandbox, time.Now(), true)
		return nil
	case "start":
		if err := s.handleStartEvent(ctx, sandbox); err != nil {
			return err
		}
		// Begin accrual from the actual start so the next sweep meters from here
		// rather than one reconcile interval back.
		s.noteLifecycleStart(sandbox.ID, time.Now())
		return nil
	default:
		return nil
	}
}

// markSandboxStopped handles die/stop/oom events: the container exited but the
// sandbox row stays — Start can resurrect it, the image is still needed, and
// the capacity reservation is legitimately held. Routes are torn down and
// per-IP netrules cleared so a stopped sandbox doesn't leave dangling Caddy
// upstreams pointing at an IP Docker may reassign on the next start.
//
// Wake-arming (D5 in plans/serverless-sandbox-http-wake.md): the event is
// classified into one of the three stop modes by consulting the
// expected-stop bookkeeping populated by stopSandboxInternal. Manual /
// lifecycle stops carry their recorded mode (StopSandbox / lifecycle
// sweep registered the expectation before docker.Stop); anything else
// is treated as involuntary. A serverless sandbox stopped via lifecycle
// or involuntarily arms wake_armed so the next inbound HTTP request can
// transparently resurrect it.
//
// Ordering matters: route work runs BEFORE the row Upsert so the wake_armed
// bit we persist reflects whether a wake route was actually installed. The
// API stop path (stopSandboxInternal) already installed the wake route
// before docker.Stop fired; tearDownPortRoutesForStop is the shared helper
// that preserves it here (D5 install-then-delete) instead of wiping it.
// Inverting these would re-introduce the bug where the API stop installs a
// wake route and the subsequent die event silently deletes it.
func (s *Service) markSandboxStopped(ctx context.Context, sandbox *models.Sandbox, event docker.DockerEvent) error {
	previousIP := sandbox.ContainerIP

	// Invalidate the warm-preflight cache the moment we observe the
	// stop event — this is the tightest possible signal that the
	// sandbox is no longer Started, since the Docker /events stream
	// surfaces die/stop/oom sub-second after the container actually
	// exits. The ingress proxy's IsSandboxStarted hot path will fall
	// through to SQLite from here on for this id.
	s.invalidateWarm(sandbox.ID)
	mode := s.classifyDockerStopEvent(sandbox.ID, event)
	arm := s.shouldArmWake(sandbox, mode)

	// Release the admitter slot — a stopped container holds no host CPU/RAM
	// and the reservation would otherwise block new admissions until the
	// sandbox is destroyed. handleStartEvent re-Reserves on the way back up
	// (out-of-band `docker start`), and the API StartSandbox path calls
	// Admit. Idempotent if a concurrent Stop API call also released.
	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}

	// Tear down routes and per-IP netrules best-effort. Caddy upsert/delete
	// helpers and netrules.ClearBlockAllEgress are all idempotent. The
	// helper applies the D5 wake-arming exception for HTTP ports and
	// demotes arm to false if every wake-route install attempt failed.
	arm = s.tearDownPortRoutesForStop(ctx, sandbox, arm)
	if s.caddy != nil {
		if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
			s.logger.Warn("delete sandbox route failed", "sandbox_id", sandbox.ID, "error", err)
		}
	}
	if previousIP != "" {
		if cr, err := s.containerRuntimeForSandbox(sandbox); err == nil {
			if err := cr.ClearNetworkRules(previousIP); err != nil {
				s.logger.Warn("clear network rules failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
			}
			// Selective-egress rules are comment-tagged, so ClearNetworkRules
			// above does not remove them — clear them from the persisted policy
			// before the IP is recycled to another container.
			if err := cr.ClearEgressPolicy(previousIP, sandbox.NetworkAllowOut, sandbox.NetworkDenyOut); err != nil {
				s.logger.Warn("clear egress policy failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
			}
		}
	}

	sandbox.Status = models.SandboxStatusStopped
	sandbox.UpdatedAt = time.Now().UTC()
	sandbox.WakeArmed = arm
	if event.Action == "oom" {
		sandbox.LastError = "container killed by OOM"
	} else if event.Action == "die" && event.ExitCode != 0 {
		sandbox.LastError = fmt.Sprintf("container exited with code %d", event.ExitCode)
	}

	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return fmt.Errorf("update sandbox status: %w", err)
	}

	s.logger.Info("audit sandbox stopped via docker event",
		"sandbox_id", sandbox.ID,
		"action", event.Action,
		"exit_code", event.ExitCode,
		"status", string(sandbox.Status),
		"stop_mode", mode.String(),
		"wake_armed", arm,
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

	// Mirror the API DestroySandbox path: drop the warm-preflight cache
	// so the ingress proxy stops treating this id as Started.
	s.invalidateWarm(sandbox.ID)
	s.forgetNetstatsActivity(sandbox.ID)

	// Best-effort teardown. Order matches DestroySandbox (caddy → mounts →
	// store.Delete → admitter → schedulePendingImageGC); container destroy
	// is skipped because the event itself means the container is already
	// gone. Failures here are picked up by gcZombieCaddyEntries /
	// mounts.Sweep on the next reconcile pass.
	if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		s.logger.Warn("delete sandbox route failed", "sandbox_id", sandbox.ID, "error", err)
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.deleteExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("delete port route failed", "sandbox_id", sandbox.ID, "port", port.Port, "protocol", port.Protocol, "error", err)
		}
	}
	if s.mounts != nil {
		if err := s.mounts.UnmountAll(sandbox.ID); err != nil {
			s.logger.Warn("unmount on destroy event failed", "sandbox_id", sandbox.ID, "error", err)
		}
	}
	if previousIP != "" {
		if cr, err := s.containerRuntimeForSandbox(sandbox); err == nil {
			if err := cr.ClearNetworkRules(previousIP); err != nil {
				s.logger.Warn("clear network rules failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
			}
			// Selective-egress rules are comment-tagged, so ClearNetworkRules
			// above does not remove them — clear them from the persisted policy
			// before the IP is recycled to another container.
			if err := cr.ClearEgressPolicy(previousIP, sandbox.NetworkAllowOut, sandbox.NetworkDenyOut); err != nil {
				s.logger.Warn("clear egress policy failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
			}
		}
	}

	// Secret tomb/outbox before store.Delete / placement delete so recipients
	// can still be resolved from the sealed row or placement. Shared with
	// DestroySandbox and reconcile-destroyed — cluster_secrets has no FK.
	if err := s.retainSandboxAuditACL(ctx, sandbox); err != nil {
		return fmt.Errorf("retain sandbox audit ACL: %w", err)
	}
	if err := s.DeleteClusterSecrets(ctx, sandbox.ID); err != nil {
		return fmt.Errorf("delete cluster secrets: %w", err)
	}

	// store.Delete must happen BEFORE schedulePendingImageGC. The
	// pending-image janitor uses HasActiveImageRef at sweep time; a stale
	// non-destroyed row here would make every future sweep skip this
	// image. ErrNotFound is benign — the API-driven destroy path may have
	// raced us.
	if err := s.store.Delete(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("delete sandbox: %w", err)
	}
	if err := s.cleanupWasmSandboxArtifacts(ctx, sandbox); err != nil {
		return err
	}

	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}
	s.deleteSelfOwnedClusterPlacement(ctx, sandbox.ID, "docker-destroy-event")
	if !s.isWasmSandbox(sandbox) {
		s.schedulePendingImageGC(ctx, sandbox.Image)
	}

	if s.logger != nil {
		s.logger.Info("audit sandbox destroyed via docker event",
			"sandbox_id", sandbox.ID,
			"image", sandbox.Image,
		)
	}
	return nil
}

func (s *Service) handleStartEvent(ctx context.Context, sandbox *models.Sandbox) error {
	// Re-attach Caddy routes if the runtime IP changed (Docker daemon restart
	// can reassign IPs). Inspect to get the current address rather than trust
	// what's in the DB.
	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		return fmt.Errorf("resolve runtime: %w", err)
	}
	state, err := rt.Inspect(ctx, sandbox.ContainerID)
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
	// A successful start (whether driven by the API, a wake, or
	// out-of-band `docker start`) means the sandbox is live again, so
	// drop wake_armed. The next stop is the one that decides whether
	// to re-arm.
	sandbox.WakeArmed = false
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return fmt.Errorf("update sandbox runtime: %w", err)
	}

	// Out-of-band start (operator ran `docker start <id>` directly): the
	// container is already running, so we cannot refuse it via Admit. Use
	// Reserve to force the slot regardless of budget — the host is already
	// committed. The eventual-consistency model accepts a transient overcommit
	// over silently dropping the reservation; the API Start path uses Admit
	// to keep human-driven starts honest. Reserve is idempotent if the slot
	// is already held (e.g. from API start that just upserted before us).
	if s.admitter != nil {
		s.admitter.Reserve(sandbox.ID, capacityRequestFromSandbox(sandbox))
	}

	if err := s.syncSandboxPublicRoute(ctx, sandbox); err != nil {
		return fmt.Errorf("upsert sandbox route: %w", err)
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.syncExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("upsert port route failed", "sandbox_id", sandbox.ID, "port", port.Port, "protocol", port.Protocol, "error", err)
		}
	}
	s.syncAllowedPorts(ctx, sandbox)
	return nil
}
