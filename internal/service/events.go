package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
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
		if err := s.publicRoutes().DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
			s.logger.Warn("delete sandbox route failed", "sandbox_id", sandbox.ID, "error", err)
		}
	}
	if previousIP != "" {
		if cr, err := s.containerRuntimeForSandbox(sandbox); err == nil && !s.ipClaimedByOther(ctx, sandbox.ID, previousIP, cr) {
			if err := cr.ClearNetworkRules(previousIP); err != nil {
				s.logger.Warn("clear network rules failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
			}
		}
		// Selective-egress rules are comment-tagged, so ClearNetworkRules
		// above does not remove them. Everything the installed record names
		// is recorded against the address and goes before the IP is
		// recycled, or, if it already was, by the new owner's rebuild.
		if err := s.teardownSandboxEgress(ctx, sandbox, previousIP); err != nil {
			s.logger.Error("egress: rules left at a stopped sandbox's address are retried by this process only", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
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
	if err := s.publicRoutes().DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
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
		if cr, err := s.containerRuntimeForSandbox(sandbox); err == nil && !s.ipClaimedByOther(ctx, sandbox.ID, previousIP, cr) {
			if err := cr.ClearNetworkRules(previousIP); err != nil {
				s.logger.Warn("clear network rules failed", "sandbox_id", sandbox.ID, "ip", previousIP, "error", err)
			}
		}
		// As on stop. The row is the retry anchor until the address's rules
		// are recorded: reconcile finds the runtime gone and tears down again.
		if err := s.teardownSandboxEgress(ctx, sandbox, previousIP); err != nil {
			return err
		}
	}
	if placement, obsolete, err := s.obsoleteLocalPlacement(ctx, sandbox); err != nil {
		return err
	} else if obsolete {
		// The runtime is already gone, but failover/reassignment preserved the
		// sandbox lifecycle elsewhere. Remove only this node's stale row and
		// local tracking; never fan out secret or external-checkpoint deletion.
		return s.finalizeStaleLocalSandbox(ctx, sandbox, placement, true)
	}
	// Retain authorization before committing delete intent. If the node fails
	// after the Raft fence, leader-side expiry may remove the placement; the
	// retained ACL must already be durable so audit history remains attributable.
	if err := s.retainSandboxAuditACL(ctx, sandbox); err != nil {
		return fmt.Errorf("retain sandbox audit ACL: %w", err)
	}
	if err := s.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sandbox); err != nil {
		return err
	}

	// Secret tomb/outbox before store.Delete / placement delete so recipients
	// can still be resolved from the sealed row or placement. Shared with
	// DestroySandbox and reconcile-destroyed — cluster_secrets has no FK.
	if err := s.DeleteClusterSecrets(ctx, sandbox.ID, sandbox.AuditIncarnationID); err != nil {
		return fmt.Errorf("delete cluster secrets: %w", err)
	}

	// WASM state is child data without an FK, so it must be finalized before the
	// parent row disappears. Failed registry deletes remain as durable push rows
	// and become eligible for the orphan-ref sweep after parent deletion.
	if err := s.cleanupWasmSandboxArtifacts(ctx, sandbox); err != nil {
		return err
	}
	if err := s.deleteSelfOwnedClusterPlacementStrict(ctx, sandbox); err != nil {
		return err
	}

	// store.Delete must happen BEFORE schedulePendingImageGC. The
	// pending-image janitor uses HasActiveImageRef at sweep time; a stale
	// non-destroyed row here would make every future sweep skip this
	// image. ErrNotFound is benign — the API-driven destroy path may have
	// raced us.
	if err := s.store.Delete(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("delete sandbox: %w", err)
	}
	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}
	if !s.isWasmSandbox(sandbox) {
		s.schedulePendingImageGC(ctx, models.SandboxEngine(sandbox), sandbox.Image)
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
		// A row that still says started at another address missed its stop:
		// what it left there is recorded and cleared before the new address
		// is enforced (review 6 finding 4).
		if sandbox.Status == models.SandboxStatusStarted && sandbox.ContainerIP != "" {
			if err := s.teardownSandboxEgress(ctx, sandbox, sandbox.ContainerIP); err != nil {
				s.logger.Error("egress: rules left at a moved sandbox's old address are retried by this process only", "sandbox_id", sandbox.ID, "ip", sandbox.ContainerIP, "error", err)
			}
		}
	}

	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
	sandbox.UpdatedAt = time.Now().UTC()
	// The stop event cleared this sandbox's per-IP rules (the IP can be
	// recycled), so a start the API didn't drive would otherwise run
	// unrestricted until the next reconcile pass. Re-apply before anything
	// else and fail closed: a sandbox whose isolation can't be restored is
	// stopped (egress plan P0-4).
	clearGen := s.egressClears.now()
	if err := s.reapplyEgressOnStart(ctx, rt, sandbox); err != nil {
		_ = rt.Stop(ctx, s.runtimeRef(sandbox))
		sandbox.Status = models.SandboxStatusError
		sandbox.LastError = err.Error()
		if uerr := s.store.Upsert(ctx, sandbox); uerr != nil {
			s.logger.Warn("record start-event egress failure", "sandbox_id", sandbox.ID, "error", uerr)
		}
		return fmt.Errorf("reapply egress on start event: %w", err)
	}
	// A successful start (whether driven by the API, a wake, or
	// out-of-band `docker start`) means the sandbox is live again, so
	// drop wake_armed. The next stop is the one that decides whether
	// to re-arm.
	sandbox.WakeArmed = false
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return fmt.Errorf("update sandbox runtime: %w", err)
	}
	s.settleEnforcedEgress(ctx, sandbox, clearGen)

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
	// Quota blocks are re-evaluated against the stored counters, the same
	// way reconcile heals them, so an over-quota sandbox started out of band
	// is blocked again right away.
	if sandbox.NetworkQuotaExceeded {
		overIn := sandbox.NetworkBytesInLimit > 0 && sandbox.NetworkBytesIn >= sandbox.NetworkBytesInLimit
		overOut := sandbox.NetworkBytesOutLimit > 0 && sandbox.NetworkBytesOut >= sandbox.NetworkBytesOutLimit
		s.applyNetworkQuotaState(ctx, sandbox, overIn, overOut)
	}
	return nil
}

// reapplyEgressOnStart puts the stored egress policy back on a container
// that started (enforceEgressOnStart). A runtime without host rules is
// refused only if the sandbox has a policy to enforce.
func (s *Service) reapplyEgressOnStart(ctx context.Context, rt runtime.Runtime, sandbox *models.Sandbox) error {
	cr, ok := runtime.AsContainerRuntime(rt)
	if !ok {
		if !sandbox.NetworkBlockAll && len(sandbox.NetworkAllowOut) == 0 && len(sandbox.NetworkDenyOut) == 0 {
			return nil
		}
		return fmt.Errorf("runtime %q does not support network rules", sandbox.Runtime)
	}
	return s.enforceEgressOnStart(ctx, cr, sandbox)
}

// ipClaimedByOther reports whether a sandbox other than sandboxID may be using
// ip now: per the store (creating/started rows and claimed netns slots) or,
// when the runtime can tell, its live network view. Stop and destroy events
// arrive asynchronously, so by the time one is handled the IP may already
// belong to a new sandbox; clearing then would strip the new owner's DROP and
// leave it unrestricted (egress plan P0-6). A lookup error also counts as
// claimed: a stale rule left behind fails closed and reconcile cleans it,
// while a wrong clear fails open.
func (s *Service) ipClaimedByOther(ctx context.Context, sandboxID, ip string, cr runtime.ContainerRuntime) bool {
	holder, known := s.ipHolder(ctx, cr, ip, sandboxID)
	switch {
	case !known:
		s.logger.Warn("skip event rule clear: ip owner unknown", "sandbox_id", sandboxID, "ip", ip)
		return true
	case holder != "":
		s.logger.Info("skip event rule clear: ip reassigned", "sandbox_id", sandboxID, "ip", ip, "new_owner", holder)
		return true
	}
	return false
}
