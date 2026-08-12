package service

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

var (
	createRequestsTotal      = expvar.NewInt("aerolvm_create_requests_total")
	createQueueDepth         = expvar.NewInt("aerolvm_create_queue_depth")
	createErrors             = expvar.NewMap("aerolvm_create_errors_total")
	createAdmissionRejects   = expvar.NewMap("aerolvm_create_admission_rejects_total")
	createTimeouts           = expvar.NewMap("aerolvm_create_timeouts_total")
	createLastNanos          = expvar.NewInt("aerolvm_create_last_nanos")
	createLatency            = scaleobs.NewDurationBuckets("aerolvm_create_latency_seconds_bucket")
	createReservationStates  = expvar.NewMap("aerolvm_create_reservation_states_total")
	createReservationExpired = expvar.NewInt("aerolvm_create_reservations_expired_total")

	ingressRouteDesiredRevision = expvar.NewInt("aerolvm_ingress_route_desired_revision")
	ingressRouteAppliedRevision = expvar.NewInt("aerolvm_ingress_route_applied_revision")
	ingressRouteFailedRevision  = expvar.NewInt("aerolvm_ingress_route_failed_revision")
	ingressRoutesByShard        = expvar.NewMap("aerolvm_ingress_routes_by_shard")
	ingressCaddyOpsPending      = expvar.NewInt("aerolvm_ingress_caddy_ops_pending")
	ingressCaddyOpsInflight     = expvar.NewInt("aerolvm_ingress_caddy_ops_inflight")
	ingressCaddyBatchesTotal    = expvar.NewInt("aerolvm_ingress_caddy_batches_total")
	ingressCaddyBatchSizeLast   = expvar.NewInt("aerolvm_ingress_caddy_batch_size_last")

	facadeIdempotencyClaims    = expvar.NewMap("aerolvm_facade_idempotency_claims_total")
	facadeIdempotencyAcquired  = expvar.NewMap("aerolvm_facade_idempotency_acquired_total")
	facadeIdempotencyReplays   = expvar.NewMap("aerolvm_facade_idempotency_replays_total")
	facadeIdempotencyConflicts = expvar.NewMap("aerolvm_facade_idempotency_conflicts_total")
	facadeIdempotencyComplete  = expvar.NewMap("aerolvm_facade_idempotency_complete_total")
	facadeIdempotencyDeletes   = expvar.NewMap("aerolvm_facade_idempotency_deletes_total")

	clusterSecretOpenTotal       = expvar.NewInt("aerolvm_secret_decrypt_total")
	clusterSecretOpenErrors      = expvar.NewMap("aerolvm_secret_decrypt_errors_total")
	clusterSecretKeyMismatches   = expvar.NewInt("aerolvm_secret_key_version_mismatches_total")
	clusterSecretLastOpenNanos   = expvar.NewInt("aerolvm_secret_decrypt_last_nanos")
	clusterSecretOpenLatency     = scaleobs.NewDurationBuckets("aerolvm_secret_decrypt_latency_seconds_bucket")
	clusterSecretRecipientDenies = expvar.NewInt("aerolvm_secret_recipient_denied_total")
	// Peer fan-out failures (push or delete). HA create fails when its bounded
	// first-ACK window gets no backup; remaining replicas may still be converging
	// while failover_ready is false.
	secretFanoutFailuresTotal = expvar.NewInt("aerolvm_secret_fanout_failures_total")
	// Durable cleanup health. Gauges are refreshed by the boot/periodic
	// reconciler and remain cardinality-free at 100k+ concurrent sandboxes.
	secretDeleteOutboxPending          = expvar.NewInt("aerolvm_secret_delete_outbox_pending")
	secretDeleteOutboxOldestAgeSeconds = expvar.NewInt("aerolvm_secret_delete_outbox_oldest_age_seconds")
	secretPutOutboxPending             = expvar.NewInt("aerolvm_secret_put_outbox_pending")
	secretPutOutboxFailuresTotal       = expvar.NewInt("aerolvm_secret_put_outbox_failures_total")
	secretTombstones                   = expvar.NewInt("aerolvm_secret_tombstones")
	// secretProviderCanaryOK is 1 after a successful awskms boot canary, 0 after failure.
	secretProviderCanaryOK = expvar.NewInt("aerolvm_secret_provider_canary_ok")
	// Best-effort local seal failures (ownership replay backfill).
	clusterSecretSealBestEffortFailures = expvar.NewInt("aerolvm_secret_seal_best_effort_failures_total")
	// Promote-retract counter for overlapped reserved-path create
	// (plans/warm-create-latency-tier1.5-seal-promote-overlap.md). Keyed by
	// result so a DeletePlacement failure is visible without relying on logs.
	clusterPromoteRetractTotal = expvar.NewMap("aerolvm_cluster_promote_retract_total")

	// Wake metrics (D3 / C6 in plans/serverless-sandbox-http-wake.md).
	// requests_total counts every EnsureSandboxAwakeForHTTP entry — both
	// hot-path hits (already running) and cold starts; cold_starts_total
	// is incremented only when we actually invoke StartSandbox. failures
	// is keyed by classifyWakeError so operators can distinguish
	// admission/capacity stalls from manual-stop refusals and circuit
	// trips. wake_circuit_open is a gauge tracking how many sandboxes
	// currently have an open breaker — recorded inline by the wake
	// helper as ids enter/leave the open set.
	// Isolation-drift signal. Reconcile reapplies the NetworkBlockAll DROP
	// rule on every pass, so call count says nothing; these only move when
	// the rule was found *missing* and had to be re-installed — i.e. a host
	// reboot, an iptables flush, or a chain rebuild dropped a tenant's
	// isolation. Any non-zero rate is worth an operator's attention;
	// reapply_errors_total means the heal itself is failing and the sandbox
	// is currently un-isolated, which is page-worthy.
	networkBlockReapplyTotal  = expvar.NewInt("aerolvm_network_block_reapply_total")
	networkBlockReapplyErrors = expvar.NewInt("aerolvm_network_block_reapply_errors_total")

	wakeRequestsTotal   = expvar.NewInt("aerolvm_wake_requests_total")
	wakeColdStartsTotal = expvar.NewInt("aerolvm_wake_cold_starts_total")
	wakeFailuresTotal   = expvar.NewMap("aerolvm_wake_failures_total")
	wakeDuration        = scaleobs.NewDurationBuckets("aerolvm_wake_duration_seconds_bucket")
	wakeCircuitOpen     = expvar.NewInt("aerolvm_wake_circuit_open")
)

func beginSandboxCreateMetric() func(error) {
	createQueueDepth.Add(1)
	start := time.Now()
	return func(err error) {
		createQueueDepth.Add(-1)
		elapsed := time.Since(start)
		createRequestsTotal.Add(1)
		createLastNanos.Set(elapsed.Nanoseconds())
		createLatency.Observe(elapsed)
		if err == nil {
			return
		}
		reason := classifyServiceMetricError(err)
		scaleobs.Add(createErrors, reason, 1)
		if errors.Is(err, capacity.ErrCapacityExceeded) || reason == "no_placement_target" || reason == "validation" || reason == "runtime_not_implemented" {
			scaleobs.Add(createAdmissionRejects, reason, 1)
		}
		if reason == "timeout" || errors.Is(err, context.DeadlineExceeded) {
			scaleobs.Add(createTimeouts, reason, 1)
		}
	}
}

func RecordCreateReservationState(state string) {
	scaleobs.Add(createReservationStates, state, 1)
}

// RecordPromoteRetract increments aerolvm_cluster_promote_retract_total after
// an overlapped create/promote failure path finishes its sync retract.
// result is typically "ok", "delete_placement_failed", or
// "delete_secrets_failed".
func RecordPromoteRetract(result string) {
	result = strings.TrimSpace(result)
	if result == "" {
		result = "unknown"
	}
	scaleobs.Add(clusterPromoteRetractTotal, result, 1)
}

func RecordExpiredReservations(count int) {
	if count > 0 {
		createReservationExpired.Add(int64(count))
	}
}

func recordIngressCaddyBatch(size int) {
	ingressCaddyBatchesTotal.Add(1)
	ingressCaddyBatchSizeLast.Set(int64(size))
}

func queueIngressCaddyOp() func(bool) {
	ingressCaddyOpsPending.Add(1)
	return func(started bool) {
		ingressCaddyOpsPending.Add(-1)
		if started {
			ingressCaddyOpsInflight.Add(1)
		}
	}
}

func finishIngressCaddyOp() {
	ingressCaddyOpsInflight.Add(-1)
}

func RecordFacadeIdempotencyReplay(scope string) {
	scaleobs.Add(facadeIdempotencyReplays, scope, 1)
}

func RecordFacadeIdempotencyConflict(scope string) {
	scaleobs.Add(facadeIdempotencyConflicts, scope, 1)
}

func beginClusterSecretOpen() func(error) {
	start := time.Now()
	return func(err error) {
		elapsed := time.Since(start)
		clusterSecretOpenTotal.Add(1)
		clusterSecretLastOpenNanos.Set(elapsed.Nanoseconds())
		clusterSecretOpenLatency.Observe(elapsed)
		if err == nil {
			return
		}
		reason := classifySecretMetricError(err)
		scaleobs.Add(clusterSecretOpenErrors, reason, 1)
		if reason == "recipient_denied" {
			clusterSecretRecipientDenies.Add(1)
		}
	}
}

func recordClusterSecretKeyMismatch() {
	clusterSecretKeyMismatches.Add(1)
}

func recordSecretFanoutFailure() {
	secretFanoutFailuresTotal.Add(1)
}

func recordSecretProviderCanary(ok bool) {
	if ok {
		secretProviderCanaryOK.Set(1)
		return
	}
	secretProviderCanaryOK.Set(0)
}

func recordClusterSecretSealBestEffortFailure() {
	clusterSecretSealBestEffortFailures.Add(1)
}

// reapplyNetworkBlockAll heals the per-IP isolation rule and reports whether
// it was actually missing. Drivers that can't answer (anything not backed by
// netrules) still get healed — they just report inserted=false, so the drift
// counter under-reports rather than the heal silently not happening.
func reapplyNetworkBlockAll(cr runtime.ContainerRuntime, containerIP string) (bool, error) {
	if reporter, ok := runtime.AsNetworkBlockReporter(cr); ok {
		return reporter.ApplyNetworkBlockAllReport(containerIP)
	}
	return false, cr.ApplyNetworkBlockAll(containerIP)
}

// beginWakeMetric tags the start of an EnsureSandboxAwakeForHTTP call.
// The returned closure must be called exactly once with (coldStart,
// err). coldStart is true only when the helper actually invoked
// StartSandbox under the single-flight (hot-path hits leave it false).
// err is classified into a stable reason label so /debug/vars stays
// queryable without leaking arbitrary error strings into metric keys.
func beginWakeMetric() func(coldStart bool, err error) {
	start := time.Now()
	return func(coldStart bool, err error) {
		wakeRequestsTotal.Add(1)
		if coldStart {
			wakeColdStartsTotal.Add(1)
			wakeDuration.Observe(time.Since(start))
		}
		if err != nil {
			scaleobs.Add(wakeFailuresTotal, classifyWakeError(err), 1)
		}
	}
}

// classifyWakeError maps a wake error to one of a small fixed set of
// reason labels. The set is intentionally narrow: the wake helper has
// only a handful of distinct failure modes (manual-stop refusal,
// circuit-open, admission/capacity, start failure, timeout), and
// keeping the label space bounded prevents an expvar map blowup if a
// downstream error message ever varies.
func classifyWakeError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrSandboxManuallyStopped):
		return "manual_stopped"
	case errors.Is(err, ErrWakeCircuitOpen):
		return "circuit_open"
	case errors.Is(err, capacity.ErrCapacityExceeded):
		return "capacity"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"):
		return "timeout"
	case strings.Contains(msg, "capacity"):
		return "capacity"
	default:
		return "start_failed"
	}
}

func classifyServiceMetricError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, capacity.ErrCapacityExceeded) {
		return "capacity"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no placement target"):
		return "no_placement_target"
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"):
		return "timeout"
	case strings.Contains(msg, "runtime") && strings.Contains(msg, "not implemented"):
		return "runtime_not_implemented"
	case strings.Contains(msg, "image is required"), strings.Contains(msg, "invalid "), strings.Contains(msg, "too many mounts"), strings.Contains(msg, "must be"):
		return "validation"
	case strings.Contains(msg, "name already in use"):
		return "name_conflict"
	case strings.Contains(msg, "reservation conflict"):
		return "reservation_conflict"
	default:
		return "error"
	}
}

func classifySecretMetricError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, secrets.ErrVersionMismatch):
		return "key_version_mismatch"
	case errors.Is(err, secrets.ErrRecipientDenied):
		return "recipient_denied"
	case errors.Is(err, secrets.ErrNotFound):
		return "ref_not_found"
	case errors.Is(err, secrets.ErrDecryptFailed):
		return "decrypt_failed"
	case errors.Is(err, secrets.ErrProviderUnavailable):
		return "provider_unavailable"
	case errors.Is(err, secrets.ErrProviderThrottled):
		return "provider_throttled"
	case errors.Is(err, secrets.ErrProviderDenied):
		return "provider_denied"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "version mismatch"):
		return "key_version_mismatch"
	case strings.Contains(msg, "not allowed to open"):
		return "recipient_denied"
	case strings.Contains(msg, "not found"):
		return "ref_not_found"
	case strings.Contains(msg, "unwrap"):
		return "unwrap_failed"
	case strings.Contains(msg, "decrypt"):
		return "decrypt_failed"
	case strings.Contains(msg, "unmarshal"):
		return "decode_failed"
	default:
		return "error"
	}
}

func idempotencyScope(scope string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return "unknown"
	}
	return scope
}

func idempotencyState(record *models.IdempotentRequestRecord) string {
	if record == nil {
		return "unknown"
	}
	switch record.State {
	case models.RequestStateReady:
		return "ready"
	case models.RequestStatePending:
		return "pending"
	default:
		return "unknown"
	}
}
