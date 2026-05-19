package service

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
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
