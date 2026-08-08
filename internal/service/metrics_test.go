package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestBeginSandboxCreateMetricTracksSuccessAndTimeouts(t *testing.T) {
	totalBefore := createRequestsTotal.Value()
	timeoutErrorsBefore := expvarMapValue(createErrors, "timeout")
	timeoutsBefore := expvarMapValue(createTimeouts, "timeout")

	success := beginSandboxCreateMetric()
	if got := createQueueDepth.Value(); got < 1 {
		t.Fatalf("queue depth during in-flight create = %d, want >= 1", got)
	}
	success(nil)
	if got := createRequestsTotal.Value() - totalBefore; got != 1 {
		t.Fatalf("successful create request delta = %d, want 1", got)
	}
	if got := createQueueDepth.Value(); got != 0 {
		t.Fatalf("queue depth after successful create = %d, want 0", got)
	}

	failure := beginSandboxCreateMetric()
	failure(context.DeadlineExceeded)
	if got := createRequestsTotal.Value() - totalBefore; got != 2 {
		t.Fatalf("total create request delta = %d, want 2", got)
	}
	if got := expvarMapValue(createErrors, "timeout") - timeoutErrorsBefore; got != 1 {
		t.Fatalf("timeout error delta = %d, want 1", got)
	}
	if got := expvarMapValue(createTimeouts, "timeout") - timeoutsBefore; got != 1 {
		t.Fatalf("timeout counter delta = %d, want 1", got)
	}
}

func TestMetricHelpersIncrementExpectedCounters(t *testing.T) {
	reservationBefore := expvarMapValue(createReservationStates, "ready")
	expiredBefore := createReservationExpired.Value()
	replaysBefore := expvarMapValue(facadeIdempotencyReplays, "e2b_create")
	conflictsBefore := expvarMapValue(facadeIdempotencyConflicts, "e2b_create")
	decryptBefore := clusterSecretOpenTotal.Value()
	secretDeniedBefore := expvarMapValue(clusterSecretOpenErrors, "recipient_denied")
	secretRecipientDeniesBefore := clusterSecretRecipientDenies.Value()
	keyMismatchBefore := clusterSecretKeyMismatches.Value()

	RecordCreateReservationState("ready")
	RecordExpiredReservations(3)
	RecordExpiredReservations(0)
	RecordFacadeIdempotencyReplay("e2b.create")
	RecordFacadeIdempotencyConflict("e2b.create")
	secretDone := beginClusterSecretOpen()
	secretDone(errors.New("recipient not allowed to open this payload"))
	recordClusterSecretKeyMismatch()

	if got := expvarMapValue(createReservationStates, "ready") - reservationBefore; got != 1 {
		t.Fatalf("reservation state delta = %d, want 1", got)
	}
	if got := createReservationExpired.Value() - expiredBefore; got != 3 {
		t.Fatalf("expired reservation delta = %d, want 3", got)
	}
	if got := expvarMapValue(facadeIdempotencyReplays, "e2b_create") - replaysBefore; got != 1 {
		t.Fatalf("replay metric delta = %d, want 1", got)
	}
	if got := expvarMapValue(facadeIdempotencyConflicts, "e2b_create") - conflictsBefore; got != 1 {
		t.Fatalf("conflict metric delta = %d, want 1", got)
	}
	if got := clusterSecretOpenTotal.Value() - decryptBefore; got != 1 {
		t.Fatalf("secret open total delta = %d, want 1", got)
	}
	if got := expvarMapValue(clusterSecretOpenErrors, "recipient_denied") - secretDeniedBefore; got != 1 {
		t.Fatalf("recipient denied metric delta = %d, want 1", got)
	}
	if got := clusterSecretRecipientDenies.Value() - secretRecipientDeniesBefore; got != 1 {
		t.Fatalf("recipient denied total delta = %d, want 1", got)
	}
	if got := clusterSecretKeyMismatches.Value() - keyMismatchBefore; got != 1 {
		t.Fatalf("key mismatch delta = %d, want 1", got)
	}

	retractBefore := expvarMapValue(clusterPromoteRetractTotal, "ok")
	RecordPromoteRetract("ok")
	if got := expvarMapValue(clusterPromoteRetractTotal, "ok") - retractBefore; got != 1 {
		t.Fatalf("promote retract ok delta = %d, want 1", got)
	}

	unknownBefore := expvarMapValue(clusterPromoteRetractTotal, "unknown")
	RecordPromoteRetract("")
	RecordPromoteRetract("   ")
	if got := expvarMapValue(clusterPromoteRetractTotal, "unknown") - unknownBefore; got != 2 {
		t.Fatalf("promote retract unknown delta = %d, want 2", got)
	}
	destroyFailedBefore := expvarMapValue(clusterPromoteRetractTotal, "destroy_failed")
	RecordPromoteRetract("destroy_failed")
	if got := expvarMapValue(clusterPromoteRetractTotal, "destroy_failed") - destroyFailedBefore; got != 1 {
		t.Fatalf("promote retract destroy_failed delta = %d, want 1", got)
	}
}

func TestClassifyMetricErrorsAndHelpers(t *testing.T) {
	if got := classifyServiceMetricError(capacity.ErrCapacityExceeded); got != "capacity" {
		t.Fatalf("capacity error classification = %q, want capacity", got)
	}
	if got := classifyServiceMetricError(errors.New("runtime kata not implemented")); got != "runtime_not_implemented" {
		t.Fatalf("runtime error classification = %q, want runtime_not_implemented", got)
	}
	if got := classifyServiceMetricError(errors.New("name already in use")); got != "name_conflict" {
		t.Fatalf("name conflict classification = %q, want name_conflict", got)
	}
	if got := classifyServiceMetricError(errors.New("reservation conflict while allocating")); got != "reservation_conflict" {
		t.Fatalf("reservation conflict classification = %q, want reservation_conflict", got)
	}
	if got := classifyServiceMetricError(errors.New("must be greater than zero")); got != "validation" {
		t.Fatalf("validation classification = %q, want validation", got)
	}

	if got := classifySecretMetricError(errors.New("version mismatch for cluster secret ref")); got != "key_version_mismatch" {
		t.Fatalf("secret key mismatch classification = %q, want key_version_mismatch", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: placement", secrets.ErrVersionMismatch)); got != "key_version_mismatch" {
		t.Fatalf("sentinel version mismatch = %q, want key_version_mismatch", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: node-b", secrets.ErrRecipientDenied)); got != "recipient_denied" {
		t.Fatalf("sentinel recipient denied = %q, want recipient_denied", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: ref", secrets.ErrNotFound)); got != "ref_not_found" {
		t.Fatalf("sentinel not found = %q, want ref_not_found", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: unwrap", secrets.ErrDecryptFailed)); got != "decrypt_failed" {
		t.Fatalf("sentinel decrypt failed = %q, want decrypt_failed", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: down", secrets.ErrProviderUnavailable)); got != "provider_unavailable" {
		t.Fatalf("sentinel provider unavailable = %q, want provider_unavailable", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: rate", secrets.ErrProviderThrottled)); got != "provider_throttled" {
		t.Fatalf("sentinel provider throttled = %q, want provider_throttled", got)
	}
	if got := classifySecretMetricError(fmt.Errorf("%w: iam", secrets.ErrProviderDenied)); got != "provider_denied" {
		t.Fatalf("sentinel provider denied = %q, want provider_denied", got)
	}
	if got := classifySecretMetricError(errors.New("decrypt failed")); got != "decrypt_failed" {
		t.Fatalf("secret decrypt classification = %q, want decrypt_failed", got)
	}
	if got := classifySecretMetricError(errors.New("unmarshal payload")); got != "decode_failed" {
		t.Fatalf("secret decode classification = %q, want decode_failed", got)
	}

	if got := idempotencyScope("   "); got != "unknown" {
		t.Fatalf("blank idempotency scope = %q, want unknown", got)
	}
	if got := idempotencyState(nil); got != "unknown" {
		t.Fatalf("nil idempotency record state = %q, want unknown", got)
	}
	if got := idempotencyState(&models.IdempotentRequestRecord{State: models.RequestStateReady}); got != "ready" {
		t.Fatalf("ready idempotency state = %q, want ready", got)
	}
	if got := idempotencyState(&models.IdempotentRequestRecord{State: models.RequestStatePending}); got != "pending" {
		t.Fatalf("pending idempotency state = %q, want pending", got)
	}
}
