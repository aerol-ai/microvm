package clustercreate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// OverlapPhase names which step failed on the overlapped reserved-path create.
// Handlers use errors.As(*OverlapFailure) to map to the right HTTP status.
const (
	OverlapPhaseCreate  = "create"
	OverlapPhaseSeal    = "seal"
	OverlapPhasePromote = "promote"
)

// OverlapFailure is returned when the create leg, seal leg, or the post-join
// promote fails. Retract has already been attempted; the handler should
// surface Err (not invent a new shape). Phase distinguishes create vs seal vs
// promote for status mapping.
type OverlapFailure struct {
	Phase string
	Err   error
}

func (f *OverlapFailure) Error() string {
	if f == nil || f.Err == nil {
		return "clustercreate: overlap failure"
	}
	return f.Err.Error()
}

func (f *OverlapFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Err
}

// OverlapOptions configures reserved-path create∥seal.
type OverlapOptions struct {
	// PromoteWithSpec includes the redacted create request in RecordPlacement.
	// v1 always wants true; Daytona/E2B facades pass true; helpers that rely
	// on the reservation-held spec pass false.
	PromoteWithSpec bool
	Timing          *createtiming.CreateTiming
}

type createLegResult struct {
	resp *models.CreateSandboxResponse
	err  error
}

type sealLegResult struct {
	secrets cluster.PlacementSecrets
	err     error
}

// OverlapCreateAndPromote runs CreateSandboxWithID in parallel with
// PutClusterSecretsForRecipient (the seal), joins both, and only then
// promotes via RecordPlacement
// (plans/warm-create-latency-tier1.5-seal-promote-overlap.md).
//
// Promote is deliberately NOT overlapped with the create. The FSM releases
// the pending-reservation accounting on opPlace, and that accounting is what
// ClusterCreateMaxPendingPerWorker backpressure and SelectPlacement's
// double-booking guard count — promoting early would uncharge an in-flight
// local create. It is also what keeps the placement invisible to the owner
// watcher, which would otherwise start a concurrent recreate of a
// failover-enabled sandbox whose local create outlives one 5s watcher tick.
// The row must stay Reserved until the local create has succeeded.
//
// Reserved path only — reservationID must be non-empty. Self-wins /
// CreateSandbox (no ID) stays sequential at the call site.
func OverlapCreateAndPromote(
	ctx context.Context,
	svc *service.Service,
	logger *slog.Logger,
	req models.CreateSandboxRequest,
	reservationID string,
	opts OverlapOptions,
) (*models.CreateSandboxResponse, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return nil, errors.New("clustercreate: OverlapCreateAndPromote requires reservationID")
	}
	if svc == nil {
		return nil, errors.New("clustercreate: service is nil")
	}
	c := svc.Cluster()
	if c == nil {
		return svc.CreateSandboxWithID(ctx, req, reservationID)
	}

	// commitCtx is derived from the request so an overall deadline still
	// bounds seal+promote, but we NEVER treat cancelling it as cleanup: a
	// Raft apply can fail client-side and still land in the FSM (§2.2).
	commitCtx, commitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer commitCancel()

	createCh := make(chan createLegResult, 1)
	sealCh := make(chan sealLegResult, 1)

	// Both legs run in bare goroutines, where a panic is fatal to the whole
	// daemon — net/http's per-request recover does not extend to goroutines
	// the handler spawns. Convert panics to leg failures so the join +
	// retract path runs and the request degrades to an error response, the
	// same blast radius the sequential code had.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				createCh <- createLegResult{err: fmt.Errorf("clustercreate: create leg panicked: %v", r)}
			}
		}()
		start := time.Now()
		resp, err := svc.CreateSandboxWithID(ctx, req, reservationID)
		if opts.Timing != nil {
			opts.Timing.RecordStage("create_with_id", time.Since(start))
		}
		createCh <- createLegResult{resp: resp, err: err}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				sealCh <- sealLegResult{err: fmt.Errorf("clustercreate: seal leg panicked: %v", r)}
			}
		}()
		start := time.Now()
		// HA creates: local seal only on this path; async fan-out is off-path
		// (plans/secrets-hardening §3e). cluster_seal timing stays local seal.
		secrets, err := svc.SealAndDistribute(commitCtx, reservationID, req, svc.SecretRecipientsForSeal(reservationID), service.SealStrict)
		if opts.Timing != nil {
			opts.Timing.RecordStage("cluster_seal", time.Since(start))
		}
		sealCh <- sealLegResult{secrets: secrets, err: err}
	}()

	cr := <-createCh
	sr := <-sealCh

	if cr.err != nil || sr.err != nil {
		// Promote was never attempted, so the FSM row is still Reserved —
		// CancelReservation is the correct release; no ambiguity to resolve.
		retractReservedCreate(context.Background(), svc, c, logger, reservationID, cr.err)
		if cr.err != nil {
			return nil, &OverlapFailure{Phase: OverlapPhaseCreate, Err: cr.err}
		}
		return nil, &OverlapFailure{Phase: OverlapPhaseSeal, Err: sr.err}
	}
	if cr.resp != nil {
		sr.secrets.OwnerRef = cr.resp.Sandbox.OwnerRef
	}

	promoteStart := time.Now()
	var promoteErr error
	if opts.PromoteWithSpec {
		redacted := service.RedactClusterSecretsOpts(req, svc != nil && svc.SecretEnvSealEnabled())
		promoteErr = c.RecordPlacement(commitCtx, reservationID, &redacted, sr.secrets)
	} else {
		promoteErr = c.RecordPlacement(commitCtx, reservationID, nil, sr.secrets)
	}
	if opts.Timing != nil {
		opts.Timing.RecordStage("cluster_promote", time.Since(promoteStart))
	}
	if promoteErr != nil {
		retractFailedPromote(context.Background(), svc, c, logger, reservationID)
		return nil, &OverlapFailure{Phase: OverlapPhasePromote, Err: promoteErr}
	}
	return cr.resp, nil
}

// retractReservedCreate cleans up after a create- or seal-leg failure, while
// the FSM row is still Reserved. Order matters: DestroySandbox runs FIRST,
// because a local sandbox that outlives its reservation gets re-asserted into
// a fresh placement by ReplayClusterOwnership — resurrecting a create the
// client was told failed. Only after the local truth is gone do we release
// the reservation and the sealed secrets. The original leg error is what the
// caller surfaces; retract failures are operational (metric + log).
func retractReservedCreate(
	ctx context.Context,
	svc *service.Service,
	c cluster.Client,
	logger *slog.Logger,
	sandboxID string,
	createErr error,
) {
	rbCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := "ok"
	if err := svc.DestroySandbox(rbCtx, sandboxID); err != nil {
		switch {
		case createErr == nil:
			// Create succeeded (seal failed) — this destroy failure leaves a
			// live local sandbox that ownership replay can resurrect.
			result = "destroy_failed"
			if logger != nil {
				logger.Error("cluster: rollback destroy after overlap failure failed",
					"sandbox_id", sandboxID, "err", err)
			}
		case errors.Is(err, store.ErrNotFound):
			// Create already failed → Destroy sees not-found after the service
			// rolled back its own partial state. This is the expected outcome,
			// not a rollback failure; keep the metric at ok and the log quiet.
			if logger != nil {
				logger.Warn("cluster: best-effort destroy after create failure",
					"sandbox_id", sandboxID, "err", err)
			}
		default:
			// The create leg failed AND destroy failed for a reason other than
			// not-found — the create's own rollback may have left runtime state
			// behind. The metric must not report ok, or the only rollback
			// failure signal is a Warn log nobody alerts on.
			result = "destroy_failed"
			if logger != nil {
				logger.Error("cluster: rollback destroy after create failure failed",
					"sandbox_id", sandboxID, "err", err,
					"create_err", errString(createErr))
			}
		}
	}

	if c != nil {
		if err := c.CancelReservation(rbCtx, sandboxID); err != nil {
			if result == "ok" {
				result = "cancel_failed"
			}
			if logger != nil {
				logger.Warn("cluster: cancel reservation after overlap failure failed",
					"sandbox_id", sandboxID, "err", err,
					"create_err", errString(createErr))
			}
		}
	}

	if err := svc.DeleteClusterSecrets(rbCtx, sandboxID); err != nil {
		if result == "ok" {
			result = "delete_secrets_failed"
		}
		if logger != nil {
			logger.Warn("cluster: DeleteClusterSecrets after overlap failure failed",
				"sandbox_id", sandboxID, "err", err)
		}
	}

	service.RecordPromoteRetract(result)
}

// retractFailedPromote handles a promote that errored after a successful
// create+seal. A client-side Raft error can still have committed in the FSM
// (§2.2 of the Tier 1.5 plan), so DeletePlacement is mandatory — opDelete
// removes both Placed and still-Reserved rows and releases the
// pending-reservation accounting, which is why no separate CancelReservation
// is needed here. Destroy runs first for the same ownership-replay reason as
// retractReservedCreate.
func retractFailedPromote(
	ctx context.Context,
	svc *service.Service,
	c cluster.Client,
	logger *slog.Logger,
	sandboxID string,
) {
	rbCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := "ok"
	if err := svc.DestroySandbox(rbCtx, sandboxID); err != nil {
		result = "destroy_failed"
		if logger != nil {
			logger.Error("cluster: rollback destroy after promote failure failed",
				"sandbox_id", sandboxID, "err", err)
		}
	}

	if c != nil {
		if err := c.DeletePlacement(rbCtx, sandboxID); err != nil {
			if result == "ok" {
				result = "delete_placement_failed"
			}
			if logger != nil {
				logger.Error("cluster: DeletePlacement after promote failure failed",
					"sandbox_id", sandboxID, "err", err)
			}
		}
	}

	if err := svc.DeleteClusterSecrets(rbCtx, sandboxID); err != nil {
		if result == "ok" {
			result = "delete_secrets_failed"
		}
		if logger != nil {
			logger.Warn("cluster: DeleteClusterSecrets after promote failure failed",
				"sandbox_id", sandboxID, "err", err)
		}
	}

	service.RecordPromoteRetract(result)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// AsOverlapFailure extracts an OverlapFailure from err, if present.
func AsOverlapFailure(err error) (*OverlapFailure, bool) {
	return errors.AsType[*OverlapFailure](err)
}

// FormatSealError matches the v1 handler's historical seal-fail message.
func FormatSealError(err error) string {
	return fmt.Sprintf("cluster: store secret ref: %v", err)
}

// FormatPromoteError matches the v1 handler's historical promote-fail message.
func FormatPromoteError(err error) string {
	return fmt.Sprintf("cluster: placement commit failed: %v", err)
}
