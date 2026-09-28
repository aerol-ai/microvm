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
	"github.com/aerol-ai/microvm/pkg/secrets"
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
// SealAndDistribute (the seal), joins both, and only then
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
// Reserved path only — reservationID must be non-empty. The local-image
// CreateSandbox path (no ID) stays sequential at the call site.
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
	if !svc.ClusterEnabled() {
		return svc.CreateSandboxWithID(ctx, req, reservationID)
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
	sealStart := time.Now()
	binding, bindingErr := svc.ReservedSecretBinding(commitCtx, reservationID)
	if bindingErr != nil {
		if opts.Timing != nil {
			opts.Timing.RecordStage("cluster_seal", time.Since(sealStart))
		}
		// No local side effect has started. Release only this reservation; its
		// incarnation-fenced CancelReservation implementation makes a delayed
		// cleanup harmless after ID reuse.
		if err := c.CancelReservation(commitCtx, reservationID); err != nil && logger != nil {
			logger.Warn("cluster: cancel reservation after binding failure",
				"sandbox_id", reservationID, "err", err)
		}
		return nil, &OverlapFailure{Phase: OverlapPhaseSeal, Err: bindingErr}
	}
	createCtx := secrets.ContextWithIncarnationID(ctx, binding.IncarnationID)
	sealCtx := secrets.ContextWithIncarnationID(commitCtx, binding.IncarnationID)

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
		resp, err := svc.CreateSandboxWithID(createCtx, req, reservationID)
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
		// HA creates: local seal only on this path; async fan-out is off-path
		// (plans/secrets-hardening §3e). cluster_seal timing stays local seal.
		sealed, err := svc.SealAndDistribute(sealCtx, reservationID, req, binding.Recipients)
		if opts.Timing != nil {
			opts.Timing.RecordStage("cluster_seal", time.Since(sealStart))
		}
		sealCh <- sealLegResult{secrets: sealed, err: err}
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
		if sr.secrets.IncarnationID == "" {
			sr.secrets.IncarnationID = cr.resp.Sandbox.AuditIncarnationID
		}
		sr.secrets.OwnerRef = cr.resp.Sandbox.OwnerRef
	}

	promoteStart := time.Now()
	var promoteErr error
	if opts.PromoteWithSpec {
		redacted := service.RedactClusterSecrets(req)
		promoteErr = c.RecordPlacement(commitCtx, reservationID, &redacted, sr.secrets)
	} else {
		promoteErr = c.RecordPlacement(commitCtx, reservationID, nil, sr.secrets)
	}
	if opts.Timing != nil {
		opts.Timing.RecordStage("cluster_promote", time.Since(promoteStart))
	}
	if promoteErr != nil {
		retractFailedPromote(context.Background(), svc, logger, reservationID)
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
	destroyErr := svc.DestroySandbox(rbCtx, sandboxID)
	if destroyErr != nil {
		switch {
		case errors.Is(destroyErr, service.ErrClusterFinalizationUnavailable):
			result = "delete_placement_failed"
			if logger != nil {
				logger.Error("cluster: rollback placement finalization failed; retaining local row",
					"sandbox_id", sandboxID, "err", destroyErr)
			}
		case createErr == nil:
			// Create succeeded (seal failed) — this destroy failure leaves a
			// live local sandbox that ownership replay can resurrect.
			result = "destroy_failed"
			if logger != nil {
				logger.Error("cluster: rollback destroy after overlap failure failed",
					"sandbox_id", sandboxID, "err", destroyErr)
			}
		case errors.Is(destroyErr, store.ErrNotFound):
			// Create already failed → Destroy sees not-found after the service
			// rolled back its own partial state. This is the expected outcome,
			// not a rollback failure; keep the metric at ok and the log quiet.
			if logger != nil {
				logger.Warn("cluster: best-effort destroy after create failure",
					"sandbox_id", sandboxID, "err", destroyErr)
			}
		default:
			// The create leg failed AND destroy failed for a reason other than
			// not-found — the create's own rollback may have left runtime state
			// behind. The metric must not report ok, or the only rollback
			// failure signal is a Warn log nobody alerts on.
			result = "destroy_failed"
			if logger != nil {
				logger.Error("cluster: rollback destroy after create failure failed",
					"sandbox_id", sandboxID, "err", destroyErr,
					"create_err", errString(createErr))
			}
		}
	}

	// DestroySandbox already removes secrets when it succeeds. A create-leg
	// failure commonly leaves no sandbox row; in that one expected not-found
	// case, clean the independently completed seal against the still-live
	// reservation. Any other destroy failure may mean a live runtime remains,
	// so retain secrets and placement together for reconciliation.
	destroyComplete := destroyErr == nil || (createErr != nil && errors.Is(destroyErr, store.ErrNotFound))
	secretCleanupOK := true
	if destroyComplete && destroyErr != nil {
		if err := svc.DeleteClusterSecretsForAuthoritativePlacement(rbCtx, sandboxID); err != nil {
			secretCleanupOK = false
			if result == "ok" {
				result = "delete_secrets_failed"
			}
			if logger != nil {
				logger.Warn("cluster: DeleteClusterSecrets after overlap failure failed",
					"sandbox_id", sandboxID, "err", err)
			}
		}
	}

	// A successful DestroySandbox already removed the exact self-owned
	// reservation before deleting the local row. Only the expected create-leg
	// not-found case still needs an explicit reservation cancel.
	if c != nil && destroyErr != nil && destroyComplete && secretCleanupOK {
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

	service.RecordPromoteRetract(result)
}

// retractFailedPromote handles a promote that errored after a successful
// create+seal. DestroySandbox performs the owner+incarnation-fenced placement
// delete after runtime/secret finalization and before removing the local row,
// so an ambiguous Raft promote cannot leave a recreatable ghost placement.
func retractFailedPromote(
	ctx context.Context,
	svc *service.Service,
	logger *slog.Logger,
	sandboxID string,
) {
	rbCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := "ok"
	destroyErr := svc.DestroySandbox(rbCtx, sandboxID)
	if destroyErr != nil {
		result = "destroy_failed"
		if errors.Is(destroyErr, service.ErrClusterFinalizationUnavailable) {
			result = "delete_placement_failed"
		}
		if logger != nil {
			logger.Error("cluster: rollback destroy after promote failure failed",
				"sandbox_id", sandboxID, "err", destroyErr)
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
