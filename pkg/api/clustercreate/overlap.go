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
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// OverlapPhase names which leg failed after an overlapped reserved-path create.
// Handlers use errors.As(*OverlapFailure) to map to the right HTTP status.
const (
	OverlapPhaseCreate  = "create"
	OverlapPhaseSeal    = "seal"
	OverlapPhasePromote = "promote"
)

// OverlapFailure is returned when either overlapped leg fails. Retract has
// already been attempted; the handler should surface Err (not invent a new
// shape). Phase distinguishes create vs seal vs promote for status mapping.
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

// OverlapOptions configures reserved-path create∥seal+promote.
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

type promoteLegResult struct {
	secrets    cluster.PlacementSecrets
	sealErr    error
	promoteErr error
}

// OverlapCreateAndPromote runs CreateSandboxWithID in parallel with
// PutClusterSecretsForRecipient + RecordPlacement, joins both before
// returning, and synchronously retracts any committed side effects on
// failure (plans/warm-create-latency-tier1.5-seal-promote-overlap.md).
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
	// Always join promoteCh, then retract deterministically.
	commitCtx, commitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer commitCancel()

	createCh := make(chan createLegResult, 1)
	promoteCh := make(chan promoteLegResult, 1)

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
		var out promoteLegResult
		stage := OverlapPhaseSeal
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("clustercreate: %s leg panicked: %v", stage, r)
				if stage == OverlapPhaseSeal {
					out.sealErr = err
				} else {
					out.promoteErr = err
				}
				promoteCh <- out
			}
		}()
		sealStart := time.Now()
		secrets, sealErr := svc.PutClusterSecretsForRecipient(commitCtx, reservationID, req, c.SelfNodeID())
		if opts.Timing != nil {
			opts.Timing.RecordStage("cluster_seal", time.Since(sealStart))
		}
		if sealErr != nil {
			out.sealErr = sealErr
			promoteCh <- out
			return
		}
		out.secrets = secrets
		stage = OverlapPhasePromote
		promoteStart := time.Now()
		if opts.PromoteWithSpec {
			redacted := service.RedactClusterSecrets(req)
			out.promoteErr = c.RecordPlacement(commitCtx, reservationID, &redacted, secrets)
		} else {
			out.promoteErr = c.RecordPlacement(commitCtx, reservationID, nil, secrets)
		}
		if opts.Timing != nil {
			opts.Timing.RecordStage("cluster_promote", time.Since(promoteStart))
		}
		promoteCh <- out
	}()

	cr := <-createCh
	pr := <-promoteCh

	if cr.err == nil && pr.sealErr == nil && pr.promoteErr == nil {
		return cr.resp, nil
	}

	retractAfterOverlap(context.Background(), svc, c, logger, reservationID, cr, pr)

	switch {
	case cr.err != nil:
		return nil, &OverlapFailure{Phase: OverlapPhaseCreate, Err: cr.err}
	case pr.sealErr != nil:
		return nil, &OverlapFailure{Phase: OverlapPhaseSeal, Err: pr.sealErr}
	default:
		return nil, &OverlapFailure{Phase: OverlapPhasePromote, Err: pr.promoteErr}
	}
}

// retractAfterOverlap is the Option A sync retract from the Tier 1.5 plan.
// Order: DeletePlacement (mandatory — covers Placed and ambiguous promote
// errors) → CancelReservation (still-Reserved) → DeleteClusterSecrets →
// DestroySandbox best-effort. Surfaces the original create/seal/promote
// error to the caller; retract failure is operational (metric + log).
func retractAfterOverlap(
	ctx context.Context,
	svc *service.Service,
	c cluster.Client,
	logger *slog.Logger,
	sandboxID string,
	cr createLegResult,
	pr promoteLegResult,
) {
	rbCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := "ok"
	if c != nil {
		if err := c.DeletePlacement(rbCtx, sandboxID); err != nil {
			result = "delete_placement_failed"
			if logger != nil {
				logger.Error("cluster: DeletePlacement after overlap failure failed",
					"sandbox_id", sandboxID, "err", err,
					"create_err", errString(cr.err),
					"seal_err", errString(pr.sealErr),
					"promote_err", errString(pr.promoteErr))
			}
		}
		cancelReservation(rbCtx, c, logger, sandboxID)
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

	if err := svc.DestroySandbox(rbCtx, sandboxID); err != nil {
		if logger != nil {
			// Create already failed → Destroy often sees not-found after the
			// service rolled back its own partial state; keep it quiet.
			if cr.err == nil {
				logger.Error("cluster: rollback destroy after overlap failure failed",
					"sandbox_id", sandboxID, "err", err)
			} else {
				logger.Warn("cluster: best-effort destroy after create failure",
					"sandbox_id", sandboxID, "err", err)
			}
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
