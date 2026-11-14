package cluster

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Carrying an apply verdict across the wire.
//
// A forwarded raft write is answered by an HTTP status, and a verdict that
// arrives as a generic 500 is indistinguishable from a transient apply
// failure. That distinction is load-bearing for the catalogue: a transient
// failure is retried unchanged, whereas a SUPERSEDED publication must make
// the publisher drop its fencing token and ask for a new one. A publisher
// that cannot tell them apart republishes forever under an epoch the
// authority has moved past, and its coverage never tracks its inventory
// again. Both apply listeners classify through ApplyErrorStatus and both
// forwarding clients invert it through forwardApplyStatus.

// ApplyErrorStatus is the HTTP status an apply listener answers a failed
// apply with. It is exported because the v1 apply handler is the other
// listener and has to answer a given verdict identically.
func ApplyErrorStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusNoContent
	case errors.Is(err, ErrNotLeader):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrCreateBackpressure):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrTeamQuotaExceeded):
		// A team at its quota. 429 like the API answer; the message names
		// the sentinel so forwardApplyStatus restores it, not backpressure.
		return http.StatusTooManyRequests
	case errors.Is(err, ErrCapacityExceeded), errors.Is(err, ErrNoPlacementTarget):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrArtifactCatalogSuperseded):
		// Conflict, not a server error: the state the caller asked for lost
		// to a newer one, and re-sending the same request cannot succeed.
		return http.StatusConflict
	case errors.Is(err, ErrReservationConflict), errors.Is(err, ErrNameConflict):
		// A placement-id or name conflict is a conflict, not a server error:
		// the slot the caller asked for is already held, and re-sending the
		// same request unchanged cannot succeed. Answering 409 (instead of the
		// default 500) is what lets forwardApplyStatus restore the sentinel on
		// the far side of a leader-forward hop, so the create path's
		// idempotent-replay branch (PreferredSandboxID + ErrReservationConflict)
		// and its name-conflict branch fire on a non-leader node exactly as
		// they already do when the apply lands on the local leader. Without it
		// a retry of an Idempotency-Key create on a multi-node cluster 503s
		// instead of replaying the existing sandbox.
		return http.StatusConflict
	case errors.Is(err, ErrPlacementUnsatisfiable):
		// The leader refused a reservation onto a node the sandbox's
		// placement rule excludes. A verdict, not a fault: as a 500 the
		// router would answer a retryable 503 for a rule no retry satisfies.
		return http.StatusConflict
	case errors.Is(err, ErrIncarnationConflict):
		// An incarnation fence is a verdict too: the placement moved to
		// another incarnation, and re-sending the same write cannot succeed.
		// The create path routes an Idempotency-Key retry whose re-reserve
		// hit it to the reservation's owner (clustercreate.Prepare), which
		// only works if the sentinel survives the hop; as a 500 the retry
		// answered 503 (seen live on cluster-hetero-lite, UC-367).
		return http.StatusConflict
	case errors.Is(err, ErrSpecVersionConflict):
		// A verdict: the spec moved on since the writer read it. The
		// writer reads it again (spec_version_fence.go), which it can only
		// do if the sentinel survives the hop; as a 500 the change was
		// dropped with a warning.
		return http.StatusConflict
	case errors.Is(err, ErrPlacementDeleted):
		// A verdict: the lifetime is deleted for good. As a 500 a returning
		// node's ownership replay could not tell it from a transient fault
		// and would keep its copy of a deleted sandbox.
		return http.StatusConflict
	case errors.Is(err, ErrMoveHandoffMoved), errors.Is(err, ErrMoveHandoffAborted):
		// Verdicts of a move handoff (fsm_move_handoff.go): the sandbox
		// moved, or its source took it back. A source must tell "moved"
		// from a fault, or it would retry a start that is not its own.
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// ApplyErrorRetryAfterSeconds is the Retry-After an apply listener sets for
// a failure that is worth retrying on a delay; 0 means none.
func ApplyErrorRetryAfterSeconds(err error) int {
	switch {
	case errors.Is(err, ErrCreateBackpressure):
		return CreateBackpressureRetryAfterSeconds
	case errors.Is(err, ErrCapacityExceeded), errors.Is(err, ErrNoPlacementTarget):
		return CapacityRetryAfterSeconds
	default:
		return 0
	}
}

// forwardApplyStatus inverts ApplyErrorStatus on the client side, restoring
// the sentinel so errors.Is works on the far side of the hop.
func forwardApplyStatus(status int, message string) error {
	switch status {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusTooManyRequests:
		if strings.Contains(message, ErrTeamQuotaExceeded.Error()) {
			return fmt.Errorf("%w: %s", ErrTeamQuotaExceeded, message)
		}
		return fmt.Errorf("%w: %s", ErrCreateBackpressure, message)
	case http.StatusConflict:
		// Restore whichever conflict sentinel the leader answered 409 with.
		// The messages are disjoint prefixes (each is the sentinel's own
		// Error()), so a plain Contains picks exactly one.
		switch {
		case strings.Contains(message, ErrArtifactCatalogSuperseded.Error()):
			return fmt.Errorf("%w: %s", ErrArtifactCatalogSuperseded, message)
		case strings.Contains(message, ErrReservationConflict.Error()):
			return fmt.Errorf("%w: %s", ErrReservationConflict, message)
		case strings.Contains(message, ErrNameConflict.Error()):
			return fmt.Errorf("%w: %s", ErrNameConflict, message)
		case strings.Contains(message, ErrIncarnationConflict.Error()):
			return fmt.Errorf("%w: %s", ErrIncarnationConflict, message)
		case strings.Contains(message, ErrPlacementUnsatisfiable.Error()):
			return fmt.Errorf("%w: %s", ErrPlacementUnsatisfiable, message)
		case strings.Contains(message, ErrPlacementDeleted.Error()):
			return fmt.Errorf("%w: %s", ErrPlacementDeleted, message)
		case strings.Contains(message, ErrSpecVersionConflict.Error()):
			return fmt.Errorf("%w: %s", ErrSpecVersionConflict, message)
		case strings.Contains(message, ErrMoveHandoffMoved.Error()):
			return fmt.Errorf("%w: %s", ErrMoveHandoffMoved, message)
		case strings.Contains(message, ErrMoveHandoffAborted.Error()):
			return fmt.Errorf("%w: %s", ErrMoveHandoffAborted, message)
		}
	case http.StatusForbidden:
		// The leader's peer check does not see this node alive in gossip
		// yet. During a leader change the new leader's view can lag the
		// forwarder's for a moment; as an unclassified error the create
		// answered 400 and an SDK gave up on a write a retry seconds later
		// commits (the reserve never reached the FSM). The agent's
		// control-plane calls already treat the same 403 this way. Every
		// other 403 stays final.
		if strings.Contains(message, PeerNotInMembershipMessage) {
			return fmt.Errorf("%w: leader-forward apply: %s", ErrMembershipPending, message)
		}
	case http.StatusServiceUnavailable:
		switch {
		case strings.Contains(message, ErrCapacityExceeded.Error()):
			return fmt.Errorf("%w: %s", ErrCapacityExceeded, message)
		case strings.Contains(message, ErrNoPlacementTarget.Error()):
			return fmt.Errorf("%w: %s", ErrNoPlacementTarget, message)
		case strings.Contains(message, ErrCreateBackpressure.Error()):
			return fmt.Errorf("%w: %s", ErrCreateBackpressure, message)
		}
		return ErrNotLeader
	}
	return fmt.Errorf("cluster: leader-forward apply: status %d: %s", status, message)
}
