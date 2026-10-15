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
