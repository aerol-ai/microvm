package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// A reservation/name conflict that fails an apply on the leader must survive
// the leader-forward hop as its sentinel, exactly like the superseded verdict
// does. Before this, the FSM's ErrReservationConflict fell through
// ApplyErrorStatus to a generic 500, so forwardApplyStatus could not tell it
// from a transient apply failure and dropped the sentinel. On a multi-node
// cluster that turned an Idempotency-Key create retry into a 503 instead of
// letting the create path's idempotent-replay branch (which keys off
// errors.Is(err, ErrReservationConflict)) route to the existing placement.
func TestApplyVerdictCarriesReservationAndNameConflicts(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		sentinel error
	}{
		{
			name:     "reservation conflict",
			err:      fmt.Errorf("%w: %s already placed by %s", ErrReservationConflict, "sb-f55ddc035b458cf8", "node2"),
			wantCode: http.StatusConflict,
			sentinel: ErrReservationConflict,
		},
		{
			name:     "name conflict",
			err:      fmt.Errorf("%w: %q is held by %s", ErrNameConflict, "demo", "node3"),
			wantCode: http.StatusConflict,
			sentinel: ErrNameConflict,
		},
		{
			name:     "superseded still carried",
			err:      fmt.Errorf("%w: template/worker-a", ErrArtifactCatalogSuperseded),
			wantCode: http.StatusConflict,
			sentinel: ErrArtifactCatalogSuperseded,
		},
		{
			name:     "ordinary apply failure is a 500 and carries no sentinel",
			err:      errors.New("disk full"),
			wantCode: http.StatusInternalServerError,
			sentinel: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The listener answers the forward with this status + message.
			got := ApplyErrorStatus(tc.err)
			if got != tc.wantCode {
				t.Fatalf("ApplyErrorStatus = %d, want %d", got, tc.wantCode)
			}
			// The forwarding client inverts it back into an error.
			round := forwardApplyStatus(got, tc.err.Error())
			if tc.sentinel == nil {
				// A generic failure must NOT be mistaken for any conflict
				// sentinel — the caller retries it unchanged.
				if errors.Is(round, ErrReservationConflict) || errors.Is(round, ErrNameConflict) || errors.Is(round, ErrArtifactCatalogSuperseded) {
					t.Fatalf("generic failure round-tripped into a conflict sentinel: %v", round)
				}
				return
			}
			if !errors.Is(round, tc.sentinel) {
				t.Fatalf("leader-forward dropped the sentinel: forwardApplyStatus(%d, %q) = %v, want errors.Is %v",
					got, tc.err.Error(), round, tc.sentinel)
			}
		})
	}
}

// A reservation conflict answered by the control plane over the agent's
// (non-voter-ingress) apply hop must come back as the sentinel too, not a bare
// statusError. forwardApplyStatus covers the raft leader-forward hop; applyCommand
// covers this one. Before the fix a non-voter ingress 503'd an Idempotency-Key
// create retry on a multi-node cluster (seen live on cluster-hetero) because the
// create path's replay branch keys off errors.Is(err, ErrReservationConflict).
func TestAgentControlPlaneCarriesReservationAndNameConflicts(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		sentinel error
	}{
		{"reservation", "cluster: fsm apply: " + ErrReservationConflict.Error() + ": sb-x already placed by node2", ErrReservationConflict},
		{"name", "cluster: fsm apply: " + ErrNameConflict.Error() + ": \"demo\" is held by node3", ErrNameConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath) {
					http.Error(w, tc.body, http.StatusConflict)
					return
				}
				http.NotFound(w, r)
			}))
			err := agent.ReserveOnTarget(context.Background(), "sb-x",
				PlacementTarget{NodeID: "node2", APIURL: "http://node2"}, nil,
				PlacementSecrets{IncarnationID: "inc"}, time.Minute)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("ReserveOnTarget over control plane = %v, want errors.Is %v", err, tc.sentinel)
			}
		})
	}
}

// The reservation and name conflicts share the 409 status, so forwardApplyStatus
// must disambiguate them by message and never cross them.
func TestApplyVerdictDoesNotCrossConflictSentinels(t *testing.T) {
	resv := forwardApplyStatus(http.StatusConflict,
		fmt.Errorf("%w: sb-x already placed by node2", ErrReservationConflict).Error())
	if !errors.Is(resv, ErrReservationConflict) || errors.Is(resv, ErrNameConflict) {
		t.Fatalf("reservation-conflict message resolved to the wrong sentinel: %v", resv)
	}
	name := forwardApplyStatus(http.StatusConflict,
		fmt.Errorf("%w: %q is held by node2", ErrNameConflict, "demo").Error())
	if !errors.Is(name, ErrNameConflict) || errors.Is(name, ErrReservationConflict) {
		t.Fatalf("name-conflict message resolved to the wrong sentinel: %v", name)
	}
}
