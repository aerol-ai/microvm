package cluster

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// The enterprise boot path retries instead of exiting only when this
// classifier says the refusal was "not yet a member" rather than a real
// rejection. The messages are the internal server's own wording
// (internal_server.go authorizePeer); if either string drifts, a restarting
// enterprise worker goes back to crash-looping into systemd's restart limit.
func TestIsControlPlaneUnavailable(t *testing.T) {
	live := statusError{status: http.StatusForbidden, message: "cluster peer not in membership"}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"leader unavailable is still covered", ErrNoLeader, true},
		{"403 peer not in membership", live, true},
		{
			"the live wrapped form from the T18 worker crash-loop",
			fmt.Errorf("cluster: validate/re-fanout durable secrets at boot: %w",
				fmt.Errorf("authoritative cluster placement snapshot during secret re-fanout: %w", live)),
			true,
		},
		{"503 before gossip is up", statusError{status: http.StatusServiceUnavailable, message: "cluster: peer membership not yet available"}, true},
		{"a different 403 stays a real rejection", statusError{status: http.StatusForbidden, message: "invalid token"}, false},
		{"a 500 is not membership", statusError{status: http.StatusInternalServerError, message: "cluster peer not in membership"}, false},
		{"a plain error with the same text is not the sentinel", errors.New("cluster peer not in membership"), false},
		{"an unrelated failure stays fatal-eligible", errors.New("secret blob failed to decrypt"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsControlPlaneUnavailable(tc.err); got != tc.want {
				t.Fatalf("IsControlPlaneUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
	if errors.Is(live, ErrNotLeader) {
		t.Fatal("statusError.Is must only claim ErrMembershipPending")
	}
}
