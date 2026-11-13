package cluster

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// A server's refusal of a forwarded call keeps its status when it is about
// the request; a refusal between nodes, or a 5xx, does not (a 500 or a
// retryable 503 stays the caller's answer).
func TestForwardedStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"412 external-CA refusal": {statusError{status: 412, message: "this cluster takes its certificates from an external CA"}, 412},
		"404 wrapped":             {fmt.Errorf("cluster: join token create: %w", statusError{status: 404}), 404},
		"409":                     {statusError{status: 409}, 409},
		"429":                     {statusError{status: 429}, 429},
		"403 on the peer":         {statusError{status: 403, message: "bad PAT"}, 0},
		"403 not in membership":   {statusError{status: 403, message: PeerNotInMembershipMessage}, 0},
		"401":                     {statusError{status: 401}, 0},
		"503":                     {statusError{status: 503}, 0},
		"not forwarded":           {errors.New("plain"), 0},
		"nil":                     {nil, 0},
	} {
		if got := ForwardedStatus(tc.err); got != tc.want {
			t.Errorf("%s = %d, want %d", name, got, tc.want)
		}
	}
	if JoinErrorStatus(fmt.Errorf("relay: %w", statusError{status: http.StatusPreconditionFailed})) != http.StatusPreconditionFailed {
		t.Fatal("a relayed join refusal lost its status")
	}
	if JoinErrorStatus(errors.New("boom")) != http.StatusInternalServerError {
		t.Fatal("an unknown join error is not a 500")
	}
}
