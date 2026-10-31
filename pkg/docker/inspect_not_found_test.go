package docker

import (
	"context"
	"errors"
	"net/http"
	"testing"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
)

// Reconcile deletes a sandbox's row when Inspect says its container is gone,
// so Inspect must say "gone" for Docker's 404 and for nothing else. A daemon
// that times out or answers 500 knows nothing about the container; reading
// that as "gone" deleted live sandboxes.
func TestInspectReportsGoneOnlyForNotFound(t *testing.T) {
	cases := []struct {
		name     string
		response func(*http.Request) (*http.Response, error)
		gone     bool
	}{
		{
			name: "404 no such container",
			response: func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusNotFound, `{"message":"No such container: sb"}`), nil
			},
			gone: true,
		},
		{
			name: "500 daemon error",
			response: func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusInternalServerError, "boom"), nil
			},
		},
		{
			name: "transport failure",
			response: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial unix /var/run/docker.sock: i/o timeout")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{httpClient: &http.Client{Transport: roundTripFunc(tc.response)}}
			st, err := c.Inspect(context.Background(), "sb")
			if err == nil {
				t.Fatalf("Inspect() = %+v, want an error", st)
			}
			if got := sbruntime.InstanceGone(st, err); got != tc.gone {
				t.Fatalf("InstanceGone(%v) = %v, want %v", err, got, tc.gone)
			}
		})
	}
}
