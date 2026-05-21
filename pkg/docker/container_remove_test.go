package docker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestIsContainerRemoveBenignError(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    bool
	}{
		{
			name:    "404 already gone",
			message: `docker API DELETE /containers/abc failed with status 404: No such container: abc`,
			want:    true,
		},
		{
			// Containers behave differently from images: 409 here means a
			// real constraint (force=false against a running container).
			// Callers always set force=true today, so this is unreachable
			// in practice — but the matcher must not swallow it if it ever
			// surfaces, otherwise we'd hide a partial destroy.
			name:    "409 still running not benign",
			message: `docker API DELETE /containers/abc failed with status 409: container abc is running`,
			want:    false,
		},
		{
			name:    "500 not benign",
			message: `docker API DELETE /containers/abc failed with status 500: server error`,
			want:    false,
		},
		{
			name:    "transport error",
			message: `connection refused`,
			want:    false,
		},
		{
			name:    "empty",
			message: "",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isContainerRemoveBenignError(tc.message); got != tc.want {
				t.Fatalf("isContainerRemoveBenignError(%q) = %v, want %v", tc.message, got, tc.want)
			}
		})
	}
}

// TestRemoveContainerSwallows404 pins the regression: a lifecycle auto-destroy
// (or any retry of a destroy that races an out-of-band `docker rm` / `--rm`
// cleanup) lands on a container that's already gone. Without 404-as-success
// here, Service.DestroySandbox returns an error, runLifecycleSweep skips the
// post-destroy DeletePlacement, and the FSM placement strands at a node with
// no container — surfacing as a "Sandbox not found" 404 from the Caddy
// wildcard fallback for every request routed to that owner.
func TestRemoveContainerSwallows404(t *testing.T) {
	var calls int
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected method %s", r.Method)
			}
			if !strings.HasPrefix(r.URL.Path, "/containers/") {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"message":"No such container: abc"}`)),
				Header:     make(http.Header),
			}, nil
		})},
	}

	if err := client.removeContainer(context.Background(), "abc", true); err != nil {
		t.Fatalf("removeContainer 404 should be swallowed, got err = %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one DELETE, got %d", calls)
	}
}

// TestRemoveContainerPropagates500 guards the negative direction: an actual
// Docker daemon failure must not be silently swallowed alongside 404.
func TestRemoveContainerPropagates500(t *testing.T) {
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("boom")),
				Header:     make(http.Header),
			}, nil
		})},
	}

	err := client.removeContainer(context.Background(), "abc", true)
	if err == nil {
		t.Fatal("removeContainer should propagate a 500")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected status 500 in error, got %v", err)
	}
}
