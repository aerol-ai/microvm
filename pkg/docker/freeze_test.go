package docker

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
)

var _ runtime.Freezer = (*Client)(nil)

// Freeze and Thaw are docker pause / unpause, and both are idempotent: the
// states docker refuses with 409 because the container is already where the
// call would put it count as done; anything else is an error to retry.
func TestClientFreezeThaw(t *testing.T) {
	for _, tc := range []struct {
		name    string
		freeze  bool
		status  int
		body    string
		wantErr bool
	}{
		{name: "freeze", freeze: true, status: http.StatusNoContent},
		{name: "freeze already paused", freeze: true, status: http.StatusConflict, body: `{"message":"Container ctr is already paused"}`},
		{name: "freeze not running", freeze: true, status: http.StatusConflict, body: `{"message":"Container ctr is not running"}`},
		{name: "freeze gone", freeze: true, status: http.StatusNotFound, body: `{"message":"No such container: ctr"}`},
		{name: "freeze restarting is an error", freeze: true, status: http.StatusConflict, body: `{"message":"Container ctr is restarting, wait until the container is running"}`, wantErr: true},
		{name: "freeze daemon error", freeze: true, status: http.StatusInternalServerError, body: `{"message":"cgroup freezer unavailable"}`, wantErr: true},
		{name: "thaw", status: http.StatusNoContent},
		{name: "thaw not paused", status: http.StatusConflict, body: `{"message":"Container ctr is not paused"}`},
		{name: "thaw gone", status: http.StatusNotFound, body: `{"message":"No such container: ctr"}`},
		{name: "thaw daemon error", status: http.StatusInternalServerError, body: "boom", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := "/containers/ctr/unpause"
			if tc.freeze {
				want = "/containers/ctr/pause"
			}
			var gotPath, gotMethod string
			c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotPath, gotMethod = r.URL.Path, r.Method
				return textResponse(tc.status, tc.body), nil
			})}}
			var err error
			if tc.freeze {
				err = c.Freeze(context.Background(), "ctr")
			} else {
				err = c.Thaw(context.Background(), "ctr")
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if gotMethod != http.MethodPost || gotPath != want {
				t.Fatalf("request = %s %s, want POST %s", gotMethod, gotPath, want)
			}
		})
	}
}

func TestIsConflictSaying(t *testing.T) {
	if isConflictSaying(nil, "x") {
		t.Fatal("nil error matched")
	}
	if isConflictSaying(errString("docker API POST /x failed with status 500: already paused"), "already paused") {
		t.Fatal("a non-409 matched")
	}
	if !isConflictSaying(errString("docker API POST /x failed with status 409: Container c is already paused"), "is not running", "already paused") {
		t.Fatal("a 409 naming the state did not match")
	}
	if !strings.Contains(errString("a").Error(), "a") {
		t.Fatal("errString")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
