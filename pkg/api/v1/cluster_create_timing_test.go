package v1

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreateSandboxOnSelectedNode_ThreadsReadinessTiming is the regression for
// the cluster-path attribution gap: createSandboxOnSelectedNode is the *only*
// path the readiness socket runs on (the feature is gated on EnableCluster), so
// if it doesn't wrap the request context with docker.WithCreateTiming and pass
// the recorder to setCreateServerTiming, the create response carries only
// create;dur= and the UC-96 integration assertions (readiness;desc=socket) can
// never pass. This drives both create entry points (promote + self-local).
func TestCreateSandboxOnSelectedNode_ThreadsReadinessTiming(t *testing.T) {
	cases := []struct {
		name          string
		reservationID string
	}{
		{name: "promote_local", reservationID: "sb-timing-promote"},
		{name: "self_local", reservationID: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &apiRecordingRuntime{timingSource: "socket"}
			stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
			h, _ := newClusterCreateHarness(t, rt, stub)

			req := models.CreateSandboxRequest{Image: "alpine:3.20"}
			rr := httptest.NewRecorder()
			httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
			h.createSandboxOnSelectedNode(rr, httpReq, req, tc.reservationID)

			if rr.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
			}
			st := rr.Header().Get("Server-Timing")
			for _, want := range []string{"create;dur=", "runtime_wait;dur=", "toolbox_wait;dur=", "readiness;desc=socket"} {
				if !strings.Contains(st, want) {
					t.Fatalf("Server-Timing = %q, missing %q (timing not threaded?)", st, want)
				}
			}
		})
	}
}

// TestCreateSandboxOnSelectedNode_TimingOnErrorPath asserts the attribution is
// also emitted on the failure path, so a create that fails late still reports
// whatever readiness phase it reached rather than dropping the header.
func TestCreateSandboxOnSelectedNode_TimingOnErrorPath(t *testing.T) {
	rt := &apiRecordingRuntime{timingSource: "health"}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		recordErr: errors.New("raft commit failed"),
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-timing-fail")

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if st := rr.Header().Get("Server-Timing"); !strings.Contains(st, "readiness;desc=health") {
		t.Fatalf("Server-Timing = %q, want readiness attribution on error path", st)
	}
}
