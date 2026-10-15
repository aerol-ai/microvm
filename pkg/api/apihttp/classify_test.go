package apihttp

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Classify is the single table every surface shares. These are the cases the
// E2B and Runloop copies used to miss (defaulting them to 400) or map with a
// literal Retry-After; pinning them here keeps the surfaces from drifting
// again.
func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		retryAfter int
		code       string
		kind       ErrKind
	}{
		{"not found", store.ErrNotFound, http.StatusNotFound, 0, "", ErrKindNotFound},
		{"admission denied", controlplane.ErrAdmissionDenied, http.StatusForbidden, 0, "", ErrKindOther},
		{"admission unavailable", controlplane.ErrAdmissionUnavailable, http.StatusServiceUnavailable, admissionRetryAfterSeconds, "", ErrKindOther},
		{"engine not registered", models.ErrContainerEngineNotRegistered, http.StatusServiceUnavailable, admissionRetryAfterSeconds, "", ErrKindOther},
		{"cluster finalization", service.ErrClusterFinalizationUnavailable, http.StatusServiceUnavailable, 5, "", ErrKindOther},
		{"wake circuit open", service.ErrWakeCircuitOpen, http.StatusServiceUnavailable, 60, "", ErrKindOther},
		{"manually stopped", service.ErrSandboxManuallyStopped, http.StatusConflict, 0, "", ErrKindOther},
		{"not running", service.ErrSandboxNotRunning, http.StatusConflict, 0, "", ErrKindSandboxNotRunning},
		{"not resumable", service.ErrSandboxNotResumable, http.StatusConflict, 0, "", ErrKindSandboxNotResumable},
		{"runtime not implemented", models.ErrRuntimeNotImplemented, http.StatusNotImplemented, 0, "", ErrKindOther},
		{"build timeout", service.ErrBuildTimeout, http.StatusGatewayTimeout, 0, "", ErrKindOther},
		{"build failed", service.ErrBuildFailed, http.StatusBadGateway, 0, "", ErrKindOther},
		{"builder unavailable", service.ErrBuilderUnavailable, http.StatusServiceUnavailable, 0, "", ErrKindOther},
		{"build not implemented", service.ErrBuildNotImplemented, http.StatusNotImplemented, 0, "", ErrKindOther},
		{"build invalid", service.ErrBuildInvalid, http.StatusBadRequest, 0, "", ErrKindOther},
		{"egress gateway", service.ErrEgressGatewayUnavailable, http.StatusServiceUnavailable, 5, models.ErrorCodeEgressGatewayUnavailable, ErrKindOther},
		{"egress inspect recreate", service.ErrEgressInspectRecreate, http.StatusConflict, 0, "", ErrKindOther},
		{"capacity", cluster.ErrCapacityExceeded, http.StatusServiceUnavailable, cluster.CapacityRetryAfterSeconds, "", ErrKindOther},
		{"backpressure", cluster.ErrCreateBackpressure, http.StatusTooManyRequests, cluster.CreateBackpressureRetryAfterSeconds, "", ErrKindOther},
		{"snapshot name conflict", store.ErrSnapshotNameConflict, http.StatusConflict, 0, "", ErrKindSnapshotNameConflict},
		{"sandbox exists", models.ErrSandboxExists, http.StatusConflict, 0, "", ErrKindSandboxExists},
		{"unclassified", errors.New("boom"), http.StatusBadRequest, 0, "", ErrKindUnclassified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Wrapped, as handlers surface them.
			c := Classify(fmt.Errorf("context: %w", tc.err))
			if c.Status != tc.status || c.RetryAfter != tc.retryAfter || c.Code != tc.code || c.Kind != tc.kind {
				t.Fatalf("Classify = status %d retry %d code %q kind %d; want %d %d %q %d",
					c.Status, c.RetryAfter, c.Code, c.Kind, tc.status, tc.retryAfter, tc.code, tc.kind)
			}
		})
	}
}
