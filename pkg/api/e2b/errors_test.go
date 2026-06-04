package e2b

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
)

func TestRequestErrorHelpersAndWriteStoreAwareError(t *testing.T) {
	t.Run("request_error_helpers", func(t *testing.T) {
		err := badRequest("bad")
		if err == nil || err.Error() != "bad" {
			t.Fatalf("badRequest error = %v", err)
		}
		err = conflict("conflict")
		if err == nil || err.Error() != "conflict" {
			t.Fatalf("conflict error = %v", err)
		}
		err = serviceUnavailable("svc")
		if err == nil || err.Error() != "svc" {
			t.Fatalf("serviceUnavailable error = %v", err)
		}
	})

	cases := []struct {
		name       string
		err        error
		wantStatus int
		retryAfter string
	}{
		{name: "known_bad_request", err: badRequest("x"), wantStatus: http.StatusBadRequest},
		{name: "store_not_found", err: store.ErrNotFound, wantStatus: http.StatusNotFound},
		{name: "manual_stop_conflict", err: service.ErrSandboxManuallyStopped, wantStatus: http.StatusConflict},
		{name: "wake_circuit_open", err: service.ErrWakeCircuitOpen, wantStatus: http.StatusServiceUnavailable, retryAfter: "60"},
		{name: "snapshot_name_conflict", err: store.ErrSnapshotNameConflict, wantStatus: http.StatusConflict},
		{name: "create_backpressure", err: cluster.ErrCreateBackpressure, wantStatus: http.StatusTooManyRequests, retryAfter: "5"},
		{name: "invalid_topology", err: cluster.ErrInvalidTopology, wantStatus: http.StatusServiceUnavailable, retryAfter: "300"},
		{name: "fallback_long_error_trimmed", err: errors.New(strings.Repeat("a", 260)), wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeStoreAwareError(nil, rr, tc.err)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.retryAfter != "" && rr.Header().Get("Retry-After") != tc.retryAfter {
				t.Fatalf("retry-after = %q, want %q", rr.Header().Get("Retry-After"), tc.retryAfter)
			}
		})
	}
}
