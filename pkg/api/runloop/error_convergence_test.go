package runloop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The Runloop writer used to miss these (all 400). It now shares
// apihttp.Classify, keeping its own body shape and x-should-retry header.
func TestRunloopErrorsFollowTheSharedTable(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		retryAfter string
	}{
		{"admission denied", controlplane.ErrAdmissionDenied, http.StatusForbidden, ""},
		{"admission unavailable", controlplane.ErrAdmissionUnavailable, http.StatusServiceUnavailable, "15"},
		{"engine not registered", models.ErrContainerEngineNotRegistered, http.StatusServiceUnavailable, "15"},
		{"cluster finalization", service.ErrClusterFinalizationUnavailable, http.StatusServiceUnavailable, "5"},
		{"build timeout", service.ErrBuildTimeout, http.StatusGatewayTimeout, ""},
		{"build invalid", service.ErrBuildInvalid, http.StatusBadRequest, ""},
		{"not running", service.ErrSandboxNotRunning, http.StatusConflict, ""},
		{"not resumable", service.ErrSandboxNotResumable, http.StatusConflict, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeStoreAwareError(nil, rr, tc.err)
			if rr.Code != tc.status || rr.Header().Get("Retry-After") != tc.retryAfter {
				t.Fatalf("%v → %d Retry-After %q; want %d %q", tc.err, rr.Code, rr.Header().Get("Retry-After"), tc.status, tc.retryAfter)
			}
			// A permanent status carries x-should-retry:false so the SDK does
			// not retry it (a build-invalid 400 is permanent; a 503 is not).
			wantNoRetry := !retryable(tc.status)
			if got := rr.Header().Get("x-should-retry") == "false"; got != wantNoRetry {
				t.Fatalf("x-should-retry=false is %v for %d, want %v", got, tc.status, wantNoRetry)
			}
		})
	}
	// Runloop's SDK keeps its own wording for the lifecycle conflicts.
	for err, want := range map[error]string{
		service.ErrSandboxNotRunning:   "devbox is not running",
		service.ErrSandboxNotResumable: "devbox is not suspended",
	} {
		rr := httptest.NewRecorder()
		writeStoreAwareError(nil, rr, err)
		var body errorResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if body.Message != want {
			t.Errorf("%v message = %q, want %q", err, body.Message, want)
		}
	}
}
