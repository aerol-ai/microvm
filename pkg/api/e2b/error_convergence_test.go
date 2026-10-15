package e2b

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The E2B writer used to hand-copy a subset of the mapping, so these errors
// all fell through to 400. Routing through apihttp.Classify fixes that; the
// envelope stays E2B's {code,message}.
func TestE2BErrorsFollowTheSharedTable(t *testing.T) {
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
		{"snapshot name conflict", store.ErrSnapshotNameConflict, http.StatusConflict, ""},
		{"sandbox exists", models.ErrSandboxExists, http.StatusConflict, ""},
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
			var body errorResponse
			_ = json.Unmarshal(rr.Body.Bytes(), &body)
			if body.Code != tc.status {
				t.Fatalf("E2B envelope code = %d, want %d (it mirrors the status)", body.Code, tc.status)
			}
		})
	}
	// E2B's SDK keeps its own wording for these.
	for err, want := range map[error]string{
		store.ErrNotFound:              "Not found",
		store.ErrSnapshotNameConflict:  "Snapshot name already in use",
		models.ErrSandboxExists:        "Sandbox already exists",
		service.ErrSandboxNotRunning:   "Sandbox is not running",
		service.ErrSandboxNotResumable: "Sandbox is not available for connect",
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

// writeErrorCode is the clustercreate.ErrorWriter for E2B: it drops the code
// and renders the E2B envelope.
func TestE2BWriteErrorCodeDropsCode(t *testing.T) {
	rr := httptest.NewRecorder()
	writeErrorCode(rr, http.StatusServiceUnavailable, "some_code", "busy")
	var body errorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusServiceUnavailable || body.Code != http.StatusServiceUnavailable || body.Message != "busy" {
		t.Fatalf("writeErrorCode → %d %+v", rr.Code, body)
	}
}
