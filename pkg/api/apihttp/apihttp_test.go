package apihttp

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteJSON(rr, http.StatusOK, map[string]any{"status": "ok"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/json") {
		t.Errorf("Content-Type = %q, want application/json", rr.Header().Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body[status] = %v, want ok", body["status"])
	}
}

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteError(rr, http.StatusBadRequest, "something went wrong")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body models.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if body.Error != "something went wrong" {
		t.Errorf("body.Error = %q, want %q", body.Error, "something went wrong")
	}
}

func storeAwareErr(t *testing.T, err error) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, err)
	var body models.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body.Error
}

func TestWriteStoreAwareError_NotFound(t *testing.T) {
	code, _ := storeAwareErr(t, store.ErrNotFound)
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", code)
	}
}

func TestWriteStoreAwareError_AdmissionDenied(t *testing.T) {
	code, _ := storeAwareErr(t, controlplane.ErrAdmissionDenied)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestWriteStoreAwareError_AdmissionUnavailable(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, controlplane.ErrAdmissionUnavailable)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing")
	}
}

func TestWriteStoreAwareError_ManuallyStopped(t *testing.T) {
	code, _ := storeAwareErr(t, service.ErrSandboxManuallyStopped)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_WakeCircuitOpen(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, service.ErrWakeCircuitOpen)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, want 60", rr.Header().Get("Retry-After"))
	}
}

func TestWriteStoreAwareError_SnapshotNameConflict(t *testing.T) {
	code, _ := storeAwareErr(t, store.ErrSnapshotNameConflict)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_TemplateIDConflict(t *testing.T) {
	code, _ := storeAwareErr(t, store.ErrTemplateIDConflict)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_TemplateInUse(t *testing.T) {
	code, _ := storeAwareErr(t, store.ErrTemplateInUse)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_TemplateNotRebuildable(t *testing.T) {
	code, _ := storeAwareErr(t, models.ErrTemplateNotRebuildable)
	if code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412", code)
	}
}

func TestWriteStoreAwareError_CustomDomainNotSupported(t *testing.T) {
	code, _ := storeAwareErr(t, models.ErrCustomDomainNotSupported)
	if code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412", code)
	}
}

func TestWriteStoreAwareError_CustomDomainProtocolConflict(t *testing.T) {
	code, _ := storeAwareErr(t, models.ErrCustomDomainProtocolConflict)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_CustomDomainPerSandboxCap(t *testing.T) {
	code, _ := storeAwareErr(t, models.ErrCustomDomainPerSandboxCap)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_CustomDomainConflict(t *testing.T) {
	code, _ := storeAwareErr(t, store.ErrCustomDomainConflict)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_CustomDomainPortMismatch(t *testing.T) {
	code, _ := storeAwareErr(t, store.ErrCustomDomainPortMismatch)
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409", code)
	}
}

func TestWriteStoreAwareError_CustomDomainInvalidTargetPort(t *testing.T) {
	code, _ := storeAwareErr(t, models.ErrCustomDomainInvalidTargetPort)
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

func TestWriteStoreAwareError_CustomDomainVerificationFailed(t *testing.T) {
	code, _ := storeAwareErr(t, models.ErrCustomDomainVerificationFailed)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestWriteStoreAwareError_CapacityExceeded(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, capacity.ErrCapacityExceeded)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing for capacity exceeded")
	}
}

func TestWriteStoreAwareError_ClusterCapacityExceeded(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, cluster.ErrCapacityExceeded)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestWriteStoreAwareError_CreateBackpressure(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, cluster.ErrCreateBackpressure)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing for backpressure")
	}
}

func TestWriteStoreAwareError_NoPlacementTarget(t *testing.T) {
	code, _ := storeAwareErr(t, cluster.ErrNoPlacementTarget)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", code)
	}
}

func TestWriteStoreAwareError_InvalidTopology(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, cluster.ErrInvalidTopology)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing for invalid topology")
	}
}

func TestWriteStoreAwareError_WrappedNotFound(t *testing.T) {
	wrapped := errors.Join(errors.New("outer context"), store.ErrNotFound)
	code, _ := storeAwareErr(t, wrapped)
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for wrapped ErrNotFound", code)
	}
}

func TestWriteStoreAwareError_GenericError(t *testing.T) {
	code, msg := storeAwareErr(t, errors.New("something unexpected"))
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
	if msg != "something unexpected" {
		t.Errorf("error message = %q, want %q", msg, "something unexpected")
	}
}

func TestWriteStoreAwareError_LongMessageTruncated(t *testing.T) {
	longMsg := strings.Repeat("x", 300)
	code, msg := storeAwareErr(t, errors.New(longMsg))
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
	if len(msg) > 200 {
		t.Errorf("message length = %d, want <= 200 (truncated)", len(msg))
	}
}
