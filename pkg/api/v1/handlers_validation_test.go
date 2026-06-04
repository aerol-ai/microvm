package v1

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newValidationHandler() *handlers {
	return &handlers{
		deps: Deps{
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}
}

func TestHandlers_InvalidJSONAndPortValidation(t *testing.T) {
	h := newValidationHandler()

	t.Run("createSandbox invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader("{bad"))
		h.createSandbox(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("createSnapshot invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb/snapshot", strings.NewReader("{bad"))
		req.SetPathValue("id", "sb")
		h.createSnapshot(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("resizeSandbox invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb/resize", strings.NewReader("{bad"))
		req.SetPathValue("id", "sb")
		h.resizeSandbox(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("updateLifecycle invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb/lifecycle", strings.NewReader("{bad"))
		req.SetPathValue("id", "sb")
		h.updateLifecycle(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("exposePort invalid port", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb/expose/abc", nil)
		req.SetPathValue("id", "sb")
		req.SetPathValue("port", "abc")
		h.exposePort(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("exposePort invalid json body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb/expose/8080", strings.NewReader("{bad"))
		req.SetPathValue("id", "sb")
		req.SetPathValue("port", "8080")
		h.exposePort(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("unexposePort invalid port", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/v1/sandboxes/sb/expose/abc", nil)
		req.SetPathValue("id", "sb")
		req.SetPathValue("port", "abc")
		h.unexposePort(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("addCustomDomain invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb/custom-domains", strings.NewReader("{bad"))
		req.SetPathValue("id", "sb")
		h.addCustomDomain(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("updateNetworkLimits invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb/network-limits", strings.NewReader("{bad"))
		req.SetPathValue("id", "sb")
		h.updateNetworkLimits(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}
