package daytona

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardToolboxErrorCoverage95(t *testing.T) {
	svc, _, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	req := httptest.NewRequest(http.MethodGet, "/files", nil)
	rr := httptest.NewRecorder()
	h.forwardToolbox(rr, req, "missing-sandbox", "/files")
	if rr.Code == http.StatusOK {
		t.Fatalf("expected error status, got %d", rr.Code)
	}
}
