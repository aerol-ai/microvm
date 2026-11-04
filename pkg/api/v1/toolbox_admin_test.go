package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The toolbox passthrough does not reach toolboxd's admin endpoint (the
// port allowlist behind the public proxy route): 404, as if it did not
// exist.
func TestToolboxPassthroughRefusesAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: buildService(nil, buildConfig{}), Auth: func(h http.Handler) http.Handler { return h }})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/toolbox/admin/allowed-ports", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("toolbox admin passthrough = %d %s; want 404", rr.Code, rr.Body.String())
	}
}
