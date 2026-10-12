package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
)

// toolboxd's /admin endpoints are the daemon's own: neither toolbox proxy
// reaches them, under any spelling of the path, and the refusal comes
// before the sandbox is even looked up.
func TestToolboxAdminPathsAreRefused(t *testing.T) {
	svc := &Service{}
	for _, path := range []string{"/admin/allowed-ports", "admin/allowed-ports", "//admin/allowed-ports", "/files/../admin/allowed-ports", "/admin", " /admin/ "} {
		if err := svc.ServeToolboxReverseProxy(context.Background(), "sb", httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil), path); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("reverse proxy to %q = %v; want not found", path, err)
		}
		if _, err := svc.RoundTripToolbox(context.Background(), "sb", http.MethodPost, path, nil, nil, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("round trip to %q = %v; want not found", path, err)
		}
	}
	for _, path := range []string{"/administrator", "/files/admin", "/process/execute", ""} {
		if err := refuseToolboxAdminPath(path); err != nil {
			t.Errorf("refuseToolboxAdminPath(%q) = %v", path, err)
		}
	}
}
