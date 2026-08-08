package v1

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestClusterAdminRoutesRejectManagedTenant(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("n1", "http://n1", ""))
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{
					Identity: controlplane.Identity{OwnerRef: "tenant-a"},
				})
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		},
	})

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/cluster/nodes/n1/drain"},
		{http.MethodPost, cluster.PublicInternalApplyPath},
		{http.MethodDelete, "/v1/cluster/members/n1"},
		{http.MethodGet, "/v1/cluster/members"},
	}
	for _, tc := range paths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer tenant-token")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d body=%s, want 403", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}
