package apihttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestRoutePermissionSpanAttribute: authorize puts the permission the route
// asked for on the request span (plans/identity-and-access.md §5.15),
// whether the caller holds it or not.
func TestRoutePermissionSpanAttribute(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	for _, tc := range []struct {
		access controlplane.Access
		want   int
	}{
		{tokenOn("payments", controlplane.RoleRunner), http.StatusNoContent},
		{tokenOn("payments", controlplane.RoleViewer), http.StatusForbidden},
	} {
		var c reached
		h := Router{Authenticate: as(tc.access)}.Route(controlplane.PermSandboxExec, c.handler())
		ctx, span := provider.Tracer("test").Start(context.Background(), "request")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/exec", nil).WithContext(ctx))
		span.End()
		if rec.Code != tc.want {
			t.Fatalf("status = %d, want %d", rec.Code, tc.want)
		}
		ended := recorder.Ended()
		got := ""
		for _, attr := range ended[len(ended)-1].Attributes() {
			if attr.Key == "aerolvm.permission" {
				got = attr.Value.AsString()
			}
		}
		if got != string(controlplane.PermSandboxExec) {
			t.Fatalf("aerolvm.permission = %q, want %q", got, controlplane.PermSandboxExec)
		}
	}
}
