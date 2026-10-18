package api

import (
	"context"
	"expvar"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func authCounter(root *expvar.Map, key, key2 string) int64 {
	inner, ok := root.Get(key).(*expvar.Map)
	if !ok {
		return 0
	}
	v, ok := inner.Get(key2).(*expvar.Int)
	if !ok {
		return 0
	}
	return v.Value()
}

// TestAuthMetrics: each decision counts once, under fixed label values
// (§5.15). The counters are process-global, so the test compares deltas.
func TestAuthMetrics(t *testing.T) {
	server := newIdentityServer(nil, WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	type count struct {
		root      *expvar.Map
		key, key2 string
	}
	cases := []struct {
		name   string
		bearer string
		remote string
		want   count
	}{
		{"PAT from the host", "pat-token", "127.0.0.1:1", count{authRequests, "operator", "host"}},
		{"PAT from outside", "pat-token", "203.0.113.5:1", count{authRequests, "operator", "public"}},
		{"token", "avm_payments", "203.0.113.5:1", count{authRequests, "token", "public"}},
		{"no credential", "", "203.0.113.5:1", count{authFailures, "none", "missing"}},
		{"unrecognised bearer", "nope", "203.0.113.5:1", count{authFailures, "unknown", "rejected"}},
		{"expired token", "avm_expired", "203.0.113.5:1", count{authFailures, "token", "expired"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := authCounter(tc.want.root, tc.want.key, tc.want.key2)
			req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
			req.RemoteAddr = tc.remote
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			server.Handler().ServeHTTP(httptest.NewRecorder(), req)
			if got := authCounter(tc.want.root, tc.want.key, tc.want.key2) - before; got != 1 {
				t.Fatalf("{%s,%s} moved by %d, want 1", tc.want.key, tc.want.key2, got)
			}
		})
	}

	// Both families reach /v1/metrics with the exporter's key/key2 labels.
	var b strings.Builder
	if err := writePrometheusExpvars(&b); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`aerolvm_auth_requests_total{key="operator",key2="host"}`,
		`aerolvm_auth_failures_total{key="token",key2="expired"}`,
		"# TYPE aerolvm_auth_failures_total counter",
	} {
		if !strings.Contains(b.String(), line) {
			t.Errorf("metrics output lacks %s", line)
		}
	}
}

func TestAddAuthCountConcurrentFirstUse(t *testing.T) {
	root := new(expvar.Map).Init()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			addAuthCount(root, "k", "v")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if got := authCounter(root, "k", "v"); got != 8 {
		t.Fatalf("count = %d, want 8 (a racing first use lost an increment)", got)
	}
}

// TestAuthSpanAttributes: the request span gains the principal kind and id,
// the team and the auth result (§5.15). Display names and credentials never
// become attributes.
func TestAuthSpanAttributes(t *testing.T) {
	oldProvider, oldPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(oldProvider)
		otel.SetTextMapPropagator(oldPropagator)
		_ = provider.Shutdown(context.Background())
	})

	server := newIdentityServer(nil, WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	cases := []struct {
		bearer, team string
		want         map[string]string
		absent       []string
	}{
		{bearer: "avm_payments", want: map[string]string{
			"aerolvm.auth.result": "ok", "aerolvm.principal.kind": "token", "aerolvm.principal.id": "tok_7Hq2", "aerolvm.team": "payments",
			"aerolvm.permission": "authenticated",
		}},
		{bearer: "pat-token", want: map[string]string{
			"aerolvm.auth.result": "ok", "aerolvm.principal.kind": "operator", "aerolvm.principal.id": "operator", "aerolvm.team": "*",
		}},
		{bearer: "avm_expired", want: map[string]string{"aerolvm.auth.result": "unauthorized"}, absent: []string{"aerolvm.principal.id", "aerolvm.permission"}},
		{bearer: "avm_payments", team: "checkout", want: map[string]string{"aerolvm.auth.result": "forbidden"}},
		{bearer: "avm_payments", team: "BAD", want: map[string]string{"aerolvm.auth.result": "bad_request"}},
	}
	for _, tc := range cases {
		before := len(recorder.Ended())
		req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+tc.bearer)
		if tc.team != "" {
			req.Header.Set(HeaderTeam, tc.team)
		}
		server.Handler().ServeHTTP(httptest.NewRecorder(), req)
		spans := recorder.Ended()
		if len(spans) != before+1 {
			t.Fatalf("%s: %d new spans, want 1", tc.bearer, len(spans)-before)
		}
		span := spans[len(spans)-1]
		for key, want := range tc.want {
			if got := spanStringAttr(span, key); got != want {
				t.Errorf("%s: %s = %q, want %q", tc.bearer, key, got, want)
			}
		}
		for _, key := range tc.absent {
			if got := spanStringAttr(span, key); got != "" {
				t.Errorf("%s: %s = %q on a refusal", tc.bearer, key, got)
			}
		}
		for _, attr := range span.Attributes() {
			if v := attr.Value.AsString(); strings.Contains(v, "ci-deploy") || strings.Contains(v, tc.bearer) {
				t.Errorf("%s: attribute %s leaks %q", tc.bearer, attr.Key, v)
			}
		}
	}
}

func TestAuthResultFor(t *testing.T) {
	for status, want := range map[int]string{401: "unauthorized", 403: "forbidden", 400: "bad_request", 503: "unavailable", 500: "unauthorized"} {
		if got := authResultFor(status); got != want {
			t.Errorf("authResultFor(%d) = %q, want %q", status, got, want)
		}
	}
}
